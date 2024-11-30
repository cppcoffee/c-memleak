use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aya::programs::UProbe;
use aya::{Btf, Ebpf, EbpfLoader};
use clap::Parser;
use libc::pid_t;
use log::{debug, info, warn};

use c_memleak::symbol::dump_stack_frames;
use c_memleak::util::{dump_to_file, get_binary_path_by_pid, wait_for_termination_signal};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Opt {
    #[clap(short, long, help = "pid of the process")]
    pid: pid_t,

    #[clap(short, long, default_value = "30", help = "timeout in seconds")]
    timeout: u64,

    #[clap(short, long, default_value = "/tmp/memleak.out", help = "output file")]
    output: PathBuf,

    #[clap(short, long, default_value = "false", help = "verbose mode")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // set log level, when RUST_LOG env not set
    if env::var("RUST_LOG").is_err() {
        let s = if opt.verbose { "debug" } else { "info" };

        env::var("RUST_LOG")
            .err()
            .map(|_| env::set_var("RUST_LOG", s));
    }

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global("TRACE_ALL", &(opt.verbose as u8), true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/c-memleak"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    if let Err(_e) = attach_uprobes(&mut ebpf, &Path::new("libc"), Some(opt.pid)) {
        // try to attach uprobes to the binary path (statically linked binary)
        let bin_path = get_binary_path_by_pid(opt.pid).await?;
        attach_uprobes(&mut ebpf, &bin_path, Some(opt.pid))?;
    }

    info!("attached uprobes to {}", opt.pid);
    info!("wait for {}s or press ctrl+c to start dump", opt.timeout);

    wait_for_termination_signal(opt.timeout).await;

    let map = dump_stack_frames(&mut ebpf, opt.pid).await?;
    dump_to_file(&opt.output, &map).await?;

    info!("dump stack frame to {:?}", opt.output);

    Ok(())
}

fn attach_uprobes(ebpf: &mut Ebpf, path: &Path, pid: Option<i32>) -> Result<()> {
    let probes = [
        ("malloc", "malloc_enter"),
        ("malloc", "malloc_exit"),
        ("calloc", "calloc_enter"),
        ("calloc", "calloc_exit"),
        ("realloc", "realloc_enter"),
        ("realloc", "realloc_exit"),
    ];

    for probe in &probes {
        attach_uprobe(ebpf, path, pid, *probe)
            .context(format!("attach to probe {} fail", probe.0))?;
    }

    let maybe_not_support_probes = [
        /* third party allocator like jemallloc not support mmap, so remove the check. */
        ("mmap", "mmap_enter"),
        ("mmap", "mmap_exit"),
        ("munmap", "munmap_enter"),
        ("mremap", "mremap_enter"),
        ("mremap", "mremap_exit"),
        ("posix_memalign", "posix_memalign_enter"),
        ("posix_memalign", "posix_memalign_exit"),
        ("memalign", "memalign_enter"),
        ("memalign", "memalign_exit"),
        ("free", "free_enter"),
        // the following probes are intentinally allowed to fail attachment

        // deprecated in libc.so bionic
        ("valloc", "valloc_enter"),
        ("valloc", "valloc_exit"),
        // deprecated in libc.so bionic
        ("pvalloc", "pvalloc_enter"),
        ("pvalloc", "pvalloc_exit"),
        // added in C11
        ("aligned_alloc", "aligned_alloc_enter"),
        ("aligned_alloc", "aligned_alloc_exit"),
    ];

    for probe in &maybe_not_support_probes {
        if let Err(e) = attach_uprobe(ebpf, path, pid, *probe) {
            debug!("failed to attach uprobe {} to {}: {}", probe.1, probe.0, e)
        }
    }

    Ok(())
}

fn attach_uprobe(
    ebpf: &mut Ebpf,
    path: &Path,
    pid: Option<i32>,
    probe: (&str, &str),
) -> Result<()> {
    let program: &mut UProbe = ebpf.program_mut(probe.1).unwrap().try_into()?;
    program.load()?;
    program.attach(Some(probe.0), 0, path, pid)?;

    Ok(())
}
