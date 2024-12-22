#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_FAST_STACK_CMP, BPF_F_REUSE_STACKID, BPF_F_USER_STACK},
    cty::{c_long, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, gen::bpf_ktime_get_ns},
    macros::{map, uprobe, uretprobe},
    maps::{stack_trace::StackTrace, HashMap},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;
use c_memleak_common::{AllocInfo, ALLOCS_MAX_ENTRIES, MAP_FAILED};

#[map]
static SIZES: HashMap<u32, usize> = HashMap::with_max_entries(10240, 0);

#[map]
static ALLOCS: HashMap<u64, AllocInfo> = HashMap::with_max_entries(ALLOCS_MAX_ENTRIES, 0);

#[map]
static MEMPTRS: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(32768, 0);

#[no_mangle]
static TRACE_ALL: bool = false;

#[uprobe]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    match try_malloc_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_malloc_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let size: usize = ctx.arg(0).ok_or(1)?;
    gen_alloc_entry(&ctx, size)
}

#[uretprobe]
pub fn malloc_exit(ctx: RetProbeContext) -> u32 {
    match try_malloc_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_malloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn free_enter(ctx: ProbeContext) -> u32 {
    match try_free_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_free_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.arg(0).ok_or(1)?;
    gen_free_enter(&ctx, ptr)
}

#[uprobe]
pub fn calloc_enter(ctx: ProbeContext) -> u32 {
    match try_calloc_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_calloc_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let count: usize = ctx.arg(0).ok_or(1)?;
    let size: usize = ctx.arg(1).ok_or(1)?;

    gen_alloc_entry(&ctx, count * size)
}

#[uretprobe]
pub fn calloc_exit(ctx: RetProbeContext) -> u32 {
    match try_calloc_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_calloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn realloc_enter(ctx: ProbeContext) -> u32 {
    match try_realloc_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_realloc_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.arg(0).ok_or(1)?;
    let size: usize = ctx.arg(1).ok_or(1)?;

    gen_free_enter(&ctx, ptr)?;
    gen_alloc_entry(&ctx, size)
}

#[uretprobe]
pub fn realloc_exit(ctx: RetProbeContext) -> u32 {
    match try_realloc_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_realloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn mmap_enter(ctx: ProbeContext) -> u32 {
    match try_mmap_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_mmap_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    //let addr: u64 = ctx.arg(0).ok_or(1)?;
    let len: usize = ctx.arg(1).ok_or(1)?;
    gen_alloc_entry(&ctx, len)
}

#[uretprobe]
pub fn mmap_exit(ctx: RetProbeContext) -> u32 {
    match try_mmap_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_mmap_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn munmap_enter(ctx: ProbeContext) -> u32 {
    match try_munmap_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_munmap_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let addr: u64 = ctx.arg(0).ok_or(1)?;
    gen_free_enter(&ctx, addr)
}

#[uprobe]
pub fn mremap_enter(ctx: ProbeContext) -> u32 {
    match try_mremap_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_mremap_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let old_addr: u64 = ctx.arg(0).ok_or(1)?;
    //let old_size: usize = ctx.arg(1).ok_or(1)?;
    let new_size: usize = ctx.arg(2).ok_or(1)?;

    gen_free_enter(&ctx, old_addr)?;
    gen_alloc_entry(&ctx, new_size)
}

#[uretprobe]
pub fn mremap_exit(ctx: RetProbeContext) -> u32 {
    match try_mremap_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_mremap_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let new_addr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, new_addr)
}

#[uprobe]
pub fn posix_memalign_enter(ctx: ProbeContext) -> u32 {
    match try_posix_memalign_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_posix_memalign_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let memptr: u64 = ctx.arg(0).ok_or(1)?;
    //let alignment: usize = ctx.arg(1).ok_or(1)?;
    let size: usize = ctx.arg(2).ok_or(1)?;

    let tid = bpf_get_current_pid_tgid() as u32;
    MEMPTRS.insert(&tid, &memptr, 0)?;

    gen_alloc_entry(&ctx, size)
}

#[uretprobe]
pub fn posix_memalign_exit(ctx: RetProbeContext) -> u32 {
    match try_posix_memalign_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_posix_memalign_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let tid = bpf_get_current_pid_tgid() as u32;

    let memptr = unsafe { MEMPTRS.get(&tid) }.ok_or(0)?;
    MEMPTRS.remove(&tid)?;

    let addr = match unsafe { bpf_probe_read_user(*memptr as *const c_void) } {
        Ok(addr) => addr,
        Err(_) => return Ok(0),
    };

    gen_alloc_exit(&ctx, addr as u64)
}

#[uprobe]
pub fn aligned_alloc_enter(ctx: ProbeContext) -> u32 {
    match try_aligned_alloc_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_aligned_alloc_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    //let alignment: usize = ctx.arg(0).ok_or(1)?;
    let size: usize = ctx.arg(1).ok_or(1)?;
    gen_alloc_entry(&ctx, size)
}

#[uretprobe]
pub fn aligned_alloc_exit(ctx: RetProbeContext) -> u32 {
    match try_aligned_alloc_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_aligned_alloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn valloc_enter(ctx: ProbeContext) -> u32 {
    match try_valloc_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_valloc_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let size: usize = ctx.arg(0).ok_or(1)?;
    gen_alloc_entry(&ctx, size)
}

#[uretprobe]
pub fn valloc_exit(ctx: RetProbeContext) -> u32 {
    match try_valloc_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_valloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn memalign_enter(ctx: ProbeContext) -> u32 {
    match try_memalign_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_memalign_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    //let alignment: usize = ctx.arg(0).ok_or(1)?;
    let size: usize = ctx.arg(1).ok_or(1)?;
    gen_alloc_entry(&ctx, size)
}

#[uretprobe]
pub fn memalign_exit(ctx: RetProbeContext) -> u32 {
    match try_memalign_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_memalign_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn pvalloc_enter(ctx: ProbeContext) -> u32 {
    match try_pvalloc_enter(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_pvalloc_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let size: usize = ctx.arg(0).ok_or(1)?;
    gen_alloc_entry(&ctx, size)
}

#[uretprobe]
pub fn pvalloc_exit(ctx: RetProbeContext) -> u32 {
    match try_pvalloc_exit(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc as u32,
    }
}

fn try_pvalloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

fn gen_alloc_entry(ctx: &ProbeContext, size: usize) -> Result<u32, c_long> {
    let tid = bpf_get_current_pid_tgid() as u32;

    SIZES.insert(&tid, &size, 0)?;

    let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
    if trace_all {
        info!(ctx, "alloc entered, size={}", size);
    }

    Ok(0)
}

fn gen_alloc_exit(ctx: &RetProbeContext, ptr: u64) -> Result<u32, c_long> {
    const STACK_FLAGS: u32 = BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID;

    let tid = bpf_get_current_pid_tgid() as u32;

    let sz = match unsafe { SIZES.get(&tid) } {
        Some(sz) => *sz,
        None => return Ok(0),
    };
    SIZES.remove(&tid)?;

    if ptr == 0 || ptr == MAP_FAILED {
        return Ok(0);
    }

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let stack_id = unsafe { STACK_TRACES.get_stackid(ctx, STACK_FLAGS as u64)? };

    let value = AllocInfo::new(sz, timestamp_ns, stack_id);
    ALLOCS.insert(&ptr, &value, 0)?;

    let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
    if trace_all {
        info!(ctx, "alloc exited, size = {}, result = {:x}", sz, ptr);
    }

    Ok(0)
}

fn gen_free_enter(ctx: &ProbeContext, ptr: u64) -> Result<u32, c_long> {
    let alloc_info = match unsafe { ALLOCS.get(&ptr) } {
        Some(info) => *info,
        None => return Ok(0),
    };

    ALLOCS.remove(&ptr)?;

    let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
    if trace_all {
        info!(
            ctx,
            "dealloc entered, address={:x}, size={}\n", ptr, alloc_info.size
        );
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
