use log::info;
use std::alloc::{Layout, alloc};
use core::{
    arch::asm,
    ptr,
    sync::atomic::{AtomicPtr, Ordering}
};

#[repr(C)]
struct KvmHostData {}
struct SyncPtr<T>(AtomicPtr<T>);

unsafe impl<T> Sync for SyncPtr<T> {}

static HYP_STACK_PER_CPU: SyncPtr<*mut u8> = SyncPtr(AtomicPtr::new(core::ptr::null_mut()));
static HOST_DAT_PER_CPU: SyncPtr<KvmHostData> = SyncPtr(AtomicPtr::new(core::ptr::null_mut()));

#[repr(C, align(4096))]
struct KvmCpuContext {
    regs: [u64; 31],
    pc: u64,
}

// #[no_mangle]
#[inline(never)]
unsafe fn _new_handle_trap(host_ctxt: &mut KvmCpuContext) {
    let esr: u64;
    // asm!("mrs {}, esr_el2", out(reg) esr);
    unsafe { asm!("mrs {}, esr_el2", out(reg) esr); }

    if (esr >> 26) & 0x3F == 0x16 {
        host_ctxt.regs[0] = 0x333;
    }
}

// #[no_mangle]
unsafe extern "C" fn fixup_vectors(_new_vectors: *mut core::ffi::c_void) {
    info!("[!] fixup_new_vectors({:x})", _new_vectors as usize);

    let num_cpus = num_online_cpus();
    let layout = Layout::array::<KvmHostData>(num_cpus).unwrap();
    let host_dat_per_cpu = unsafe { alloc(layout) } as *mut KvmHostData;
    let host_dat_per_cpu_pa = virt_to_phys(host_dat_per_cpu as *mut u8);

    info!("[!] host_dat_per_cpu @ PA {:x}", host_dat_per_cpu_pa);

    HOST_DAT_PER_CPU.0.store(host_dat_per_cpu, Ordering::Release);

    unsafe {
        ptr::copy_nonoverlapping(
            &host_dat_per_cpu_pa as *const u64,
            addr_new_vectors(_new_vectors, _FIXUP_1),
            1
        );
    }
    helper_for_each_cpu(|| 
        helper_flush_virt(addr_new_vectors(_new_vectors, _FIXUP_1))
    );

    let trap_handler_pa = highmem_virt_to_phys(_new_handle_trap as *mut u8);
    let mut shellcode_br = [0u32; 5];
    assemble_absolute_load(0b10010, trap_handler_pa, &mut shellcode_br);
    shellcode_br[4] = 0xd63f0240u32.to_le();

    unsafe { 
        ptr::copy_nonoverlapping(
            shellcode_br.as_ptr(),
            addr_new_vectors(_new_vectors, _FIXUP_2) as *mut u32,
            5
        );
    }
    helper_for_each_cpu(|| 
        helper_flush_virt(addr_new_vectors(_new_vectors, _FIXUP_2))
    );
}

unsafe fn copy_new_vectors() -> *mut core::ffi::c_void {
    info!("[!] copy_new_vectors()");

    let _new_vectors = helper_make_contig(_new_vectors, _new_vectors_end - _new_vectors);
    helper_for_each_cpu(|| 
        helper_flush_virt(_new_vectors)
    );
    fixup_new_vectors(_new_vectors);
    helper_for_each_cpu(|| 
        helper_flush_virt(_new_vectors)
    );

    info!("[!] _new_vectors -> {:x} (VA)", _new_vectors as usize);
    info!("[!] addr_new_vectors(_new_vectors, _fixup_1) -> {:x}", addr_new_vectors(_new_vectors, _FIXUP_1) as usize);
    info!("[!] _new_vectors -> {:x} (PA)", virt_to_phys(_new_vectors as *mut u8));
    info!("[!] fixed _fixup_1 -> host_dat_per_cpu {:x} (PA)", *(addr_new_vectors(_new_vectors, _FIXUP_1)));
    info!("[!] fixed _fixup_2 -> b _new_handle_trap {:x} (PA)", highmem_virt_to_phys(_new_handle_trap as *mut u8));
    
    for i in 0..5 {
        info!("[!] {:x}", u32::from_be(*(addr_new_vectors(_new_vectors, _FIXUP_2).add(i) as *const u32)));
    }

    _new_vectors
}

#[no_mangle]
pub extern "C" fn new_init() -> i32 {
    info!("[!] mod loaded");
    init_init_mm_ptr();

    let _new_vectors = unsafe { copy_new_vectors() };

    info!("[!] init cpu context");
    helper_for_each_cpu(|| {
        unsafe {
            helper_init_host_cpu_context(&mut (*HOST_DAT_PER_CPU.0.load(Ordering::Acquire)).host_ctxt);
            info!("[!] host_dat for cpu {} -> {:x} (VA) {:x} (PA)",
                  new_get_smp_processor_id(),
                  HOST_DAT_PER_CPU.0.load(Ordering::Acquire) as usize,
                  virt_to_phys(HOST_DAT_PER_CPU.0.load(Ordering::Acquire) as *mut u8));
        }
    });

    info!("[!] reset vectors to _hyp_stub_vectors");
    helper_for_each_cpu(new_reset_vectors);

    info!("[!] set vbar_el2 to _new_stub_vectors -> {:x}", highmem_virt_to_phys(_new_stub_vectors as *mut u8));
    helper_for_each_cpu(|| 
        new_set_vectors(highmem_virt_to_phys(_new_stub_vectors as *mut u8))
    );

    let hyp_stack_per_cpu = unsafe {
        let layout = Layout::array::<*mut u8>(num_online_cpus()).unwrap();
        alloc(layout) as *mut *mut u8
    };
    HYP_STACK_PER_CPU.0.store(hyp_stack_per_cpu, Ordering::Release);

    helper_for_each_cpu(|| 
        unsafe {
            let stack = alloc(Layout::array::<u8>(new_HYP_STACK_SIZE).unwrap()) as *mut u8;
            *hyp_stack_per_cpu.add(new_get_smp_processor_id()) = stack;
            info!("[!] stack allocated for cpu {} @ VA {:x}, PA {:x}",
                new_get_smp_processor_id(),
                stack as usize,
                virt_to_phys(stack));
        }
    );
    helper_for_each_cpu(|| 
        helper_flush_virt(hyp_stack_per_cpu as *mut u64)
    );

    helper_for_each_cpu(|| 
        unsafe {
            let x = new_hvc(new_HVC_INIT_VECTORS,
                            virt_to_phys(_new_vectors as *mut u8),
                            stack_top(virt_to_phys(*hyp_stack_per_cpu.add(new_get_smp_processor_id()))),
                            read_sysreg!(MPIDR_EL1));
            info!("[!] new_HVC_INIT_VECTORS for cpu {} returned {:x}", new_get_smp_processor_id(), x);
        }
    );

    helper_for_each_cpu(|| 
        unsafe {
            let x = new_hvc(0, 0, 0, 0);
            info!("[!] hvc returned {:x}", x);

            let host_dat = &*HOST_DAT_PER_CPU.0.load(Ordering::Acquire);
            info!("[!] host_dat saved x0: {:x}", host_dat.host_ctxt.regs[0]);
            info!("[!] host_dat saved x1: {:x}", host_dat.host_ctxt.regs[1]);
            info!("[!] host_dat saved x2: {:x}", host_dat.host_ctxt.regs[2]);
            info!("[!] host_dat saved x3: {:x}", host_dat.host_ctxt.regs[3]);
        }
    );

    0
}

#[no_mangle]
pub extern "C" fn new_exit() {
    info!("[!] module unloaded");
}

// TODO: Implement necessary helper functions
fn num_online_cpus() -> usize {}
fn virt_to_phys(virt: *mut u8) -> u64 {}
fn addr_new_vectors(base: *mut core::ffi::c_void, offset: usize) -> *mut u64 {}
fn helper_for_each_cpu<F: Fn()>(f: F) {}
fn helper_flush_virt(addr: *mut u64) {}
fn assemble_absolute_load(reg: u32, addr: u64, output: &mut [u32; 5]) {}
fn highmem_virt_to_phys(virt: *mut u8) -> u64 {}
fn helper_make_contig(start: *mut u8, size: usize) -> *mut core::ffi::c_void {}
fn init_init_mm_ptr() {}
fn helper_init_host_cpu_context(ctxt: &mut KvmCpuContext) {}
fn new_get_smp_processor_id() -> usize {}
fn new_reset_vectors() {}
fn new_set_vectors(addr: u64) {}
unsafe fn new_hvc(arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {}
fn stack_top(addr: u64) -> u64 {}

const _FIXUP_1: usize;
const _FIXUP_2: usize;
const NEW_HYP_STACK_SIZE: usize;
const NEW_HVC_INIT_VECTORS: u64;;

unsafe {
    extern "C" {
        static _new_vectors: u8;
        static _new_vectors_end: u8;
        static _new_stub_vectors: u8;
    }
}

macro_rules! read_sysreg {
    ($reg:ident) => {{
        let value: u64;
        unsafe { asm!(concat!("mrs {}, ", stringify!($reg)), out(reg) value) };
        value
    }};
}
