#![no_std]
#![no_main]

use core::str::Utf8Error;
use aya_ebpf::{macros::kprobe, programs::ProbeContext, EbpfContext, TASK_COMM_LEN};
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::{bpf_override_return};
use aya_ebpf::macros::{lsm, tracepoint};
use aya_ebpf::programs::LsmContext;
use aya_log_ebpf::info;

const VM_AGENT_BYTES: &'static [u8] = b"vm-agent";

#[lsm]
pub fn hook_settime(ctx: LsmContext) -> i32 {
    let comm_bytes = match ctx.command() {
        Ok(bytes) => { bytes }
        Err(_) => { return 0; }
    };

    let len = comm_bytes.iter()
        .position(|&x| x == 0)
        .unwrap_or(comm_bytes.len());

    if len == VM_AGENT_BYTES.len() && &comm_bytes[..len] == VM_AGENT_BYTES {
        info!(&ctx, "match vm-agent, return -1");
        return -1;
    }
    0
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
