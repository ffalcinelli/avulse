//! Tests `avulse.sys` through its control device, as the user-mode backend will use it: opening
//! and closing handles, their parameters, shutdown and counters, refusing bad programs, and
//! WinDivert's filter vectors evaluated in the kernel (`EVAL`) against the evaluator.
//!
//! Run as Administrator, with the driver started (drivers/windows/scripts/test.ps1).

use std::ffi::c_void;
use std::process::ExitCode;
use std::ptr::{null, null_mut};

use avulse_abi::ioctl::{self, OpenRequest, Record};
use avulse_abi::{Address, Flags, Param, Syntax};
use avulse_filter::{Filter, Layer};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// WinDivert's filter vectors, as the filter crate's tests have them.
#[path = "../../../../crates/filter/src/tests/windivert_vectors.rs"]
#[rustfmt::skip]
#[allow(dead_code)]
mod windivert_vectors;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NO_DATA: u32 = 232;

/// A file of the control device, closed when dropped.
struct Device(HANDLE);

impl Device {
    fn open() -> Result<Device, u32> {
        let path: Vec<u16> = ioctl::DEVICE_PATH.encode_utf16().chain([0]).collect();
        // SAFETY: a NUL-terminated path and valid arguments.
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            // SAFETY: plain call.
            return Err(unsafe { GetLastError() });
        }
        Ok(Device(h))
    }

    /// One IOCTL: its output, or the Win32 error.
    fn ioctl(&self, code: u32, input: &[u8], out_len: usize) -> Result<Vec<u8>, u32> {
        let mut out = vec![0u8; out_len];
        let mut n = 0;
        // SAFETY: the buffers are valid for their lengths; the call is synchronous.
        let ok = unsafe {
            DeviceIoControl(
                self.0,
                code,
                input.as_ptr().cast::<c_void>(),
                input.len() as u32,
                out.as_mut_ptr().cast::<c_void>(),
                out.len() as u32,
                &mut n,
                null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: plain call.
            return Err(unsafe { GetLastError() });
        }
        out.truncate(n as usize);
        Ok(out)
    }

    fn open_handle(&self, src: &str, syntax: Syntax, layer: Layer) -> Result<(), u32> {
        let filter = match syntax {
            Syntax::WinDivert => Filter::compile_windivert(src, layer),
            _ => Filter::compile(src),
        }
        .unwrap_or_else(|e| panic!("{src}: {}", e.render(src)));
        let program = filter.program().expect("bytecode").to_bytes();
        let req = OpenRequest {
            layer,
            priority: 0,
            flags: Flags::SNIFF,
            program: &program,
            interfaces: vec![],
            filter: src,
            syntax,
        };
        self.ioctl(ioctl::OPEN, &req.encode(), 0).map(drop)
    }

    fn eval(&self, packet: &[u8], addr: &Address) -> Result<bool, u32> {
        let mut input = Vec::new();
        Record {
            addr: *addr,
            data: packet,
        }
        .encode_into(&mut input);
        let out = self.ioctl(ioctl::EVAL, &input, 4)?;
        Ok(out == [1, 0, 0, 0])
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: opened by `open`.
        unsafe { CloseHandle(self.0) };
    }
}

struct Checks {
    failed: usize,
    passed: usize,
}

impl Checks {
    fn check(&mut self, ok: bool, what: impl std::fmt::Display) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
            println!("FAILED: {what}");
        }
    }
}

fn main() -> ExitCode {
    let mut c = Checks {
        failed: 0,
        passed: 0,
    };
    let d = match Device::open() {
        Ok(d) => d,
        Err(e) => {
            println!(
                "cannot open {}: error {e} (is the driver started?)",
                ioctl::DEVICE_PATH
            );
            return ExitCode::FAILURE;
        }
    };

    // Before OPEN, a handle has nothing to read.
    let got = d.ioctl(ioctl::GET_PARAM, &0u32.to_le_bytes(), 8);
    c.check(got.is_err(), format_args!("GET_PARAM before OPEN: {got:?}"));

    // A program the verifier refuses, and a request it cannot decode.
    let bad = OpenRequest {
        layer: Layer::Network,
        priority: 0,
        flags: Flags::NONE,
        program: b"AVBC not really a program",
        interfaces: vec![],
        filter: "tcp",
        syntax: Syntax::Native,
    };
    let got = d.ioctl(ioctl::OPEN, &bad.encode(), 0);
    c.check(
        got == Err(ERROR_INVALID_PARAMETER),
        format_args!("a bad program: {got:?}"),
    );
    let got = d.ioctl(ioctl::OPEN, &bad.encode()[..20], 0);
    c.check(
        got == Err(ERROR_INVALID_PARAMETER),
        format_args!("a cut request: {got:?}"),
    );

    // Open, then the parameters, counters and shutdown.
    c.check(
        d.open_handle("tcp.port == 443", Syntax::Native, Layer::Network)
            .is_ok(),
        "OPEN",
    );
    let again = d.open_handle("udp", Syntax::Native, Layer::Network);
    c.check(again.is_err(), format_args!("a second OPEN: {again:?}"));
    let p = d.ioctl(ioctl::GET_PARAM, &0u32.to_le_bytes(), 8);
    c.check(
        p == Ok(4096u64.to_le_bytes().to_vec()),
        format_args!("QUEUE_LENGTH: {p:?}"),
    );
    let set = d.ioctl(
        ioctl::SET_PARAM,
        &ioctl::encode_set_param(Param::QueueTime, 4000),
        0,
    );
    c.check(set.is_ok(), format_args!("SET_PARAM: {set:?}"));
    let p = d.ioctl(ioctl::GET_PARAM, &1u32.to_le_bytes(), 8);
    c.check(
        p == Ok(4000u64.to_le_bytes().to_vec()),
        format_args!("QUEUE_TIME: {p:?}"),
    );
    let set = d.ioctl(
        ioctl::SET_PARAM,
        &ioctl::encode_set_param(Param::QueueTime, 1),
        0,
    );
    c.check(
        set == Err(ERROR_INVALID_PARAMETER),
        format_args!("out of range: {set:?}"),
    );
    let s = d
        .ioctl(ioctl::STATS, &[], 64)
        .map(|b| ioctl::decode_stats(&b));
    c.check(matches!(s, Ok(Ok(_))), format_args!("STATS: {s:?}"));
    let short = d.ioctl(ioctl::STATS, &[], 8);
    c.check(
        short.is_err(),
        format_args!("STATS into 8 bytes: {short:?}"),
    );
    c.check(
        d.ioctl(ioctl::SHUTDOWN, &3u32.to_le_bytes(), 0).is_ok(),
        "SHUTDOWN",
    );
    let bad = d.ioctl(ioctl::SHUTDOWN, &4u32.to_le_bytes(), 0);
    c.check(
        bad == Err(ERROR_INVALID_PARAMETER),
        format_args!("SHUTDOWN 4: {bad:?}"),
    );
    // Shut down with nothing queued: RECV ends at once (STATUS_PIPE_EMPTY).
    let recv = d.ioctl(ioctl::RECV, &[], 4096);
    c.check(
        recv == Err(ERROR_NO_DATA),
        format_args!("RECV after shutdown: {recv:?}"),
    );
    drop(d);

    // WinDivert's filter vectors, in the kernel, at the NETWORK layer and outbound, as
    // WinDivert's own tests run them, against the evaluator.
    let mut addr = Address::new(Layer::Network);
    addr.outbound = true;
    let mut ran = 0;
    for &(src, packet, want) in windivert_vectors::VECTORS {
        if src.contains("random") {
            continue;
        }
        let bytes = windivert_vectors::PACKETS[packet].1;
        let d = match Device::open() {
            Ok(d) => d,
            Err(e) => {
                c.check(false, format_args!("opening the device: error {e}"));
                break;
            }
        };
        if let Err(e) = d.open_handle(src, Syntax::WinDivert, Layer::Network) {
            c.check(false, format_args!("{src}: OPEN failed: {e}"));
            continue;
        }
        let mut a = addr;
        a.ipv6 = bytes[0] >> 4 == 6;
        let got = d.eval(bytes, &a);
        c.check(
            got == Ok(want),
            format_args!("{src}: kernel {got:?}, expected {want}"),
        );
        ran += 1;
    }
    c.check(ran > 200, format_args!("only {ran} vectors ran"));

    // A native filter on metadata the address carries.
    let d = Device::open().expect("device");
    d.open_handle("outbound and not loopback", Syntax::Native, Layer::Network)
        .expect("OPEN");
    let packet = windivert_vectors::PACKETS[0].1;
    let mut a = Address::new(Layer::Network);
    for (outbound, loopback, want) in [
        (true, false, true),
        (false, false, false),
        (true, true, false),
    ] {
        a.outbound = outbound;
        a.loopback = loopback;
        let got = d.eval(packet, &a);
        c.check(
            got == Ok(want),
            format_args!("outbound {outbound}, loopback {loopback}: {got:?}"),
        );
    }

    // A handle left open: the process's exit closes it (IRP_MJ_CLEANUP), and test.ps1 then stops
    // the driver, which only unloads once every file is closed.
    let left = Device::open().expect("device");
    left.open_handle("tcp", Syntax::Native, Layer::Network)
        .expect("OPEN");
    std::mem::forget(left);

    println!("{} passed, {} failed", c.passed, c.failed);
    if c.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
