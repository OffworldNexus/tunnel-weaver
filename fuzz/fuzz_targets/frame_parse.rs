#![no_main]

use libfuzzer_sys::fuzz_target;
use weaver_mux::Frame;

fuzz_target!(|data: &[u8]| {
    let _ = Frame::parse(data);
});
