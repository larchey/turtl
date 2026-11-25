#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| turtl_fuzz::oracles::kem_decaps(data));
