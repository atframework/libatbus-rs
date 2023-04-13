// Copyright 2023 atframework
// Licensed under the MIT licenses.

use rand::{thread_rng, Rng};

pub fn generate_uuid() -> String {
    let mut ret = String::with_capacity(32);
    let mut engine = thread_rng();
    for _i in 0..16 {
        let c = engine.gen::<u8>();
        let lc = c % 16;
        let hc = c / 16;
        ret.push(if lc >= 10 {
            (lc - 10 + ('a' as u8)) as char
        } else {
            (lc + ('0' as u8)) as char
        });
        ret.push(if hc >= 10 {
            (hc - 10 + ('a' as u8)) as char
        } else {
            (hc + ('0' as u8)) as char
        });
    }

    ret
}
