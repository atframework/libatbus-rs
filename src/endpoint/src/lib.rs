// Copyright 2023 atframework
// Licensed under the MIT licenses.

extern crate libatbus_utility;
extern crate libatbus_protocol;

pub mod stream;
pub mod config;
pub mod endpoint;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
