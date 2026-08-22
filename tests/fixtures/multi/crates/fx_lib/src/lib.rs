//! Fixture library crate: has public items, an unsafe fn, and tests.

pub mod util;

/// Public API item #1.
pub fn hello() -> &'static str {
    "hi"
}

/// Public API item #2.
pub struct Widget {
    pub id: u32,
}

/// Third public item, plus an unsafe surface for `unsafe-surface`.
pub unsafe fn raw_poke() -> u8 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_works() {
        assert_eq!(hello(), "hi");
    }
}
