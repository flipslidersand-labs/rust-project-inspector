//! Minimal fixture used by rpi-collect / rpi-inspections tests.

pub mod math;

/// A public function so `pub-surface` has something to count.
pub fn greet(name: &str) -> String {
    format!("hello, {name}")
}

unsafe fn danger() -> u8 {
    // Exists so `unsafe-surface` has a target.
    42
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greets() {
        assert_eq!(greet("x"), "hello, x");
    }
}
