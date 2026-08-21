//! Second module so the fixture crate is multi-file.

/// A helper with an inner `unsafe` block for `unsafe-surface`.
pub fn twice(n: u32) -> u32 {
    let v = unsafe { core::mem::transmute::<u32, u32>(n) };
    v * 2
}
