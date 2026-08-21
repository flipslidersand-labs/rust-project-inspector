//! Fixture binary crate: depends on fx_lib and intentionally has NO tests,
//! so `test-gap` flags it.

fn main() {
    println!("{}", fx_lib::hello());
}
