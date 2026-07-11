//! xtask — Meridian dev tooling (scaffold placeholder).
//! Real commands: `codegen`, `vectors`, `package`. See docs/architecture/stack.md §4.

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "codegen" => println!("TODO: run UniFFI + wasm-bindgen codegen -> bindings/"),
        "vectors" => println!("TODO: (re)generate conformance vectors -> test-vectors/"),
        _ => println!("xtask: commands = codegen | vectors | package (scaffold)"),
    }
}
