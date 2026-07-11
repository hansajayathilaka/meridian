//! xtask — Meridian dev tooling.
//! Commands: `codegen` (stub), `vectors` (T01 identity conformance fixtures), `package` (stub).
//! See docs/architecture/stack.md §4.

mod vectors;

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "codegen" => println!("TODO: run UniFFI + wasm-bindgen codegen -> bindings/"),
        "vectors" => {
            if let Err(e) = vectors::generate() {
                eprintln!("xtask vectors: {e}");
                std::process::exit(1);
            }
        }
        _ => println!("xtask: commands = codegen | vectors | package"),
    }
}
