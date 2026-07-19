//! xtask — Meridian dev tooling.
//! Commands: `codegen` (stub), `vectors` (identity/X3DH/ratchet/envelope/safety-number
//! conformance fixtures under `test-vectors/`), `package` (stub).
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
