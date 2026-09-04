//! xtask — Meridian dev tooling.
//! Commands: `codegen` (wasm-bindgen half wired, task 12.10; UniFFI half still `TODO: confirm` —
//! no Kotlin/Swift-consuming task has landed yet, T12), `vectors` (identity/X3DH/ratchet/envelope/
//! safety-number conformance fixtures under `test-vectors/`), `package` (stub).
//! See docs/architecture/stack.md §4.

mod codegen;
mod vectors;

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "codegen" => {
            if let Err(e) = codegen::run() {
                eprintln!("xtask codegen: {e}");
                std::process::exit(1);
            }
        }
        "vectors" => {
            if let Err(e) = vectors::generate() {
                eprintln!("xtask vectors: {e}");
                std::process::exit(1);
            }
        }
        _ => println!("xtask: commands = codegen | vectors | package"),
    }
}
