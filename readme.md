## Wasi-Crypto Demo

The purpose of this project is to demonstrate how to use the Wasi-Crypto [crate](https://github.com/WebAssembly/wasi-crypto/tree/main/implementations/hostcalls/rust).

### Prerequisites:
* [Wasi-libc](https://github.com/WebAssembly/wasi-libc)
* Rust (tested only with nightly)
* Wasi target support: `rustup target add wasm32-wasi`

### Compiling:
* `WASI_SDK_DIR=/opt/wasi-sdk/share/wasi-sysroot/ cargo build`
  * Note: the Wasi-crypto crate depends on a crate called "pqcrypto", which seems to have a bug in it's [build.rs](https://github.com/rustpq/pqcrypto/blob/main/pqcrypto-internals/build.rs#L42) script. It seems to think that the environment variable **WASI_SDK_DIR** should point to the `share/sysroot/` directory, whereas it seems logical (to me) that it points to the installation directory of the Wasi-libc directory.
  * Make sure the environment variable points to the location where the SDK's sysroot is located on your system.

### Running:
* `cargo run`

### Output:

```
Hello, world!
Keypair generated.
Signature for "test":
6fa385a4c71a6c4566c25fb93ba6f79589213d574841872b8bf14ce54a1341cc29ccecbdd78ccbaee5ca2a1c775cdafeb2dcc7f5e4cfcdc26fb0f06828f0
Signature validated.
Hash for "test":
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2bb822cd15d6c15b0f0a8
```
* Note that the signature should be different for each run.
* The SHA hash can be validated via Python:
```python
import hashlib
hashlib.sha256(b"test").hexdigest()
```