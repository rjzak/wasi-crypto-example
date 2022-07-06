## Wasi-Crypto Demo
The purpose of this project is to demonstrate how to use the Wasi-Crypto [crate](https://github.com/WebAssembly/wasi-crypto/tree/main/implementations/bindings/rust).

### Prerequisites:
* Rust (tested only with nightly)
* Wasi target support: `rustup target add wasm32-wasi`
* [Wasmtime](https://github.com/bytecodealliance/wasmtime)
  * Compile Wasmtime from source: `cargo build --release --features wasi-crypto`.

### Compiling:
* `cargo build`

### Running:
* `cargo run` if the compiled Wasmtime is in your `$PATH`.
* `CARGO_TARGET_WASM32_WASI_RUNNER="/path/to/my/compiled/wasmtime run --wasi-modules experimental-wasi-crypto --" cargo run`

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
* Note that the signature should be different for each run, since the data string is signed using a random key.
* The SHA hash can be validated via Python:
```python
import hashlib
hashlib.sha256(b"test").hexdigest()
```

### Notes:
* Trying to compile a native binary, with `cargo build --target=x86_64-unknown-linux-gnu` for example, should result in many `undefined reference to....` errors.
* You can check the Wasm output and see the use of the built-in functions for Wasi-crypto using a hex editor, such as `xxd`:
```commandline
xxd target/wasm32-wasi/release/wasi-crypto-example.wasm | head -n 20
00000000: 0061 736d 0100 0000 0174 1160 0000 6001  .asm.....t.`..`.
00000010: 7f00 6001 7f01 7e60 027f 7f00 6001 7f01  ..`...~`....`...
00000020: 7f60 027f 7f01 7f60 037f 7f7f 0060 037f  .`.....`.....`..
00000030: 7f7f 017f 6004 7f7f 7f7f 017f 6005 7f7f  ....`.......`...
00000040: 7f7f 7f01 7f60 0001 7f60 047f 7f7f 7f00  .....`...`......
00000050: 6005 7f7f 7f7f 7f00 6007 7f7f 7f7f 7f7f  `.......`.......
00000060: 7f00 6006 7f7f 7f7f 7f7f 017f 6007 7f7f  ..`.........`...
00000070: 7f7f 7f7f 7f01 7f60 037e 7f7f 017f 02b4  .......`.~......
00000080: 050e 1c77 6173 695f 6570 6865 6d65 7261  ...wasi_ephemera
00000090: 6c5f 6372 7970 746f 5f63 6f6d 6d6f 6e10  l_crypto_common.
000000a0: 6172 7261 795f 6f75 7470 7574 5f6c 656e  array_output_len
000000b0: 0005 1c77 6173 695f 6570 6865 6d65 7261  ...wasi_ephemera
000000c0: 6c5f 6372 7970 746f 5f63 6f6d 6d6f 6e11  l_crypto_common.
000000d0: 6172 7261 795f 6f75 7470 7574 5f70 756c  array_output_pul
000000e0: 6c00 0827 7761 7369 5f65 7068 656d 6572  l..'wasi_ephemer
000000f0: 616c 5f63 7279 7074 6f5f 6173 796d 6d65  al_crypto_asymme
00000100: 7472 6963 5f63 6f6d 6d6f 6e10 6b65 7970  tric_common.keyp
00000110: 6169 725f 6765 6e65 7261 7465 0009 2777  air_generate..'w
00000120: 6173 695f 6570 6865 6d65 7261 6c5f 6372  asi_ephemeral_cr
00000130: 7970 746f 5f61 7379 6d6d 6574 7269 635f  ypto_asymmetric_
```