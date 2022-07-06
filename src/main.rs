use wasi_crypto;
use wasi_crypto::{AlgorithmType, SignatureEncoding};

fn main() {
    const TEST_DATA: &str = "test";
    println!("Hello, world!");

    let context = wasi_crypto::CryptoCtx::new();

    // Generate keys
    let keypair =
        match context.keypair_generate(AlgorithmType::Signatures, "ECDSA_P256_SHA256", None) {
            Ok(k) => k,
            Err(x) => {
                eprintln!("Error generating keypair: {:?}", x);
                return;
            }
        };
    println!("Keypair generated.");

    let pk_handle = context.keypair_publickey(keypair).unwrap();
    let state_handle = context.signature_state_open(keypair).unwrap();

    // Sign some data
    context
        .signature_state_update(state_handle, TEST_DATA.as_bytes())
        .unwrap();
    let signature_handle = context.signature_state_sign(state_handle).unwrap();
    let signature_value_handle = context
        .signature_export(signature_handle, SignatureEncoding::Raw)
        .unwrap();
    let mut raw = vec![0u8; context.array_output_len(signature_value_handle).unwrap()];
    context
        .array_output_pull(signature_value_handle, &mut raw)
        .unwrap();
    println!("Signature for \"{}\":", TEST_DATA);
    for v in raw {
        print!("{:x}", v);
    }
    print!("\n");

    // Validate the signature
    let verification_state_handle = context
        .signature_verification_state_open(pk_handle)
        .unwrap();
    context
        .signature_verification_state_update(verification_state_handle, TEST_DATA.as_bytes())
        .unwrap();
    context
        .signature_verification_state_verify(verification_state_handle, signature_handle)
        .unwrap();
    println!("Signature validated.");

    // Hash some data
    let hash_handle = context.symmetric_state_open("SHA-256", None, None).unwrap();
    context
        .symmetric_state_absorb(hash_handle, TEST_DATA.as_bytes())
        .unwrap();
    let mut out = [0u8; 32];
    context
        .symmetric_state_squeeze(hash_handle, &mut out)
        .unwrap();
    context.symmetric_state_close(hash_handle).unwrap();
    println!("Hash for \"{}\":", TEST_DATA);
    for v in out {
        print!("{:x}", v);
    }
    print!("\n");

    // Clean-up
    context
        .signature_verification_state_close(verification_state_handle)
        .unwrap();
    context.signature_state_close(state_handle).unwrap();
    context.keypair_close(keypair).unwrap();
    context.publickey_close(pk_handle).unwrap();
    context.signature_close(signature_handle).unwrap();
}
