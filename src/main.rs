use wasi_crypto_guest::signatures::SignatureKeyPair;
use wasi_crypto_guest::prelude::Hash;

fn main() {
    const TEST_DATA: &str = "test";
    println!("Hello, world!");

    let keypair = match SignatureKeyPair::generate("ECDSA_P384_SHA384") {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error generating keypair: {:?}", e);
            return;
        }
    };
    println!("Keypair generated.");

    let signature = match keypair.sign(TEST_DATA.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error signing: {:?}", e);
            return;
        }
    };

    let signature_raw = match signature.raw() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error getting signature bytes: {:?}", e);
            return;
        }
    };

    println!("Signature for \"{}\":", TEST_DATA);
    for v in &signature_raw {
        print!("{:x}", v);
    }
    print!("\n");

    println!("Signature size: {}", signature_raw.len());

    let public_key = match keypair.publickey() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error getting public key: {:?}", e);
            return;
        }
    };

    match public_key.signature_verify(TEST_DATA.as_bytes(), &signature) {
        Ok(_) => {
            println!("Signature validated.");
        }
        Err(e) => {
            eprintln!("Error validating signature {:?}", e);
            return;
        }
    }

    let hash = match Hash::hash("SHA-256", TEST_DATA.as_bytes(), 32, None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error hashing test data {:?}", e);
            return;
        }
    };

    println!("Hash for \"{}\":", TEST_DATA);
    for h in hash {
        print!("{:x}", h);
    }
    print!("\n");
}
