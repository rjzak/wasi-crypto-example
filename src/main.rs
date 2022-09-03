use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE,
};
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_384, SECP_384_R_1,
};
use der::{asn1::{UIntRef, BitStringRef, GeneralizedTime}};
use der::{Decode, Encode};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use std::time::{Duration, SystemTime};
use wasi_crypto_guest::signatures::SignatureKeyPair;
use wasi_crypto_guest::prelude::Hash;
use x509::{name::RdnSequence, time::{Time, Validity}, Certificate, TbsCertificate};
use x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};

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

    let pub_key_raw = match public_key.raw() {
        Ok(r) => {
            println!("Public key size: {}", r.len());
            r
        },
        Err(e) => {
            eprint!("Error getting raw public key {:?}", e);
            return;
        }
    };

    println!("Public key raw():");
    for v in &pub_key_raw {
        print!("{:x}", v);
    }
    print!("\n");

    let pub_key_sec = match public_key.sec() {
        Ok(x) => x,
        Err(e) => {
            eprint!("Error getting sec public key {:?}", e);
            return;
        }
    };

    println!("Public key sec():");
    for v in &pub_key_sec {
        print!("{:x}", v);
    }
    print!("\n");

    let _pub_key_obj =
        match elliptic_curve::PublicKey::<p384::NistP384>::from_sec1_bytes(&pub_key_sec) {
            Ok(x) => x,
            Err(e) => {
                eprint!("Error getting sec public key {:?}", e);
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

    println!("Now, let's create a certificate with the wasi-crypto keypair.");

    let rdns = RdnSequence::encode_from_string("CN=localhost").unwrap();
    let rdns = RdnSequence::from_der(&rdns).unwrap();

    let ku = KeyUsage(KeyUsages::KeyCertSign.into()).to_vec().unwrap();
    let bc = BasicConstraints {
        ca: true,
        path_len_constraint: Some(0),
    }
    .to_vec().unwrap();

    let now = SystemTime::now();
    let dur = Duration::from_secs(60 * 60 * 24 * 365);

    let cert = TbsCertificate {
        version: x509::Version::V3,
        serial_number: UIntRef::new(&[0u8]).unwrap(),
        signature: AlgorithmIdentifier { // Should be same as outer signing AlgorithmIdentifier
            oid: ECDSA_WITH_SHA_384, // The format of the signature we're expecting to use for signing
            parameters: None
        },
        issuer: rdns.clone(),
        validity: Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_system_time(now).unwrap()),
            not_after: Time::GeneralTime(GeneralizedTime::from_system_time(now + dur).unwrap()),
        },
        subject: Default::default(),
        subject_public_key_info: SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: SECP_384_R_1, // SECP_384 means SEC1 formatted P-384, format of the public key we're embedding
                parameters: None
            },
            subject_public_key: &pub_key_sec.to_vec().unwrap(),
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            x509::ext::Extension {
                extn_id: ID_CE_KEY_USAGE,
                critical: true,
                extn_value: &ku,
            },
            x509::ext::Extension {
                extn_id: ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: &bc,
            },
        ]),
    };

    let cert_vec = match cert.to_vec() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to convert cert to Vec: {:?}", e);
            return;
        }
    };

    println!("Generated certificate bytes:");
    for v in &cert_vec {
        print!("{:x}", v);
    }
    print!("\nIs it valid?\n");

    // Need to sign cert before it becomes a real certificate!

    let cert_signature = match keypair.sign(cert_vec) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to sign TbsCertificate: {:?}", e);
            return;
        }
    };

    let cert_signature = match cert_signature.raw() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to get raw() from wasi_crypto Signature: {:?}", e);
            return;
        }
    };

    let cert_signature = match BitStringRef::from_bytes(&cert_signature) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to get BitStringRef from wasi_crypto Signature bytes: {:?}", e);
            return;
        }
    };

    let cert_signed = Certificate {
        tbs_certificate: cert,
        signature_algorithm: AlgorithmIdentifier {
            oid: ECDSA_WITH_SHA_384,
            parameters: None
        },
        signature: cert_signature,
    };

    let cert_signed_bytes = match cert_signed.to_vec() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to convert Certificate to Vec: {:?}", e);
            return;
        }
    };

    match Certificate::from_der(&cert_signed_bytes) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to validate certificate: {:?}", e);
            return;
        }
    }
    println!("Certificate was successfully constructed and parsed.");
}
