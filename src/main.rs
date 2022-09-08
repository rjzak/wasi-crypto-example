use const_oid::ObjectIdentifier;
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE,
};
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_384, SECP_384_R_1, ID_EXTENSION_REQ,
};
use der::{asn1::{AnyRef, UIntRef, BitStringRef, GeneralizedTime}};
use der::{Decode, Encode};
use p384::ecdsa::signature::Signature;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use std::time::{Duration, SystemTime};
use wasi_crypto_guest::signatures::SignatureKeyPair;
use wasi_crypto_guest::prelude::Hash;
use x509::{attr::Attribute, {name::RdnSequence, request::{CertReq, CertReqInfo, ExtensionReq}, time::{Time, Validity}, Certificate, TbsCertificate}};
use x509::ext::{Extension, pkix::{BasicConstraints, KeyUsage, KeyUsages}};

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
    println!("Certificate was successfully constructed and parsed, now let's try a Certificate Request.");

    let exts = vec![Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.1"),
            critical: false,
            extn_value: &[],
        }];

    let req = ExtensionReq::from(exts).to_vec().unwrap();
    let any = AnyRef::from_der(&req).unwrap();
    let att = Attribute {
        oid: ID_EXTENSION_REQ,
        values: vec![any].try_into().unwrap(),
    };
    let cri = CertReqInfo {
        version: x509::request::Version::V1,
        attributes: vec![att].try_into().unwrap(),
        subject: RdnSequence::default(),
        public_key: SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_384,
                parameters: None,
            },
            subject_public_key: &pub_key_sec.to_vec().unwrap(),
        },
    };

    let cri_bytes = cri.to_vec().unwrap();

    let cri_sig = match keypair.sign(cri_bytes) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("keypair.sign() error {:?}", e);
            return;
        }
    };
    let sign = match cri_sig.raw() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("keypair.sign().raw() error {:?}", e);
            return;
        }
    };
    let sign = p384::ecdsa::Signature::from_bytes(&sign).unwrap().to_vec();

    let rval = CertReq {
        info: cri,
        algorithm: AlgorithmIdentifier {
            oid: ECDSA_WITH_SHA_384,
            parameters: None,
        },
        signature: BitStringRef::from_bytes(&sign).unwrap(),
    };

    let rval = rval.to_vec().unwrap();

    let cr = match CertReq::from_der(rval.as_ref()) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to decode CertRequest {:?}", e);
            return;
        }
    };
    println!("Decoded CSR");
    if cr.info.version != x509::request::Version::V1 {
        eprintln!("invalid version");
        return;
    }

    let signature_obj = match wasi_crypto_guest::signatures::Signature::from_raw("ECDSA_P384_SHA384", cr.signature.as_bytes().unwrap()) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to get wasi-crypto signature object from bytes {:?}", e);
            return;
        }
    };

    let body = match cr.info.to_vec() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to get CR info as bytes {:?}", e);
            return;
        }
    };
    match public_key.signature_verify(body, &signature_obj) {
        Ok(_) => {
            println!("Signature verified!");
        }
        Err(e) => {
            eprintln!("Failed to validate signature {:?}", e);
            return;
        }
    }
}
