use candid::{Decode, Encode, Principal};
use ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport;
use ic_agent::Agent;
use std::time::Duration;
use Certification_Validate::bls::bls12381::bls;
use Certification_Validate::{
    extract_der, lookup_value, Certificate, CertificationError, Delegation,
};

const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";
const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

#[tokio::main]
async fn main() {
    get_certification_and_verify().await;
}

async fn get_certification_and_verify() {
    let url = "https://ic0.app";
    let transport = ReqwestHttpReplicaV2Transport::create(url).unwrap();
    let cid = Principal::from_text("gibz6-6yaaa-aaaak-qan7a-cai").unwrap();
    let waiter = garcon::Delay::builder()
        .throttle(Duration::from_millis(10))
        .timeout(Duration::from_secs(6))
        .build();
    let agent = Agent::builder().with_transport(transport).build().unwrap();
    let _ = agent
        .update(&cid, "set")
        .with_arg(&Encode!().unwrap())
        .call_and_wait(waiter)
        .await
        .unwrap();
    println!("calling the set function finished");
    let res = agent
        .query(&cid, "get")
        .with_arg(&Encode!().unwrap())
        .call()
        .await
        .unwrap();
    let res = Decode!(&res, Option<Vec<u8>>).unwrap();
    if let Some(cer) = res {
        let cer = serde_cbor::from_slice::<Certificate>(&cer).unwrap();
        verify(&cer, cid.clone()).expect("failed to verify");
        println!("Certification : ");
        println!("subnet signature : {:?}", cer.signature);
        println!("subnet delegation : ");
        let delegation = cer.delegation.unwrap();
        println!(
            "Subnet Id: {}",
            Principal::from_slice(delegation.subnet_id.as_slice())
        );
        println!("\tSubnet Certificate : {:?}", delegation.certificate);
        println!("Certification Hash Tree: {:#?}", cer.tree);
    } else {
        println!("decode certification failed");
    }
}

/// Verify a certificate, checking delegation if present.
/// Only passes if the certificate also has authority over the canister.
pub fn verify(
    cert: &Certificate,
    effective_canister_id: Principal,
) -> Result<(), CertificationError> {
    let sig = &cert.signature;

    let root_hash = cert.tree.digest();
    let mut msg = vec![];
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);

    let der_key = check_delegation(&cert.delegation)?;
    let key = extract_der(der_key);
    let result = bls::core_verify(sig, &*msg, &*key);
    if result != bls::BLS_OK {
        Err(CertificationError::CertificateVerificationFailed)
    } else {
        println!("verify successfully");
        Ok(())
    }
}

fn check_delegation(delegation: &Option<Delegation>) -> Result<Vec<u8>, CertificationError> {
    match delegation {
        None => Ok(IC_ROOT_KEY.to_vec()),
        Some(delegation) => {
            let cert: Certificate = serde_cbor::from_slice(&delegation.certificate)
                .map_err(|e| CertificationError::InvalidCborData)?;
            let public_key_path = [
                "subnet".into(),
                delegation.subnet_id.clone().into(),
                "public_key".into(),
            ];
            lookup_value(&cert, public_key_path).map(|pk| pk.to_vec())
        }
    }
}
