use candid::{CandidType, Deserialize};
use ic_types::hash_tree::{Label, LookupResult};
use ic_types::HashTree;

pub mod bls;
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";

#[derive(Debug, Deserialize, PartialEq, Eq, CandidType)]
pub struct Delegation {
    #[serde(with = "serde_bytes")]
    pub subnet_id: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// The hash tree.
    pub tree: HashTree<'a>,

    /// The signature of the root hash in `tree`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,

    /// A delegation from the root key to the key used to sign `signature`, if one exists.
    pub delegation: Option<Delegation>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum CertificationError {
    CertificateVerificationFailed,
    CertificateNotAuthorized,
    InvalidCborData,
    LookupPathAbsent,
    LookupPathUnknown,
    LookupPathError,
}

/// Looks up a value in the certificate's tree at the specified hash.
///
/// Returns the value if it was found; otherwise, errors with `LookupPathAbsent`, `LookupPathUnknown`, or `LookupPathError`.
pub fn lookup_value<'a, P>(
    certificate: &'a Certificate<'a>,
    path: P,
) -> Result<&'a [u8], CertificationError>
where
    for<'p> &'p P: IntoIterator<Item = &'p Label>,
    P: Into<Vec<Label>>,
{
    match certificate.tree.lookup_path(&path) {
        LookupResult::Absent => Err(CertificationError::LookupPathAbsent),
        LookupResult::Unknown => Err(CertificationError::LookupPathUnknown),
        LookupResult::Found(value) => Ok(value),
        LookupResult::Error => Err(CertificationError::LookupPathError),
    }
}

pub fn extract_der(buf: Vec<u8>) -> Vec<u8> {
    buf[DER_PREFIX.len()..].to_vec()
}
