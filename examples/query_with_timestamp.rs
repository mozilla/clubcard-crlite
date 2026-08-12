/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use base64::Engine;
use clubcard_crlite::{CRLiteClubcard, CRLiteKey, CRLiteStatus};
use sha2::{Digest, Sha256};
use std::env::args;
use std::path::PathBuf;
use std::process::ExitCode;
use x509_parser::prelude::*;

fn read_as_der(path: &PathBuf) -> Result<Vec<u8>, std::io::Error> {
    let bytes = std::fs::read(path)?;
    match parse_x509_pem(&bytes) {
        Ok((_, pem)) => Ok(pem.contents),
        _ => Ok(bytes),
    }
}

fn parse_args() -> Option<(PathBuf, PathBuf, PathBuf, String, u64)> {
    let mut args = args();
    let _name = args.next()?;
    Some((
        args.next()?.into(),
        args.next()?.into(),
        args.next()?.into(),
        args.next()?,
        args.next()?.parse().ok()?,
    ))
}

fn main() -> std::process::ExitCode {
    let Some((filter_path, issuer_cert_path, end_entity_cert_path, base64_log_id, timestamp)) =
        parse_args()
    else {
        eprintln!(
            "Usage: {} <filter> <issuer certificate> <end entity certificate> <log id> <timestamp>",
            args().next().unwrap()
        );
        return ExitCode::FAILURE;
    };

    let Ok(filter_bytes) = std::fs::read(&filter_path) else {
        eprintln!("Could not read filter");
        return ExitCode::FAILURE;
    };

    let Ok(filter) = CRLiteClubcard::from_bytes(&filter_bytes) else {
        eprintln!("Could not parse filter");
        return ExitCode::FAILURE;
    };

    let Ok(issuer_bytes) = read_as_der(&issuer_cert_path) else {
        eprintln!("Could not read issuer certificate");
        return ExitCode::FAILURE;
    };

    let Ok((_, issuer)) = X509Certificate::from_der(&issuer_bytes) else {
        eprintln!("Could not parse issuer certificate");
        return ExitCode::FAILURE;
    };

    let Ok(cert_bytes) = read_as_der(&end_entity_cert_path) else {
        eprintln!("Could not read end-entity certificate");
        return ExitCode::FAILURE;
    };

    let Ok((_, cert)) = X509Certificate::from_der(&cert_bytes) else {
        eprintln!("Could not parse end-entity certificate");
        return ExitCode::FAILURE;
    };

    if cert.verify_signature(Some(issuer.public_key())).is_err() {
        eprintln!("Invalid signature (wrong issuer certificate?)");
        return ExitCode::FAILURE;
    }

    if !cert.tbs_certificate.validity.is_valid() {
        eprintln!("End-entity certificate is expired");
        return ExitCode::FAILURE;
    }

    let mut log_id = [0u8; 32];
    match base64::prelude::BASE64_STANDARD.decode(&base64_log_id) {
        Ok(bytes) if bytes.len() == 32 => log_id.copy_from_slice(&bytes),
        _ => return ExitCode::FAILURE,
    };
    let scts = vec![(&log_id, timestamp)];

    let issuer_spki_hash: [u8; 32] = Sha256::digest(issuer.tbs_certificate.subject_pki.raw).into();
    let serial = cert.tbs_certificate.raw_serial();
    let key = CRLiteKey::new(&issuer_spki_hash, serial);

    match filter.contains(&key, scts.into_iter()) {
        CRLiteStatus::Good => println!("Good"),
        CRLiteStatus::Revoked => println!("Revoked"),
        CRLiteStatus::NotEnrolled | CRLiteStatus::NotCovered => println!("Unknown"),
    };

    ExitCode::SUCCESS
}
