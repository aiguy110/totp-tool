use totp_rs::*;

use crate::generic_error::GenericError;

pub mod proto_message {
    include!(concat!(env!("OUT_DIR"), "/migration.rs"));
}

impl Into<Result<TOTP, GenericError>> for proto_message::Payload {
    fn into(self) -> Result<TOTP, GenericError> {
        let otp_params = self.otp_parameters[0].clone();
        let otp_config = TOTP { 
            algorithm: match otp_params.algorithm() {
                proto_message::payload::Algorithm::Unspecified => return Err(GenericError::new("Hash algorithm not specified.")),
                proto_message::payload::Algorithm::Sha1 => Algorithm::SHA1,
                proto_message::payload::Algorithm::Sha256 => Algorithm::SHA256,
                proto_message::payload::Algorithm::Sha512 => Algorithm::SHA512,
                proto_message::payload::Algorithm::Md5 => return Err(GenericError::new("MD5 hash algorithm not supported.")),
            }, 
            digits: match otp_params.digits() {
                proto_message::payload::DigitCount::Unspecified => return Err(GenericError::new("Digit count not specified.")),
                proto_message::payload::DigitCount::Six => 6,
                proto_message::payload::DigitCount::Eight => 8,
            }, 
            skew: 1, 
            step: 30, 
            secret: otp_params.secret, 
            issuer: Some(otp_params.issuer), 
            account_name: otp_params.name 
        };

        Ok(otp_config)
    }
}