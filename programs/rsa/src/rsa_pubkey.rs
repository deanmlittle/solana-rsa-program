use std::io::Cursor;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_error::ProgramError;

use crate::rsa_cursor::RSACursor;

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct RSAPubkey(pub Vec<u8>, pub Vec<u8>);

impl From<RSAPubkey> for (Vec<u8>, Vec<u8>) {
    fn from(value: RSAPubkey) -> Self {
        (value.0, value.1)
    }
}

impl RSAPubkey {
    pub fn from_der_bytes(b: &[u8]) -> Result<Self, ProgramError> {
        Cursor::new(b).read_pubkey()
    }

    pub fn to_der_bytes(&self) -> Result<Vec<u8>, ProgramError> {
        let mut der = vec![0x30];
        // check is n is considered negative by DER-encoding standards
        let pad_n = self.0[0] > 0x7f;
        let len_n = length_bytes(self.0.len() + pad_n as usize)?;
        let len_e = length_bytes(self.1.len())?;
        let len_total = length_bytes(len_n.len() + self.0.len() + len_e.len() + self.1.len() + 2)?;
        der.extend_from_slice(&len_total);
        der.extend_from_slice(&[0x02]);
        // add zero padding for DER-encoded negative integers if needed
        if pad_n {
            der.extend_from_slice(&[0x00]);
        }
        der.extend_from_slice(&len_n);
        der.extend_from_slice(&self.0);
        der.extend_from_slice(&[0x02]);
        der.extend_from_slice(&len_e);
        der.extend_from_slice(&self.1);
        Ok(der)
    }
}

pub fn length_bytes(l: usize) -> Result<Vec<u8>, std::io::Error> {
    if l < 0x80 {
        Ok(vec![l as u8])
    } else if l <= 0xff {
        Ok(vec![0x81, l as u8])
    } else if l <= 0xffff {
        let be_bytes = (l as u16).to_be_bytes();
        Ok(vec![0x82, be_bytes[0], be_bytes[1]])
    } else if l <= 0xffff {
        let be_bytes = (l as u16).to_be_bytes();
        Ok(vec![0x82, be_bytes[0], be_bytes[1]])
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidData, ProgramError::InvalidInstructionData))
    }
}