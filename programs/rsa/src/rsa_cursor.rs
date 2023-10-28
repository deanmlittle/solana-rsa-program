use std::io::{Cursor, Read};

use solana_program::{ msg, program_error::ProgramError };

use crate::rsa_pubkey::RSAPubkey;

pub const DER_SEQUENCE: u8 = 0x30;
pub const DER_INTEGER: u8 = 0x02;
pub const DER_BITSTRING: u8 = 0x03;

pub trait RSACursor {
    fn read_u8(&mut self) -> Result<u8, ProgramError>;
    fn read_u8_exact(&mut self, n: u8) -> Result<(), ProgramError>;
    fn read_u16(&mut self) -> Result<u16, ProgramError>;
    fn read_length(&mut self) -> Result<usize, ProgramError>;
    fn read_bytes(&mut self, l: usize) -> Result<Vec<u8>, ProgramError>;
    fn read_pubkey(&mut self) -> Result<RSAPubkey, ProgramError>;
}

impl RSACursor for Cursor<&[u8]> {
    fn read_u8(&mut self) -> Result<u8, ProgramError> {
        let mut b = [0u8];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }

    fn read_u16(&mut self) -> Result<u16, ProgramError> {
        let mut b = [0u8;2];
        self.read_exact(&mut b)?;
        Ok(u16::from_be_bytes(b))
    }

    fn read_u8_exact(&mut self, n: u8) -> Result<(), ProgramError> {
        let v = self.read_u8()?;
        if v != n {
            msg!("Invalid byte: {}, expected: {}", v, n);
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }

    fn read_length(&mut self) -> Result<usize, ProgramError> {
        let length = self.read_u8()?;
        match length < 0x80 {
            true => Ok(length as usize),
            false => {
                match length {
                    0x81 => Ok(usize::from(self.read_u8()?)),
                    0x82 => Ok(usize::from(self.read_u16()?)),
                    n => {
                        msg!("Invalid integer length: {}", n);
                        Err(ProgramError::InvalidInstructionData)
                    }
                }
            }
        }
    }

    fn read_bytes(&mut self, l: usize) -> Result<Vec<u8>, ProgramError> {
        let mut v = vec![0_u8; l as usize];
        self.read_exact(&mut v)?;
        Ok(v)
    }

    fn read_pubkey(&mut self) -> Result<RSAPubkey, ProgramError> {
        self.read_u8_exact(DER_SEQUENCE)?;
        self.read_length()?;
        match self.read_u8()? {
            0x30 => {
                let oid_len = self.read_length()?;
                self.read_bytes(oid_len)?;
                self.read_u8_exact(DER_BITSTRING)?;
                self.read_length()?;
                self.read_u8_exact(0x00)?;
                self.read_u8_exact(DER_SEQUENCE)?;
                self.read_length()?;
                self.read_u8_exact(DER_INTEGER)?;
            },
            0x02 => (),
            v => {
                msg!("Invalid byte: {}, expected 0x30 or 0x02", v);
                return Err(ProgramError::InvalidInstructionData);
            }
        }
        let n_len = self.read_length()?;
        let mut n = self.read_bytes(n_len)?;
        // trim zero padding for DER-encoded negative integers
        if n.len() % 2 == 1 && n[0] == 0x00 {
            n = n[1..].to_vec()
        }
        self.read_u8_exact(DER_INTEGER)?;
        let e_len = self.read_length()?;
        let e = self.read_bytes(e_len)?;
        Ok(RSAPubkey(n,e))
    }
}
