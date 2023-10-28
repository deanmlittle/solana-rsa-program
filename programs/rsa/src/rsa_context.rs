use borsh::{BorshDeserialize, BorshSerialize};

// Size as a multiple of 512 bits
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug)]
#[borsh(use_discriminant=true)]

#[repr(u8)]
pub enum RSAKeySize {
    RSA512 = 1,
    RSA1024 = 2,
    RSA2048 = 4,
    RSA3072 = 6,
    RSA4096 = 8,
    RSA8192 = 16
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug)]
#[borsh(use_discriminant=true)]

#[repr(u8)]
pub enum RSAHashingAlgorithm {
    NAIVE = 0,
    SHA256 = 1,
    SHA3 = 2,
    BLAKE3 = 3
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct RSAContext {
    pub size: RSAKeySize,
    pub hash: RSAHashingAlgorithm,
    pub message: Vec<u8>,
    pub signature: Vec<u8>, 
    pub pubkey: Vec<u8>
}

impl RSAContext {
    pub fn new(size: RSAKeySize, hash: RSAHashingAlgorithm, message: &[u8], signature: &[u8], pubkey: &[u8]) -> RSAContext {
        RSAContext {
            size,
            hash,
            message: message.to_vec(),
            signature: signature.to_vec(),
            pubkey: pubkey.to_vec()
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![];
        self.serialize(&mut data).unwrap();
        data
    }
}