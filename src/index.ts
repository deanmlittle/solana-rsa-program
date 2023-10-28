import { PublicKey } from "@solana/web3.js";

export const RSA_PROGRAM_ID = new PublicKey(
  "rsaGmKjfFv7JW14MXd5AjwBMcknxkAsbtLvYdG4KaEr"
);

export enum RSAKeyLength {
  RSA512 = 1,
  RSA1024 = 2,
  RSA2048 = 4,
  RSA3072 = 6,
  RSA4096 = 8,
}

export enum RSAHashAlgorithm {
  NAIVE = 0,
  SHA256 = 1,
  SHA3 = 2,
  BLAKE3 = 4,
}

export class RSASignatureInstruction {
  constructor(
    public keyLength: RSAKeyLength,
    public hashType: RSAHashAlgorithm,
    public message: Buffer,
    public signature: Buffer,
    public pubkey: Buffer
  ) {}

  toBuffer(): Buffer {
    const keyLength = Buffer.allocUnsafe(1);
    keyLength.writeUInt8(this.keyLength);
    const hashType = Buffer.allocUnsafe(1);
    hashType.writeUInt8(this.hashType);
    const messageLength = Buffer.allocUnsafe(4);
    messageLength.writeUint32LE(this.message.length);
    const signatureLength = Buffer.allocUnsafe(4);
    signatureLength.writeUint32LE(this.signature.length);
    const pubkeyLength = Buffer.allocUnsafe(4);
    pubkeyLength.writeUint32LE(this.pubkey.length);
    return Buffer.concat([
      keyLength,
      hashType,
      messageLength,
      this.message,
      signatureLength,
      this.signature,
      pubkeyLength,
      this.pubkey,
    ]);
  }
}
