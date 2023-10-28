import {
  Connection,
  Transaction,
  TransactionInstruction,
  Keypair,
  Commitment,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
// import { Rsa } from "../target/types/rsa2048";
import { generateKeyPairSync, createSign, createVerify } from "crypto";
import {
  RSAHashAlgorithm,
  RSAKeyLength,
  RSASignatureInstruction,
  RSA_PROGRAM_ID,
} from "../src";

describe("RSA tests", () => {
  const commitment: Commitment = "confirmed";
  const connection = new Connection("http://localhost:8899", commitment);

  const confirmTx = async (signature: string) => {
    const latestBlockhash = await connection.getLatestBlockhash();
    await connection.confirmTransaction(
      {
        signature,
        ...latestBlockhash,
      },
      commitment
    );
    return signature;
  };

  const keypair = new Keypair();
  it("Airdrops coins to a new account", async () => {
    const tx = await connection
      .requestAirdrop(keypair.publicKey, 1e9)
      .then(confirmTx);
  });
  it("Valid 1028 bit sha256 signature!", async () => {
    const { privateKey: RSAPrivateKey, publicKey: RSAPublicKey } =
      generateKeyPairSync("rsa", {
        modulusLength: 1024,
        publicKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
      });

    const pubkeyBytes = Buffer.from(
      RSAPublicKey.replace("-----BEGIN RSA PUBLIC KEY-----", "")
        .replace("-----END RSA PUBLIC KEY-----", "")
        .replace("\n", ""),
      "base64"
    );

    const message = Buffer.from("Some message to sign");
    const sign = createSign("SHA256");
    sign.write(message);
    sign.end();

    const rsaSignature = sign.sign(RSAPrivateKey);

    const instruction = new RSASignatureInstruction(
      RSAKeyLength.RSA1024,
      RSAHashAlgorithm.SHA256,
      message,
      rsaSignature,
      pubkeyBytes
    );

    console.log(instruction.toBuffer());

    const ix = new TransactionInstruction({
      keys: [],
      programId: RSA_PROGRAM_ID,
      data: Buffer.from(instruction.toBuffer()),
    });

    const tx = new Transaction().add(ix);
    const signature = await sendAndConfirmTransaction(connection, tx, [
      keypair,
    ]).then(confirmTx);
    console.log("Your transaction signature", signature);
  });
  it("Valid 2048 bit sha256 signature!", async () => {
    const { privateKey: RSAPrivateKey, publicKey: RSAPublicKey } =
      generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
      });

    const pubkeyBytes = Buffer.from(
      RSAPublicKey.replace("-----BEGIN RSA PUBLIC KEY-----", "")
        .replace("-----END RSA PUBLIC KEY-----", "")
        .replace("\n", ""),
      "base64"
    );

    const message = Buffer.from("Some message to sign");
    const sign = createSign("SHA256");
    sign.write(message);
    sign.end();

    const rsaSignature = sign.sign(RSAPrivateKey);

    const instruction = new RSASignatureInstruction(
      RSAKeyLength.RSA2048,
      RSAHashAlgorithm.SHA256,
      message,
      rsaSignature,
      pubkeyBytes
    );

    console.log(instruction.toBuffer());

    const ix = new TransactionInstruction({
      keys: [],
      programId: RSA_PROGRAM_ID,
      data: Buffer.from(instruction.toBuffer()),
    });

    const tx = new Transaction().add(ix);
    const signature = await sendAndConfirmTransaction(connection, tx, [
      keypair,
    ]).then(confirmTx);
    console.log("Your transaction signature", signature);
  });
  it("Valid 3072 bit sha256 signature!", async () => {
    const { privateKey: RSAPrivateKey, publicKey: RSAPublicKey } =
      generateKeyPairSync("rsa", {
        modulusLength: 3072,
        publicKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
      });

    const pubkeyBytes = Buffer.from(
      RSAPublicKey.replace("-----BEGIN RSA PUBLIC KEY-----", "")
        .replace("-----END RSA PUBLIC KEY-----", "")
        .replace("\n", ""),
      "base64"
    );

    const message = Buffer.from("Some message to sign");
    const sign = createSign("SHA256");
    sign.write(message);
    sign.end();

    const rsaSignature = sign.sign(RSAPrivateKey);

    const instruction = new RSASignatureInstruction(
      RSAKeyLength.RSA3072,
      RSAHashAlgorithm.SHA256,
      message,
      rsaSignature,
      pubkeyBytes
    );

    console.log(instruction.toBuffer());

    const ix = new TransactionInstruction({
      keys: [],
      programId: RSA_PROGRAM_ID,
      data: Buffer.from(instruction.toBuffer()),
    });

    const tx = new Transaction().add(ix);
    const signature = await sendAndConfirmTransaction(connection, tx, [
      keypair,
    ]).then(confirmTx);
    console.log("Your transaction signature", signature);
  });

  it("Valid 4096 bit sha256 signature!", async () => {
    const { privateKey: RSAPrivateKey, publicKey: RSAPublicKey } =
      generateKeyPairSync("rsa", {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
      });

    const pubkeyBytes = Buffer.from(
      RSAPublicKey.replace("-----BEGIN RSA PUBLIC KEY-----", "")
        .replace("-----END RSA PUBLIC KEY-----", "")
        .replace("\n", ""),
      "base64"
    );

    const message = Buffer.from("lol");
    const sign = createSign("SHA256");
    sign.write(message);
    sign.end();

    const rsaSignature = sign.sign(RSAPrivateKey);

    const instruction = new RSASignatureInstruction(
      RSAKeyLength.RSA4096,
      RSAHashAlgorithm.SHA256,
      message,
      rsaSignature,
      pubkeyBytes
    );

    console.log(instruction.toBuffer());

    const ix = new TransactionInstruction({
      keys: [],
      programId: RSA_PROGRAM_ID,
      data: Buffer.from(instruction.toBuffer()),
    });

    const tx = new Transaction().add(ix);
    const signature = await sendAndConfirmTransaction(connection, tx, [
      keypair,
    ]).then(confirmTx);
    console.log("Your transaction signature", signature);
  }).timeout(10000);
});
