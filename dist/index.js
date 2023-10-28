"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RSASignatureInstruction = exports.RSAHashAlgorithm = exports.RSAKeyLength = exports.RSA_PROGRAM_ID = void 0;
const web3_js_1 = require("@solana/web3.js");
exports.RSA_PROGRAM_ID = new web3_js_1.PublicKey("rsaGmKjfFv7JW14MXd5AjwBMcknxkAsbtLvYdG4KaEr");
var RSAKeyLength;
(function (RSAKeyLength) {
    RSAKeyLength[RSAKeyLength["RSA512"] = 1] = "RSA512";
    RSAKeyLength[RSAKeyLength["RSA1024"] = 2] = "RSA1024";
    RSAKeyLength[RSAKeyLength["RSA2048"] = 4] = "RSA2048";
    RSAKeyLength[RSAKeyLength["RSA3072"] = 6] = "RSA3072";
    RSAKeyLength[RSAKeyLength["RSA4096"] = 8] = "RSA4096";
})(RSAKeyLength = exports.RSAKeyLength || (exports.RSAKeyLength = {}));
var RSAHashAlgorithm;
(function (RSAHashAlgorithm) {
    RSAHashAlgorithm[RSAHashAlgorithm["NAIVE"] = 0] = "NAIVE";
    RSAHashAlgorithm[RSAHashAlgorithm["SHA256"] = 1] = "SHA256";
    RSAHashAlgorithm[RSAHashAlgorithm["SHA3"] = 2] = "SHA3";
    RSAHashAlgorithm[RSAHashAlgorithm["BLAKE3"] = 4] = "BLAKE3";
})(RSAHashAlgorithm = exports.RSAHashAlgorithm || (exports.RSAHashAlgorithm = {}));
class RSASignatureInstruction {
    constructor(keyLength, hashType, message, signature, pubkey) {
        this.keyLength = keyLength;
        this.hashType = hashType;
        this.message = message;
        this.signature = signature;
        this.pubkey = pubkey;
    }
    toBuffer() {
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
exports.RSASignatureInstruction = RSASignatureInstruction;
