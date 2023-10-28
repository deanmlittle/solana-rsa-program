use borsh::BorshDeserialize;
use solana_program::{
    account_info::AccountInfo, declare_id, entrypoint::ProgramResult, instruction::Instruction,
    pubkey::Pubkey, big_mod_exp::big_mod_exp, program_error::ProgramError, msg, hash, keccak, blake3,
};

mod rsa_pubkey;
mod rsa_cursor;
mod rsa_context;

use rsa_context::{RSAContext, RSAHashingAlgorithm};
use rsa_pubkey::RSAPubkey;

declare_id!("rsaGmKjfFv7JW14MXd5AjwBMcknxkAsbtLvYdG4KaEr");

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(rsa);

pub fn rsa(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let ctx = RSAContext::try_from_slice(&instruction_data)?;
    rsa_verify(&ctx)
}

pub fn rsa_verify(ctx: &RSAContext) -> Result<(), ProgramError> {
    let size = (ctx.size as usize).checked_mul(64).ok_or(ProgramError::ArithmeticOverflow)?;
    // Assert signature is of expected length
    if ctx.signature.len().ne(&size) {
        msg!("Invalid signature length, expected: {}", size);
        return Err(ProgramError::InvalidInstructionData);
    }

    let key = RSAPubkey::from_der_bytes(&ctx.pubkey)?;

    // Assert public key is of expected length
    if key.0.len().ne(&size)  {
        return Err(ProgramError::InvalidInstructionData);
    }

    let msg = match ctx.hash {
        RSAHashingAlgorithm::NAIVE => ctx.message.clone(),
        RSAHashingAlgorithm::SHA256 => hash::hash(&ctx.message).to_bytes().to_vec(),
        RSAHashingAlgorithm::SHA3 => keccak::hash(&ctx.message).to_bytes().to_vec(),
        RSAHashingAlgorithm::BLAKE3 => blake3::hash(&ctx.message).to_bytes().to_vec(),
    };

    if msg.len() > size {
        msg!("Message length overflow. Expected <= {}, got {}", size, msg.len());
        return Err(ProgramError::InvalidInstructionData);
    }

    let verification = big_mod_exp(&ctx.signature, &key.1, &key.0);

    if !msg.eq(&verification[verification.len() - msg.len()..]) {
        return Err(ProgramError::MissingRequiredSignature); 
    }

    Ok(())
}

pub fn instruction(ctx: &RSAContext) -> Instruction {
    Instruction {
        program_id: crate::id(),
        accounts: vec![],
        data: ctx.to_bytes()
    }
}

#[cfg(test)]
 mod tests {
    use hex_literal::hex;
    use crate::{rsa_verify, rsa_context::{RSAContext, RSAKeySize, RSAHashingAlgorithm}};

    #[test]
    fn verify_rsa_sha256_512() {
        let ctx = RSAContext::new(
            RSAKeySize::RSA512, 
            RSAHashingAlgorithm::SHA256,
            b"hello", 
            &hex!("05069a2ac8e8166eda881d3262a4f72a4a2c0d92d5d94f1ecbb6ba533020cd9dd5c6ffe3d884e9da0e03b8595531da272e33785bdb0597fa9ce09c876fb758c6"),
&hex!("305c300d06092a864886f70d0101010500034b003048024100ccbe3c1bc37a17e5e2701090cb92add0094b657d148a1c66fac8a4a846d953f3bf84b1b228c8d46a567c69da677288668f7bb21c5bcb095148d0f2b48c6947590203010001")
        );
        rsa_verify(&ctx).unwrap()
    }
    
    #[test]
    fn verify_rsa_sha256_1024() {
        let ctx = RSAContext::new(
            RSAKeySize::RSA1024, 
            RSAHashingAlgorithm::SHA256,

            b"hello", 
            &hex!("848e10e5546a41a7b507fe8bbe1a3679f3e5759f13819df5702f38a43cf9501a6911a2a6207b115a6fc441b209bbddea0b577f6b7d6f9b4be1e48efae2a3866cca6a2bc8d1917c7d58cfc626877f4f8dc8cbdd171fc72d8b0dc7eebffeecf711da76c475ae3477ade41d18fffbb113a60b2472dd91db1e792eaab0f6b358cc64"),
&hex!("30819f300d06092a864886f70d010101050003818d0030818902818100a7b20fae4bd6b224e4d1ca7830a4c7197d3c94609b418cff37226699acff34f4bfdff94f1f1bf7bbcd4ebf1e0fc25fc657d7ae04cb2377e7623805ef462a51a841c4d6943ce117242a1b309c776de1f640b0c23efed4a08388a14f41b119a72684d9720b06ee56a90838517e1871e579250fbc51d63c7b27573267ecea6aeb230203010001")
        );

        rsa_verify(&ctx).unwrap();
    }

    #[test]
    fn verify_rsa_sha256_2048() {
        let ctx = RSAContext::new(
            RSAKeySize::RSA2048, 
            RSAHashingAlgorithm::SHA256,
            b"hello", 
            &hex!("b4b079a588d2f3e5ad2ea0af20b3f6fa78532d43dfcf56c2c7427dfb26a976876f6c928a72da4737e3f001cfdffa10f3e7127b4e64da2c0f003e3179f5545092960ac5e42a09a2d631fcbaee3f743b9c69a584314dde6cc83fa0b603d463bdb6d74b9d350b54cf0a0537c595a4f0d9ac1c98c750c04ec6f41417ee315a546b0b57b0d5afa1baee844f34cec0b63dcbb831eafb086f20ddd72ffdc5acf11fea871b4e52820e8184c4ffd3a2ff0b694bd470fdea537f027d644257d6ab52f5cee3efb8f10794ba88e54c264155baff2de0e3b78d9d8101fdac738d605c1ee617aa9c2367ee65fc744425183a02fc42666f53015d31f471ff6f500c4294d7933a8e"),
&hex!("30820122300d06092a864886f70d01010105000382010f003082010a0282010100c7ea3eb7124f1a42d7e9499a8cab665fab1439f0828d580e596caafd7adb8a4d32a6a5b11fecfbf697b8398b1511a6f038e4d72f0436b69f26aab109e35a5de85ab9e52aa0483698b37864a25a6d02c8679f88adb30a66d6cdd5bb42288f662fd1c440f6ce36b0da29cc6a456bb09ce0686d565f58a9218b421c7bfbef5d824a01f04f351e34188e1ed4572c62af56ca5bdf3e0228ebf060f7bec7943696084f454d9970c75ebad2c74b1dc9fa0d0818c57de8af36ce0c0b8f7e2e7b0bfccf6cfd6f61db84a32d9826e63e46759ec7270ab4c9d4dfbe128ec3dd00d9613e9b638177c50a975ec8478ed765617dbcec8355788b3b127dfc4fcb1486d7967ef4e50203010001")
        );
        rsa_verify(&ctx).unwrap()
    }

    #[test]
    fn verify_rsa_sha256_3072() {
        let ctx = RSAContext::new(
            RSAKeySize::RSA3072,
            RSAHashingAlgorithm::SHA256, 
            b"hello",
            &hex!("4C3E67DDC7A90EC2D63510740F2C7E463FE278FA34DF33B46A95CE97F269EA7D47A1DFF02A5D02A6DA155E31A42C41A5C7E8B55322084D6E28951A6CF9BA19F7811068B2790013C9FD29D1BEB689A5B8BEBBDFEB47B245EF57790C194CAA030822ABE1300A63FB050378CF3FC11B0BA50F63FCA97DEFEABFF926B40E8A245166D54766391907CD4004FDF46C92E790932457CCB707B31F8F622044D70F83A37BD414D2BA46CE904D32F76FEE944B3B225733DDFFCCBAA33E55F6D03F60853886D21A981E6475D74DA99BE36D7268537A8AFDAC579B0BCC79357A95FCA5D5FAE04DA6648030CE525C5D033FC923796DE5FCE32744BECDF59BB31E0813D7EA39D5DB54914DAE0E4A8ADEBB41A16FEB1572FE0277BE4EB01FA5972BD7F61E05ECCB938846836AC2C4F5FDC20868D35E7CD16E44945D78F3ECC43B80934E042EA04B64594B0AA11A76B8619E534BEBCA957F6638D9F3DE562A67F84979960383F281D1AB1AFCA9597A9D43FAC7D812ACA43637F7627F5D2B33CC4267128084C2AC4B"),
&hex!("308201a2300d06092a864886f70d01010105000382018f003082018a028201810098f431d14f23d34bd7e6d115e386eceb0a2107a56456b46368cdbc20869cea30046b091d98bd80bcd3ec9268c83e5dc675252bcceb6479b4566e72fa354cfa4870d7b1366b59ee377e3bcffa5a03c78b9f4f941b2116200af296691fc30892a8e119c342b06a7ce4c232d7e13e3d30628276e6398fa3533b9cb4ed6376866773d14b8ceefc386589d6b5971f14f07e6155c8382046632703087103d998299f46c6a232f86c168363dd847ed90b826ae8b85ece8cb4485a8620687ba1f6cc8a99763cd1a79c2f58b164486f9ebcef38699ae03540824ad4d40db141a5d96046ef249b82422d9170d5c0fc251129680b17950561861101a4b41720fa30ed8473765e9b6e79f1006a204bbae81ed366058beb760117c1abb4d0056d6566396fc0c77fcd8ed26bb8aa2268d4d3d4f8cda25045a4ef6ae39f9a5d194146bf46ab8da71257a7a37262987b2d1c6a1fc2a5e273b95d51977f57792e688f3bd1032de70650e15c09e64060a02544e31a8753a804a56cdadc406a19a63ded93b40f50c4050203010001")
        );
        rsa_verify(&ctx).unwrap()
    }

    #[test]
    fn verify_rsa_sha256_4096() {
        let ctx = RSAContext::new(
            RSAKeySize::RSA4096, 
            RSAHashingAlgorithm::SHA256,
            b"hello", 
            &hex!("207e9320f116b1417ce945935b48aad6afaa8f062b58a2cc24bc63405d1446c12e995d213b97f7e95fe5b4382f726b66d7ad9b0967c6a988b3ed9c63bd758e3bec05986490d4eb916d4743fa8f3b31b2646dc026b8de3e6c5cc4738a3f5496017be372b45bf664c2c586ca80200f7d95569798f084c7873eb4669b30ce6e9615a43ec1ea56869c2a84ff0517708900bab51bacc95f06fbb1dd7950310eec9abbc1249f4e54a395952242ddd8338932ebbf47b7cdecf4d1e88dd9e27f229b60f68a05685f0de2842d47e9835ca262b83240c323e66d2abd2522bf935d429fba28755626da4552b5b778edc2101e98911620f46b9f448472dbdc28bb49243da2cd628bc166a05375c63de171d0a8587419bfeca6144f67c31d1314be14552464abae2411c4ed201b592a6b379563de5966612877e131aab0ecf2acbd87c381e78c55c55f2e099ba353c94a77bbeff0cbedaf0888f6945ca4f80080a20d2c318e82cb715678f5f105921a27b4e46eaad1e48eb80ec781739a9aede51dfa2c5a37372d19b6f2996547fde693eac5c3187cf551fee9dab009c71757061b32751d5d683a1d6a939eb0cc52191edc3d52f3c1a47ee31ab9e0dcef03e2c6e85600228f9457ad462bbf290ebfd7190baeb9d797401cd85ccd8f873c2aed342f9807ebac360cd3308fc9174766a5e762ab305fbbbb7b72d7fec16c9c47b645627be6528f4f"),
&hex!("30820222300d06092a864886f70d01010105000382020f003082020a0282020100db65992ab00fd9e812db6a267e0254030db575a9ecc7025120540e8aca415491d3078a53dea0d6e00425a051dcb7e6c95d9877648089bb2f3b44b91cf618f2800e094f63e02be339c914ed76f7722667a63be2e86a883ae0fad407ae5ab7e3474bdd2c72d517381d5e4d46fa1bd5cf0b134238ef744ebfc10f8a5c79b1f9434083dccbf05e5d5257a333e5e11461ab8b18162a9aea616d5594df54e47c78eb0b9eae38ec7c39adb360505a5ebba98f3fd17f92f0426c2c6637017cd1e6d86709c3f1873aa406187941a70e1eb2222afa7f88b81a6ecfec4834cd2d6960f2bc8eb26ba258fbb3eb4b976c8678145c04a6edff17dd4659f6e6d5726aee3f3b95a67f433aeb0ed07cbb12e29733640f15bdc7b18ab7d5faa799f8a3148d4c97a118e24492448b9af87eb49e12ee2aba996b94a463266839f2286c443d1ec36e853dfbe5850e243b2f671350df6b2a5827fdc46d5d4714b4ae4dfb79f0f0e267822fc9ef89f2f11af565693a539bd08cd599a22fa868aa0a219e134b6dfab0ef9935505d48866d9c32770e5069fd6415500bb50d3c6ab91ac02c7ec2abae986eee50648b2e731d396be2f25f96623bb3a3185614482c4549248aae300fdf5336d2371bebd0ec444cc31c1a0aa68ddc938537dab20abf1d643935e1ab9d50af76c8cbe4aa646b96b75035a01786dcee7bbea6b8e6cfd87411c9be8edd1cd958db00db0203010001")
        );
       rsa_verify(&ctx).unwrap()
    }
}

