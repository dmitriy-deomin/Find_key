
use base58::ToBase58;
use sha2::{Digest, Sha256};
use sv::util::hash160;
use ripemd::Ripemd160;
use bitcoincash_addr::{Address, Network, Scheme};
use tiny_keccak::Keccak;
use tiny_keccak::Hasher;


pub const LEGACY_BTC: u8 = 0x00;
pub const LEGACY_BTG: u8 = 0x26;
pub const BIP49_BTC: u8 = 0x05;
pub const BIP49_BTG: u8 = 0x17;
pub const LEGACY_DOGE: u8 = 0x1E;
pub const BIP49_DOGE: u8 = 0x16;
pub const LEGACY_LTC: u8 = 0x30;

pub fn get_legacy(public_key: &[u8], coin: u8) -> String {
    let hash160 = hash160(public_key);
    let mut v = Vec::with_capacity(1 + hash160.0.len() + 4);
    v.push(coin);
    v.extend_from_slice(&hash160.0);
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum[0..4]);
    v.to_base58()
}

pub fn get_hasher_from_public(public_key: &Vec<u8>) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&*public_key);
    hasher.finalize(&mut output);
    output
}

pub fn legasy_btc_to_bch(legacy_addr: String) -> String {
    let mut addr = Address::decode(&legacy_addr).unwrap();
    addr.network = Network::Main;
    addr.scheme = Scheme::CashAddr;
    addr.encode().unwrap()[12..].to_string()
}

pub fn get_bip49(public_key: &Vec<u8>, coin: u8) -> String {
    let digest1 = Sha256::digest(&public_key);

    let hash160_1 = Ripemd160::digest(&digest1);

    let mut v = Vec::with_capacity(hash160_1.len() + 2);
    v.push(0x00);
    v.push(0x14);
    v.extend_from_slice(&hash160_1);

    let digest2 = Sha256::digest(&v);
    let hash160_3 = Ripemd160::digest(&digest2);

    let mut v = Vec::with_capacity(hash160_3.len() + 1);
    v.push(coin);
    v.extend_from_slice(&hash160_3);

    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum[0..4]);
    v.to_base58()
}

fn sha256d(data: &[u8]) -> Vec<u8> {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(&first_hash);
    second_hash.to_vec()
}

// ETH
const NIBBLE_MASK: u8 = 0x0F;
const SCORE_FOR_LEADING_ZERO: i32 = 100;

pub fn get_eth_from_prk(output: [u8; 32]) -> String {
    let _score = calc_score(&output);
    let addr = encode(&output[12..]);
    addr.to_string()
}

fn calc_score(address: &[u8]) -> i32 {
    let mut score = 0;
    let mut has_reached_non_zero = false;
    for &byte in &address[12..] {
        score += score_nibble(byte >> 4, &mut has_reached_non_zero);
        score += score_nibble(byte & NIBBLE_MASK, &mut has_reached_non_zero);
    }
    score
}

fn score_nibble(nibble: u8, has_reached_non_zero: &mut bool) -> i32 {
    if nibble == 0 && !*has_reached_non_zero {
        SCORE_FOR_LEADING_ZERO
    } else if nibble != 0 {
        *has_reached_non_zero = true;
        0
    } else {
        0
    }
}

fn encode(data: &[u8]) -> String {
    data.to_base58()
}

// TRX
const ADDRESS_TYPE_PREFIX: u8 = 0x41;

pub fn get_trx_from_prk(output: [u8; 32]) -> String {
    let mut raw = [ADDRESS_TYPE_PREFIX; 21];
    raw[1..].copy_from_slice(&output[12..]);
    let addr = b58encode_check(&raw);
    addr
}

fn b58encode_check<T: AsRef<[u8]>>(raw: T) -> String {
    let mut hasher = Sha256::new();
    let data = raw.as_ref();
    hasher.update(data);
    let digest1 = hasher.finalize();

    let digest2 = {
        let mut hasher = Sha256::new();
        hasher.update(&digest1);
        hasher.finalize()
    };

    let mut result = Vec::with_capacity(data.len() + 4);
    result.extend_from_slice(data);
    result.extend_from_slice(&digest2[..4]);
    result.to_base58()
}



















// use base58::ToBase58;
// use hex::encode;
// use libsecp256k1::SecretKey;
// use sha2::{Digest, Sha256};
// use sv::util::{hash160, sha256d};
// use tiny_keccak::{Hasher, Keccak};
// use ripemd::Ripemd160;
// use bitcoincash_addr::{Address, Network, Scheme};
//
// pub const LEGASY_BTC: u8 = 0x00;
// pub const LEGASY_BTG: u8 = 0x26;
// pub const BIP49_BTC: u8 = 0x05;
// pub const BIP49_BTG: u8 = 0x17;
// pub const LEGASY_DOGE: u8 = 0x1E;
// pub const BIP49_DOGE: u8 = 0x16;
// pub const LEGASY_LTC: u8 = 0x30;
//
//
// //legasy-----------------------------------------------------------------------
// pub fn get_legacy(public_key: &Vec<u8>, coin: u8) -> String {
//     let hash160 = hash160(&public_key.as_ref());
//     let mut v = Vec::with_capacity(1 + hash160.0.len() + 2);
//     v.push(coin);
//     v.extend_from_slice(&hash160.0);
//     let checksum = sha256d(&v).0;
//     v.push(checksum[0]);
//     v.push(checksum[1]);
//     v.push(checksum[2]);
//     v.push(checksum[3]);
//     let b: &[u8] = v.as_ref();
//     b.to_base58()
// }
//
// // pub fn get_legacy(public_key: &[u8; 33], coin: u8) -> String {
// //     let hash160 = hash160(&public_key.as_ref());
// //     let mut v = [0; 25];
// //     v[0] = coin;
// //     v[1..=20].copy_from_slice(&hash160.0);
// //     let checksum = sha256d(&v[0..=20]).0;
// //     v[21..=24].copy_from_slice(&checksum[0..=3]);
// //     v.to_base58()
// // }
//
// //поготовка ключа для get_legacy
// pub fn get_hasher_from_public(secret_key: [u8; 32]) -> [u8; 32] {
//     let secret_key = SecretKey::parse(&secret_key);
//     let p = libsecp256k1::PublicKey::from_secret_key(&secret_key.unwrap());
//     let public = &p.serialize()[1..];
//     let mut output = [0u8; 32];
//     let mut hasher = Keccak::v256();
//     hasher.update(public);
//     hasher.finalize(&mut output);
//     output
// }
// //------------------------------------------------------------------------------------
// // fn hex_to_wif_compressed(raw_hex: Vec<u8>) -> String {
// //     let mut v = [0; 38];
// //     v[0] = 0x80;
// //     v[1..=32].copy_from_slice(&raw_hex.as_ref());
// //     v[33] = 0x01;
// //     let checksum = sha256d(&v[0..=33]).0;
// //     v[34..=37].copy_from_slice(&checksum[0..=3]);
// //     v.to_base58()
// // }
//
// // fn hex_to_wif_compressed(raw_hex: Vec<u8>) -> String {
// //     let mut v = Vec::with_capacity(raw_hex.len() + 2);
// //     v.push(0x80);
// //     v.extend_from_slice(raw_hex.as_ref());
// //     v.push(0x01);
// //
// //     let checksum = sha256d(&v).0;
// //     v.push(checksum[0]);
// //     v.push(checksum[1]);
// //     v.push(checksum[2]);
// //     v.push(checksum[3]);
// //     let b: &[u8] = v.as_ref();
// //     b.to_base58()
// // }
// // fn hex_to_wif_uncompressed(raw_hex: Vec<u8>) -> String {
// //     let mut v = Vec::with_capacity(raw_hex.len() + 2);
// //     v.push(0x80);
// //     v.extend_from_slice(raw_hex.as_ref());
// //
// //     let checksum = sha256d(&v).0;
// //     v.push(checksum[0]);
// //     v.push(checksum[1]);
// //     v.push(checksum[2]);
// //     v.push(checksum[3]);
// //     let b: &[u8] = v.as_ref();
// //     b.to_base58()
// // }
// pub fn legasy_btc_to_bch(legacy_addr: String) -> String {
//
//     let mut addr = Address::decode(legacy_addr.as_str()).unwrap();
//
//     // Change the base58 address to a test network cashaddr
//     addr.network = Network::Main;
//     addr.scheme = Scheme::CashAddr;
//
//     // Encode cashaddr
//     let cashaddr_str = addr.encode().unwrap();
//     cashaddr_str[12..].to_string()
// }
//
// pub fn get_bip49(public_key_c: Vec<u8>,coin:u8) -> String {
//     let mut hasher = Sha256::new();
//     hasher.update(&public_key_c);
//     let digest1 = hasher.finalize();
//
//     let mut ripemd160 = Ripemd160::new();
//     ripemd160.update(&digest1);
//     let hash160_1 = ripemd160.finalize();
//
//     let mut v = Vec::with_capacity( hash160_1.len() + 2);
//     v.push(0x00);
//     v.push(0x14);
//     v.extend_from_slice(hash160_1.as_ref());
//
//     let mut hasher = Sha256::new();
//     hasher.update(v);
//     let digest2 = hasher.finalize();
//
//     let mut ripemd160 = Ripemd160::new();
//     ripemd160.update(&digest2);
//     let hash160_3 = ripemd160.finalize();
//
//     let mut v = Vec::with_capacity( hash160_3.len() + 1);
//     v.push(coin);
//     v.extend_from_slice(&hash160_3);
//
//     let checksum = sha256d(&v).0;
//     v.push(checksum[0]);
//     v.push(checksum[1]);
//     v.push(checksum[2]);
//     v.push(checksum[3]);
//     let b: &[u8] = v.as_ref();
//     b.to_base58()
// }
// //-------------------------------------------------------------------------------------
//
// //ETH----------------------------------------------------------------------------
// const NIBBLE_MASK: u8 = 0x0F;
// const SCORE_FOR_LEADING_ZERO: i32 = 100;
//
// pub fn get_eth_from_prk(output: [u8; 32]) -> String {
//     let _score = calc_score(&output);
//     let addr = encode(&output[(output.len() - 20)..]);
//     return addr.to_string();
// }
//
// #[inline(always)]
// fn calc_score(address: &[u8]) -> i32 {
//     let mut score: i32 = 0;
//     let mut has_reached_non_zero = false;
//     for &byte in &address[(address.len() - 20)..] {
//         score += score_nibble(byte >> 4, &mut has_reached_non_zero);
//         score += score_nibble(byte & NIBBLE_MASK, &mut has_reached_non_zero);
//     }
//     score
// }
//
// #[inline(always)]
// fn score_nibble(nibble: u8, has_reached_non_zero: &mut bool) -> i32 {
//     let mut local_score = 0;
//     if nibble == 0 && !*has_reached_non_zero {
//         local_score += SCORE_FOR_LEADING_ZERO;
//     } else if nibble != 0 {
//         *has_reached_non_zero = true;
//     }
//
//     local_score
// }
// //---------------------------------------------------------------------------------------
//
//
// //trx----------------------------------------------------------------------------------
// const ADDRESS_TYPE_PREFIX: u8 = 0x41;
//
// pub fn get_trx_from_prk(output: [u8; 32]) -> String {
//     let mut raw = [ADDRESS_TYPE_PREFIX; 21];
//     raw[1..21].copy_from_slice(&output[output.len() - 20..]);
//
//     let addr = b58encode_check(raw);
//     addr
// }
//
// /// Base58check encode.
// pub fn b58encode_check<T: AsRef<[u8]>>(raw: T) -> String {
//     let mut hasher = Sha256::new();
//     hasher.update(raw.as_ref());
//     let digest1 = hasher.finalize();
//
//     let mut hasher = Sha256::new();
//     hasher.update(&digest1);
//     let digest = hasher.finalize();
//
//     let mut raw = raw.as_ref().to_owned();
//     raw.extend(&digest[..4]);
//     raw.to_base58()
// }
//
// //-------------------------------------------------------------------------------