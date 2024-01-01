use base58::ToBase58;
use sha2::{Digest, Sha256};
use sv::util::{hash160};
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
    let mut v = Vec::with_capacity(1 + hash160.0.len() + 2);
    v.push(coin);
    v.extend_from_slice(&hash160.0);
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum[0..4]);
    let b: &[u8] = v.as_ref();
    b.to_base58()
}

//ETH
pub fn get_eth_address_from_public_key(public_key_u: &String) -> String {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    let k = hex::decode(&public_key_u.strip_prefix("04").unwrap_or(&public_key_u)).unwrap();
    hasher.update(&k);
    hasher.finalize(&mut output);
    hex::encode(&output[12..])
}


pub fn legasy_btc_to_bch(legacy_addr: String) -> String {
    let mut addr = Address::decode(&legacy_addr).unwrap();
    addr.network = Network::Main;
    addr.scheme = Scheme::CashAddr;
    addr.encode().unwrap()[12..].to_string()
}

pub fn get_bip49(public_key: &[u8], coin: u8) -> String {
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

// TRX
pub fn get_trx_from_eth(eth: String) -> String {
    let mut v = Vec::with_capacity(50);
    v.push(0x41);
    v.extend_from_slice(hex::decode(eth).unwrap().as_slice());
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum[0..4]);
    let b: &[u8] = v.as_ref();
    b.to_base58()
}