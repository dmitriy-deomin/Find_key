mod data;

extern crate bitcoin;
extern crate secp256k1;
extern crate num_cpus;

use std::{io, fs::{OpenOptions}, fs::File, io::Write, time::Instant, time::Duration, io::{BufRead, BufReader}, path::Path};
use std::io::stdout;

use secp256k1::{rand, Secp256k1, SecretKey};
use libsecp256k1;
use bitcoin::{PrivateKey, Address, PublicKey};
use std::sync::{Arc, mpsc};
use std::sync::mpsc::Sender;
use bitcoin::Network::Bitcoin;
use bloomfilter::Bloom;
use tiny_keccak::{Hasher, Keccak};
use tokio::task;
use hex::encode;
use rustils::parse::boolean::string_to_bool;

#[tokio::main]
async fn main() {
    println!("================");
    println!("FIND KEY v 0.8.0");
    println!("================");

    let conf = data::load_db("confFkey.txt");

    let stroka_0_all = &conf[0].to_string();
    let mut num_cores: u8 = first_word(stroka_0_all).to_string().parse::<u8>().unwrap();
    let btc44_u = first_word(&conf[1].to_string()).to_string();
    let btc44_c = first_word(&conf[2].to_string()).to_string();
    let btc49 = first_word(&conf[3].to_string()).to_string();
    let btc84 = first_word(&conf[4].to_string()).to_string();
    let eth44 = first_word(&conf[5].to_string()).to_string();

    let mut bench = false;
    if num_cores == 0 {
        println!("----------------");
        println!(" LOG MODE 1 CORE");
        println!("----------------");
        bench = true;
        num_cores = 1;
    }
    println!("CORE CPU:{num_cores}/{}\n\
     -[44u]BTC:{}\n\
     -[44c]BTC:{}\n\
    -[49]BTC:{}\n\
    -[84]BTC:{}\n\
    -[44]ETH:{}\n", num_cpus::get(),
             string_to_bool(btc44_u.clone()),string_to_bool(btc44_c.clone()), string_to_bool(btc49.clone()),
             string_to_bool(btc84.clone()), string_to_bool(eth44.clone()));

    //если блум есть загрузим его
    let database = data::load_bloom();

    //дополнительные настройки упакуем в список
    let mut settings = vec![];
    settings.push(btc44_u);
    settings.push(btc44_c);
    settings.push(btc49);
    settings.push(btc84);
    settings.push(eth44);

    println!("----------------");

    //получать сообщения от потоков
    let (tx, rx) = mpsc::channel();
    let d = Arc::new(database);
    let s = Arc::new(settings);

    for _ in 0..num_cores {
        let database = d.clone();
        let tx = tx.clone();
        let set = s.clone();
        task::spawn_blocking(move || {
            process(&database, bench,tx,&set);
        });
    }

    //отображает инфу в однy строку(обновляемую)
    let backspace: char = 8u8 as char;
    let mut total_address: u64 = 0;
    let mut total_hex: u64 = 0;
    let mut stdout = stdout();
    for received in rx {
        let list: Vec<&str> = received.split(",").collect();
        let mut speed = list[0].to_string().parse::<u64>().unwrap();
        let hex = list[1].to_string().parse::<u64>().unwrap() * num_cores as u64;
        total_address = total_address + speed;
        total_hex = total_hex + hex;
        speed = speed * num_cores as u64;
        print!("\r{}ADDRESS:{speed}/s || HEX:{hex}/s || TOTAL:{total_address}/{total_hex}  ", backspace);
        stdout.flush().unwrap();
    }
}

fn process(file_content: &Arc<Bloom<String>>, bench: bool, tx: Sender<String>, set: &Arc<Vec<String>>) {
    let mut start = Instant::now();
    let mut speed: u32 = 0;

    let mut addresa = vec![];
    let mut hex = 0;

    let btc44_u = string_to_bool(set[0].to_string());
    let btc44_c = string_to_bool(set[1].to_string());
    let btc49 = string_to_bool(set[2].to_string());
    let btc84 = string_to_bool(set[3].to_string());
    let eth44 = string_to_bool(set[4].to_string());

    loop {
        let secret_key = SecretKey::new(&mut rand::thread_rng());

        let private_key_u = PrivateKey::new_uncompressed(secret_key, Bitcoin);
        let public_key_u = PublicKey::from_private_key(&Secp256k1::new(), &private_key_u);

        let private_key_c = PrivateKey::new(secret_key, Bitcoin);
        let public_key_c = PublicKey::from_private_key(&Secp256k1::new(), &private_key_c);

        if btc44_u{addresa.push(Address::p2pkh(&public_key_u, Bitcoin).to_string())};
        if btc44_c{addresa.push(Address::p2pkh(&public_key_c, Bitcoin).to_string())};
        if btc49{addresa.push(Address::p2shwpkh(&public_key_c, Bitcoin).unwrap().to_string())};
        if btc84{addresa.push(Address::p2wpkh(&public_key_c, Bitcoin).unwrap().to_string())};
        if eth44{addresa.push(address_from_seed_eth(secret_key.secret_bytes()))};

        hex = hex+1;
        for a in addresa.iter() {
            if file_content.check(&a){
                print_and_save(a.to_string(),secret_key.display_secret().to_string());
            }

            if bench {
                speed = speed + 1;
                if start.elapsed() >= Duration::from_secs(1) {
                    println!("--------------------------------------------------------");
                    println!("HEX:{}", &secret_key.display_secret());
                    println!("ADDRESS:{}",addresa[0]);
                    println!("ADDRESS:{}",addresa[1]);
                    println!("ADDRESS:{}",addresa[2]);
                    println!("ADDRESS:{}",addresa[3]);
                    println!("ADDRESS:{}",addresa[4]);
                    println!("--------------------------------------------------------");
                    start = Instant::now();
                    speed = 0;
                }
            } else {
                speed = speed + 1;
                if start.elapsed() >= Duration::from_secs(1) {
                    tx.send(format!("{speed},{hex}",).to_string()).unwrap();
                    start = Instant::now();
                    speed = 0;
                    hex=0;
                }
            }
        }
        addresa.clear();
    }
}
fn address_from_seed_eth(hex: [u8; 32]) -> String {
    let secret_key = libsecp256k1::SecretKey::parse(&hex);
    let public = libsecp256k1::PublicKey::from_secret_key(&secret_key.unwrap());
    let public = &public.serialize()[1..65];

    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(public);
    hasher.finalize(&mut output);

    let _score = calc_score(&output);
    let addr = encode(&output[(output.len() - 20)..]);

    return addr.to_string();
}


const NIBBLE_MASK: u8 = 0x0F;
const SCORE_FOR_LEADING_ZERO: i32 = 100;

#[inline(always)]
fn calc_score(address: &[u8]) -> i32 {
    let mut score: i32 = 0;
    let mut has_reached_non_zero = false;
    for &byte in &address[(address.len() - 20)..] {
        score += score_nibble(byte >> 4, &mut has_reached_non_zero);
        score += score_nibble(byte & NIBBLE_MASK, &mut has_reached_non_zero);
    }
    score
}

#[inline(always)]
fn score_nibble(nibble: u8, has_reached_non_zero: &mut bool) -> i32 {
    let mut local_score = 0;

    if nibble == 0 && !*has_reached_non_zero {
        local_score += SCORE_FOR_LEADING_ZERO;
    } else if nibble != 0 {
        *has_reached_non_zero = true;
    }

    local_score
}
fn print_and_save(address: String, secret_key: String) {
    println!("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!!!!!!FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("ADDRESS:{}", &address);
    println!("HEX:{}", &secret_key);

    let s = format!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
    ADDRESS:{address}\n\
    HEX:{secret_key}\n\
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    add_v_file("BOBLO.txt", s.to_string());

    println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!SAVE TO BOBLO.txt!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

fn lines_from_file(filename: impl AsRef<Path>) -> io::Result<Vec<String>> {
    BufReader::new(File::open(filename)?).lines().collect()
}

fn first_word(s: &String) -> &str {
    let bytes = s.as_bytes();
    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[0..i];
        }
    }
    &s[..]
}

fn add_v_file(name: &str, data: String) {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(name)
        .expect("cannot open file")
        .write(data.as_bytes())
        .expect("write failed");
}
