mod data;
mod wallets;

extern crate bitcoin;
extern crate secp256k1;
extern crate num_cpus;

use std::{io, fs::{OpenOptions}, fs::File, io::Write, time::Instant, time::Duration, io::{BufRead, BufReader}, path::Path};
use std::io::stdout;
use std::str::FromStr;

use secp256k1::{rand, Secp256k1, SecretKey};
use bitcoin::{PrivateKey, Address, PublicKey, ScriptBuf};
use std::sync::{Arc, mpsc};
use std::sync::mpsc::Sender;
use bitcoin::Network::Bitcoin;
use bloomfilter::Bloom;
use rand::Rng;

use tokio::task;
use rustils::parse::boolean::string_to_bool;

const HEX: [&str; 16] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"];

#[tokio::main]
async fn main() {
    println!("================");
    println!("FIND KEY v 1.0.4");
    println!("================");

    let conf = data::load_db("confFkey.txt");

    let stroka_0_all = &conf[0].to_string();
    let mut num_cores: u8 = first_word(stroka_0_all).to_string().parse::<u8>().unwrap();
    let btc44_u = first_word(&conf[1].to_string()).to_string();
    let btc44_c = first_word(&conf[2].to_string()).to_string();
    let btc49 = first_word(&conf[3].to_string()).to_string();
    let btc84 = first_word(&conf[4].to_string()).to_string();
    let btc84b = first_word(&conf[5].to_string()).to_string();
    let eth44 = first_word(&conf[6].to_string()).to_string();
    let trx = first_word(&conf[7].to_string()).to_string();
    let ltc_u = first_word(&conf[8].to_string()).to_string();
    let ltc_c = first_word(&conf[9].to_string()).to_string();
    let doge_u = first_word(&conf[10].to_string()).to_string();
    let doge_c = first_word(&conf[11].to_string()).to_string();
    let doge49 = first_word(&conf[12].to_string()).to_string();
    let bch = first_word(&conf[13].to_string()).to_string();
    let btg44_u = first_word(&conf[14].to_string()).to_string();
    let btg44_c = first_word(&conf[15].to_string()).to_string();
    let btg49 = first_word(&conf[16].to_string()).to_string();
    let custom_digit = first_word(&conf[17].to_string()).to_string().parse::<String>().unwrap();

    let mut bench = false;
    if num_cores == 0 {
        println!("----------------");
        println!(" LOG MODE 1 CORE");
        println!("----------------");
        bench = true;
        num_cores = 1;
    }
    println!("CORE CPU:{num_cores}/{}\n\
    -CUSTOM_HEX_DIGIT:{}\n\
    -BTC[44u]:{}\n\
    -BTC[44c]:{}\n\
    -BTC[49]:{}\n\
    -BTC[84 p2wpkh]:{}\n\
    -BTC[84 p2wsh]:{}\n\
    -ETH:{}\n\
    -TRX:{}\n\
    -LTC u:{}\n\
    -LTC c:{}\n\
    -DOGECOIN 44u:{}\n\
    -DOGECOIN 44c:{}\n\
    -DOGECOIN 49:{}\n\
    -BCH:{}\n\
    -BTG[44u]:{}\n\
    -BTG[44c]:{}\n\
    -BTG[49]:{}\n", num_cpus::get(), custom_digit,
             string_to_bool(btc44_u.clone()), string_to_bool(btc44_c.clone()), string_to_bool(btc49.clone()),
             string_to_bool(btc84.clone()), string_to_bool(btc84b.clone()), string_to_bool(eth44.clone()), string_to_bool(trx.clone()),
             string_to_bool(ltc_u.clone()), string_to_bool(ltc_c.clone()), string_to_bool(doge_u.clone()),
             string_to_bool(doge_c.clone()), string_to_bool(doge49.clone()), string_to_bool(bch.clone()),
             string_to_bool(btg44_u.clone()), string_to_bool(btg44_c.clone()), string_to_bool(btg49.clone()));

    //если блум есть загрузим его
    let database = data::load_bloom();

    //дополнительные настройки упакуем в список
    let mut settings = vec![];
    settings.push(btc44_u);
    settings.push(btc44_c);
    settings.push(btc49);
    settings.push(btc84);
    settings.push(eth44);
    settings.push(trx);
    settings.push(ltc_u);
    settings.push(ltc_c);
    settings.push(doge_u);
    settings.push(doge_c);
    settings.push(doge49);
    settings.push(bch);
    settings.push(btc84b);
    settings.push(btg44_u);
    settings.push(btg44_c);
    settings.push(btg49);
    settings.push(custom_digit);

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
            process(&database, bench, tx, &set);
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
    let trx = string_to_bool(set[5].to_string());
    let ltc_u = string_to_bool(set[6].to_string());
    let ltc_c = string_to_bool(set[7].to_string());
    let doge_u = string_to_bool(set[8].to_string());
    let doge_c = string_to_bool(set[9].to_string());
    let doge49 = string_to_bool(set[10].to_string());
    let bch = string_to_bool(set[11].to_string());
    let btc84b = string_to_bool(set[12].to_string());
    let btg44_u = string_to_bool(set[13].to_string());
    let btg44_c = string_to_bool(set[14].to_string());
    let btg49 = string_to_bool(set[15].to_string());
    let custom_digit =set[16].to_string();
    let list_custom: Vec<&str> = custom_digit.split(",").collect();
    //проверим что длинна правельная
    if list_custom.len()!=64{println!("ERROR LEN HEX:{}!=64",list_custom.len())}
    let mut rng = rand::thread_rng();

    loop {
        let mut hex_rand = "".to_string();
        for i in 0..64{
            if list_custom[i as usize] == "*" {
                hex_rand.push_str(&HEX[rng.gen_range(0..16)].to_string());
            } else {
                hex_rand.push_str(&list_custom[i as usize].to_string());
            }
        }

        // let secret_key = SecretKey::new(&mut rand::thread_rng());
        let secret_key = SecretKey::from_str(hex_rand.as_str()).unwrap();

        let private_key_u = PrivateKey::new_uncompressed(secret_key, Bitcoin);
        let private_key_c = PrivateKey::new(secret_key, Bitcoin);

        let public_key_u = PublicKey::from_private_key(&Secp256k1::new(), &private_key_u);
        let public_key_c = PublicKey::from_private_key(&Secp256k1::new(), &private_key_c);

        // wallets::get_bip84_p2wsh(&public_key_c.to_bytes());

        if btc44_u { addresa.push(wallets::get_legacy(&public_key_u.to_bytes(), wallets::LEGASY_BTC)) };
        if btc44_c { addresa.push(wallets::get_legacy(&public_key_c.to_bytes(), wallets::LEGASY_BTC)) };
        if btc49 { addresa.push(wallets::get_bip49(public_key_c.to_bytes(), wallets::BIP49_BTC)); };
        if btc84 { addresa.push(Address::p2wpkh(&public_key_c, Bitcoin).unwrap().to_string()) };
        if btc84b {
            let script = ScriptBuf::from_bytes(public_key_c.to_bytes());
            addresa.push(Address::p2wsh(&script, Bitcoin).to_string())
        };

        let hash = wallets::get_hasher_from_public(secret_key.secret_bytes());
        if eth44 { addresa.push(wallets::get_eth_from_prk(hash)) };

        if trx { addresa.push(wallets::get_trx_from_prk(hash)) };

        if ltc_u { addresa.push(wallets::get_legacy(&public_key_u.to_bytes(), wallets::LEGASY_LTC)) };
        if ltc_c { addresa.push(wallets::get_legacy(&public_key_c.to_bytes(), wallets::LEGASY_LTC)) };

        if doge_u { addresa.push(wallets::get_legacy(&public_key_u.to_bytes(), wallets::LEGASY_DOGE)) };
        if doge_c { addresa.push(wallets::get_legacy(&public_key_c.to_bytes(), wallets::LEGASY_DOGE)) };
        if doge49 { addresa.push(wallets::get_bip49(public_key_c.to_bytes(), wallets::BIP49_DOGE)) };

        if bch { addresa.push(wallets::legasy_btc_to_bch(wallets::get_legacy(&public_key_c.to_bytes(), wallets::LEGASY_BTC))) };

        if btg44_u { addresa.push(wallets::get_legacy(&public_key_u.to_bytes(), wallets::LEGASY_BTG)) };
        if btg44_c { addresa.push(wallets::get_legacy(&public_key_c.to_bytes(), wallets::LEGASY_BTG)) };
        if btg49 { addresa.push(wallets::get_bip49(public_key_c.to_bytes(), wallets::BIP49_BTG)); };

        hex = hex + 1;
        for a in addresa.iter() {
            if file_content.check(&a) {
                print_and_save(a.to_string(), secret_key.display_secret().to_string());
            }

            if bench {
                speed = speed + 1;
                if start.elapsed() >= Duration::from_secs(1) {
                    println!("--------------------------------------------------------");
                    println!("HEX:{}", &secret_key.display_secret());
                    for ad in addresa.iter() {
                        println!("ADDRESS:{ad}");
                    }
                    println!("--------------------------------------------------------");
                    start = Instant::now();
                    speed = 0;
                }
            } else {
                speed = speed + 1;
                if start.elapsed() >= Duration::from_secs(1) {
                    tx.send(format!("{speed},{hex}", ).to_string()).unwrap();
                    start = Instant::now();
                    speed = 0;
                    hex = 0;
                }
            }
        }
        addresa.clear();
    }
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
    add_v_file("FOUND.txt", s.to_string());

    println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!SAVE TO FOUND.txt!!!!!!!!!!!!!!!!!!!!!!!!");
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


// let pubkey_hex = "04005937fd439b3c19014d5f328df8c7ed514eaaf41c1980b8aeab461dffb23fbf3317e42395db24a52ce9fc947d9c22f54dc3217c8b11dfc7a09c59e0dca591d3";
// let pubkeyhash = hash160(&hex::decode(pubkey_hex).unwrap());
// let legacyaddr = legacyaddr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
// assert!(legacyaddr == "1NM2HFXin4cEQRBLjkNZAS98qLX9JKzjKn");

// pub fn get_bch_to_public(pubkey: String) -> String {
//     let pubkeyhash = bch::hash160(&hex::decode(pubkey).unwrap());
//     let legacyaddr = bch::legacyaddr_encode(&pubkeyhash, bch::AddressType::P2PKH, bch::Network::Mainnet);
//     legacyaddr
// }
