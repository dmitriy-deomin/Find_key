mod data;
mod wallets;
mod ice_library;

extern crate bitcoin;
extern crate secp256k1;
extern crate num_cpus;

use std::{io, fs::{OpenOptions}, fs::File, io::Write, time::Instant, time::Duration, io::{BufRead, BufReader}, path::Path};
use std::io::stdout;
use std::str::FromStr;

use secp256k1::{rand, SecretKey};
use bitcoin::{ Address, PublicKey, ScriptBuf};
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
    println!("FIND KEY v 1.0.7");
    println!("================");

    let conf = data::load_db("confFkey.txt");

    let mut num_cores: u8 = first_word(&conf[0].to_string()).to_string().parse::<u8>().unwrap();
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
    let enum_start = first_word(&conf[18].to_string()).to_string();
    let enum_end = first_word(&conf[19].to_string()).to_string();
    let save_start = first_word(&conf[20].to_string()).to_string();
    let save_end = first_word(&conf[21].to_string()).to_string();

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
    -BTG[49]:{}\n\
    ENUMERATION start:{enum_start}\n\
    ENUMERATION end:{enum_end}\n\
    ENUMERATION SAVE start:{save_start}\n\
    ENUMERATION SAVE end:{save_end}\n", num_cpus::get(), custom_digit,
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
    settings.push(enum_start);
    settings.push(enum_end);
    settings.push(save_start);
    settings.push(save_end);

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
        print!("\r{}ADDRESS:{speed}/s || HEX:{hex}/s || TOTAL:{total_address}/{total_hex}  {}", backspace, list[2].to_string());
        stdout.flush().unwrap();
    }
}

fn process(file_content: &Arc<Bloom<String>>, bench: bool, tx: Sender<String>, set: &Arc<Vec<String>>) {
    let mut start = Instant::now();
    let mut speed: u32 = 0;
    let mut speed_save: u32 = 0;

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
    let custom_digit = set[16].to_string();
    let list_custom: Vec<&str> = custom_digit.split(",").collect();
    //проверим что длинна правельная
    if list_custom.len() != 64 { println!("ERROR LEN HEX:{}!=64", list_custom.len()) }
    let mut rng = rand::thread_rng();
    let mut hex_rand = "".to_string();

    let enum_start = set[17].to_string().parse::<usize>().unwrap();
    let enum_end = set[18].to_string().parse::<usize>().unwrap();
    let end_hex = get_hex(enum_end);
    let start_hex = get_hex(enum_start);

    let secret_key_default = SecretKey::from_str("9dd1e8aaf75daba3a770e402659d66f12025b1762502f9df16b741bc6fc4919b").unwrap();

    let save_start = u128::from_str_radix(&*set[19].to_string(), 16).unwrap();
    let save_end = u128::from_str_radix(&*set[20].to_string(), 16).unwrap();

    let config_file = lines_from_file("confFkey.txt").unwrap();

    let ice_library = ice_library::IceLibrary::new();
    ice_library.init_secp256_lib();


    loop {
        hex_rand.clear();
        for i in enum_start..64 - enum_end {
            if list_custom[i] == "*" {
                hex_rand.push_str(&HEX[rng.gen_range(0..16)].to_string());
            } else {
                hex_rand.push_str(&list_custom[i].to_string());
            }
        }

        for end_h in save_end..=end_hex {
            for start_h in save_start..=start_hex {
                let st = if start_hex == 0 { "".to_string() } else { format!("{:0enum_start$X}", start_h) };
                let en = if end_hex == 0 { "".to_string() } else { format!("{:0enum_end$X}", end_h) };
                let hex_rand = format!("{st}{hex_rand}{en}");

                let secret_key = SecretKey::from_str(hex_rand.as_str()).unwrap_or(secret_key_default);

                let ice_pub_unc = ice_library.privatekey_to_publickey(hex_rand.as_str());
                let ice_pub_comp = ice_library.publickey_uncompres_to_compres(ice_pub_unc.as_str());

                let public_key_u = PublicKey::from_str(ice_pub_unc.as_str()).unwrap();
                let public_key_c = PublicKey::from_str(ice_pub_comp.as_str()).unwrap();


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
                        print_and_save(a.to_string(), &secret_key.display_secret().to_string());
                    }

                    if bench {
                        speed = speed + 1;
                        if start.elapsed() >= Duration::from_secs(1) {
                            println!("--------------------------------------------------------");
                            println!("HEX:{}", &secret_key.display_secret().to_string());
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
                            tx.send(format!("{speed},{hex},", ).to_string()).unwrap();
                            start = Instant::now();
                            speed = 0;
                            hex = 0;
                            speed_save = speed_save + 1;
                        }
                        if speed_save >= 10 {
                            //каждые 10 секунд сохраняем
                            let mut cont = "".to_string();
                            for (i, f) in config_file.iter().enumerate() {
                                if i == 20 {
                                    let st20 = if st == "" { "0 -ENUMERATION SAVE start\n".to_string() } else { format!("{:x} -ENUMERATION SAVE start\n", start_h) };
                                    cont.push_str(st20.as_str());
                                } else if i == 21 {
                                    let st21 = if en == "" { "0 -ENUMERATION SAVE end\n".to_string() } else { format!("{:x} -ENUMERATION SAVE end\n", end_h) };
                                    cont.push_str(st21.as_str());
                                } else {
                                    cont.push_str(&*format!("{f}\n"));
                                }
                                // tx.send(format!("0,0,SAVE").to_string()).unwrap();
                                speed_save = 0;
                            }

                            let file_path = "confFkey.txt";
                            let mut file = OpenOptions::new()
                                .write(true)
                                .truncate(true)  // Это гарантирует, что файл будет обрезан до нулевой длины при открытии
                                .open(file_path)
                                .unwrap();
                            // Теперь можем записать что-то в файл
                            file.write_all(cont.as_ref()).unwrap();
                        }
                    }
                }
                addresa.clear();
            }
        }
    }
}

fn get_hex(range: usize) -> u128 {
    let hex = match range {
        1 => 0xF,
        2 => 0xFF,
        3 => 0xFFF,
        4 => 0xFFFF,
        5 => 0xFFFFF,
        6 => 0xFFFFFF,
        7 => 0xFFFFFFF,
        8 => 0xFFFFFFFF,
        9 => 0xFFFFFFFFF,
        10 => 0xFFFFFFFFFF,
        11 => 0xFFFFFFFFFFF,
        12 => 0xFFFFFFFFFFFF,
        13 => 0xFFFFFFFFFFFFF,
        14 => 0xFFFFFFFFFFFFFF,
        15 => 0xFFFFFFFFFFFFFFF,
        16 => 0xFFFFFFFFFFFFFFFF,
        17 => 0xFFFFFFFFFFFFFFFFF,
        18 => 0xFFFFFFFFFFFFFFFFFF,
        19 => 0xFFFFFFFFFFFFFFFFFFF,
        20 => 0xFFFFFFFFFFFFFFFFFFFF,
        21 => 0xFFFFFFFFFFFFFFFFFFFFF,
        22 => 0xFFFFFFFFFFFFFFFFFFFFFF,
        23 => 0xFFFFFFFFFFFFFFFFFFFFFFF,
        24 => 0xFFFFFFFFFFFFFFFFFFFFFFFF,
        25 => 0xFFFFFFFFFFFFFFFFFFFFFFFFF,
        26 => 0xFFFFFFFFFFFFFFFFFFFFFFFFFF,
        27 => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        28 => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        29 => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        30 => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        31 => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        32 => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        _ => { 0x0 }
    };
    hex
}

fn print_and_save(address: String, secret_key: &String) {
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
