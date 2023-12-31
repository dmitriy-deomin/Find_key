mod data;
mod wallets;
mod ice_library;

extern crate num_cpus;

use std::{io, fs::{OpenOptions}, fs::File, io::Write, time::Instant, time::Duration, io::{BufRead, BufReader}, path::Path};
use std::io::stdout;
use std::str::FromStr;
use std::sync::{Arc, mpsc};
use std::sync::mpsc::Sender;
use bitcoin::{Address, PublicKey};
use bitcoin::Network::Bitcoin;
use bloomfilter::Bloom;
use rand::Rng;

use tokio::task;
use rustils::parse::boolean::string_to_bool;

const HEX: [&str; 16] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"];

#[tokio::main]
async fn main() {
    println!("================");
    println!("FIND KEY v 2.0.0");
    println!("================");

    let conf = data::load_db("confFkey.txt");

    let mut num_cores: u8 = first_word(&conf[0].to_string()).to_string().parse::<u8>().unwrap();
    let btc44_u = first_word(&conf[1].to_string()).to_string();
    let btc44_c = first_word(&conf[2].to_string()).to_string();
    let btc49 = first_word(&conf[3].to_string()).to_string();
    let btc84 = first_word(&conf[4].to_string()).to_string();
    let eth44 = first_word(&conf[5].to_string()).to_string();
    let trx = first_word(&conf[6].to_string()).to_string();
    let ltc_u = first_word(&conf[7].to_string()).to_string();
    let ltc_c = first_word(&conf[8].to_string()).to_string();
    let doge_u = first_word(&conf[9].to_string()).to_string();
    let doge_c = first_word(&conf[10].to_string()).to_string();
    let doge49 = first_word(&conf[11].to_string()).to_string();
    let bch = first_word(&conf[12].to_string()).to_string();
    let btg44_u = first_word(&conf[13].to_string()).to_string();
    let btg44_c = first_word(&conf[14].to_string()).to_string();
    let btg49 = first_word(&conf[15].to_string()).to_string();
    let custom_digit = first_word(&conf[16].to_string()).to_string().parse::<String>().unwrap();
    let enum_start = first_word(&conf[17].to_string()).to_string();
    let enum_end = first_word(&conf[18].to_string()).to_string();
    let step = first_word(&conf[19].to_string()).to_string();

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
    -BTC,BCH[44u]:{}\n\
    -BTC,BCH[44c]:{}\n\
    -BTC[49]:{}\n\
    -BTC[84 p2wpkh]:{}\n\
    -ETH,BNB:{}\n\
    -TRX:{}\n\
    -LTC u:{}\n\
    -LTC c:{}\n\
    -DOGECOIN 44u:{}\n\
    -DOGECOIN 44c:{}\n\
    -DOGECOIN 49:{}\n\
    -BCH[49]:{}\n\
    -BTG[44u]:{}\n\
    -BTG[44c]:{}\n\
    -BTG[49]:{}\n\
    ENUMERATION start:{enum_start}\n\
    ENUMERATION end:{enum_end}\n\
    STEP:{step}\n\
    ", num_cpus::get(), custom_digit,
             string_to_bool(btc44_u.clone()), string_to_bool(btc44_c.clone()), string_to_bool(btc49.clone()),
             string_to_bool(btc84.clone()),string_to_bool(eth44.clone()), string_to_bool(trx.clone()),
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
    settings.push(btg44_u);
    settings.push(btg44_c);
    settings.push(btg49);
    settings.push(custom_digit);
    settings.push(enum_start);
    settings.push(enum_end);
    settings.push(step);

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
    let mut stdout = stdout();
    for received in rx {
        let list: Vec<&str> = received.split(",").collect();
        let mut speed = list[0].to_string().parse::<u64>().unwrap();
        let hex = list[1].to_string().parse::<u64>().unwrap() * num_cores as u64;
        speed = speed * num_cores as u64;
        print!("\r{}[ADDRESS:{speed}/s][HEX:{hex}/s][HEX:{}]", backspace, list[2].to_string());
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
    let btg44_u = string_to_bool(set[12].to_string());
    let btg44_c = string_to_bool(set[13].to_string());
    let btg49 = string_to_bool(set[14].to_string());
    let custom_digit = set[15].to_string();
    let list_custom: Vec<&str> = custom_digit.split(",").collect();
    //проверим что длинна правельная
    if list_custom.len() != 64 { println!("ERROR LEN HEX:{}!=64", list_custom.len()) }
    let mut rng = rand::thread_rng();
    let mut hex_rand = "".to_string();

    let enum_start = set[16].to_string().parse::<usize>().unwrap();
    let enum_end = set[17].to_string().parse::<usize>().unwrap();
    let end_hex = get_hex(enum_end);
    let start_hex = get_hex(enum_start);

    let step = u128::from_str_radix(&*set[18].to_string(), 16).unwrap();

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

        for end_h in (0..=end_hex).step_by(step as usize) {
            for start_h in (0..=start_hex).step_by(step as usize) {
                let st = if start_hex == 0 { "".to_string() } else { format!("{:0enum_start$X}", start_h) };
                let en = if end_hex == 0 { "".to_string() } else { format!("{:0enum_end$X}", end_h) };
                let hex_rand = format!("{st}{hex_rand}{en}");

                let ice_pub_key_unc = ice_library.privatekey_to_publickey(hex_rand.as_str());
                let ice_pub_key_com = ice_library.publickey_uncompres_to_compres(ice_pub_key_unc.as_str());
                let pub_key_unc = ice_pub_key_unc.clone().into_bytes();
                let pub_key_com = ice_pub_key_com.clone().into_bytes();

                if btc44_u { addresa.push(wallets::get_legacy(&pub_key_unc, wallets::LEGACY_BTC)) };
                if btc44_c { addresa.push(wallets::get_legacy(&pub_key_com, wallets::LEGACY_BTC)) };
                if btc49 { addresa.push(wallets::get_bip49(&pub_key_com, wallets::BIP49_BTC)); };
                if btc84 {
                    let public_key_c = PublicKey::from_str(ice_pub_key_com.as_str()).unwrap();
                    addresa.push(Address::p2wpkh(&public_key_c, Bitcoin).unwrap().to_string()) };

                let hash = wallets::get_hasher_from_public(&pub_key_com);
                if eth44 { addresa.push(wallets::get_eth_from_prk(hash)) };

                if trx { addresa.push(wallets::get_trx_from_prk(hash)) };

                if ltc_u { addresa.push(wallets::get_legacy(&pub_key_unc, wallets::LEGACY_LTC)) };
                if ltc_c { addresa.push(wallets::get_legacy(&pub_key_com, wallets::LEGACY_LTC)) };

                if doge_u { addresa.push(wallets::get_legacy(&pub_key_unc, wallets::LEGACY_DOGE)) };
                if doge_c { addresa.push(wallets::get_legacy(&pub_key_com, wallets::LEGACY_DOGE)) };
                if doge49 { addresa.push(wallets::get_bip49(&pub_key_com, wallets::BIP49_DOGE)) };

                if bch { addresa.push(wallets::legasy_btc_to_bch(wallets::get_legacy(&pub_key_com, wallets::LEGACY_BTC))) };

                if btg44_u { addresa.push(wallets::get_legacy(&pub_key_unc, wallets::LEGACY_BTG)) };
                if btg44_c { addresa.push(wallets::get_legacy(&pub_key_com, wallets::LEGACY_BTG)) };
                if btg49 { addresa.push(wallets::get_bip49(&pub_key_com, wallets::BIP49_BTG)); };


                hex = hex + 1;
                for (i,a) in addresa.iter().enumerate() {
                    if file_content.check(&a) {
                        let coin_and_adress = format!("{} {}",get_coin_index(i),a);
                        print_and_save(coin_and_adress, &hex_rand);
                    }

                    if bench {
                        speed = speed + 1;
                        if start.elapsed() >= Duration::from_secs(1) {
                            println!("--------------------------------------------------------");
                            println!("HEX:{}", &hex_rand);
                            for (i,ad) in addresa.iter().enumerate() {
                                let coin =get_coin_index(i);
                                println!("ADDRESS:{coin} {ad}");
                            }
                            println!("--------------------------------------------------------");
                            start = Instant::now();
                            speed = 0;
                        }
                    } else {
                        speed = speed + 1;
                        if start.elapsed() >= Duration::from_secs(1) {
                            tx.send(format!("{speed},{hex},{hex_rand}", ).to_string()).unwrap();
                            start = Instant::now();
                            speed = 0;
                            hex = 0;
                        }

                    }
                }
                addresa.clear();
            }
        }
    }
}

fn get_coin_index(index:usize)->String{
   let coin =  match index {
       0=>"BTC,BCH bip44 u".to_string(),
       1=>"BTC,BCH bip44 c".to_string(),
       2=>"BTC bip49".to_string(),
       3=>"BTC bip84".to_string(),
       4=>"ETH".to_string(),
       5=>"TRX".to_string(),
       6=>"LTC u".to_string(),
       7=>"LTC c".to_string(),
       8=>"DOGE u".to_string(),
       9=>"DOGE c".to_string(),
       10=>"DOGE bip49".to_string(),
       11=>"BCH bip49".to_string(),
       12=>"BTG bip44 u".to_string(),
       13=>"BTG bip44 c".to_string(),
       14=>"BTG bip49".to_string(),
       _=>"NEIZVESTNO".to_string()
   };
   coin
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
