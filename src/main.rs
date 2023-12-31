mod data;
mod wallets;
mod ice_library;
mod get_online;
mod color;

extern crate num_cpus;

use std::{io, fs::{OpenOptions}, fs::File, io::Write, time::Instant, time::Duration, io::{BufRead, BufReader}, path::Path};
use std::io::stdout;
use std::sync::{Arc, mpsc};
use std::sync::mpsc::Sender;
use bloomfilter::Bloom;
use rand::Rng;

use tokio::task;
use rustils::parse::boolean::string_to_bool;
use crate::color::{blue, color_bool, cyan, green, magenta, red};
use crate::get_online::{get_balance, get_bch_balance, get_bnb_balance, get_btg_balance, get_trx_balance};

const HEX: [&str; 16] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"];

#[tokio::main]
async fn main() {
    let version: &str = env!("CARGO_PKG_VERSION");
    println!("{}", blue("================"));
    println!("{}{}", blue("FIND KEY v:"),magenta(version));
    println!("{}", blue("================"));

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
        println!("{}", red("----------------"));
        println!("{}", red(" LOG MODE 1 CORE"));
        println!("{}", red("----------------"));
        bench = true;
        num_cores = 1;
    }
    println!("{}/{}{cpu}\n\
    {custom}\n{}\n\
    {}{btc44}\n\
    {}{btc44c}\n\
    {}{btc49}\n\
    {}{btc84}\n\
    {}{eth}\n\
    {}{trx}\n\
    {}{ltcu}\n\
    {}{ltcc}\n\
    {}{dogu}\n\
    {}{dogc}\n\
    {}{dog49}\n\
    {}{bch49}\n\
    {}{btgu}\n\
    {}{btgc}\n\
    {}{btg49}\n\
    {}{est}\n\
    {}{een}\n\
    {}{st}\n\
    ",green(num_cores), blue(num_cpus::get()), green(custom_digit.clone()),
             color_bool(string_to_bool(btc44_u.clone())), color_bool(string_to_bool(btc44_c.clone())), color_bool(string_to_bool(btc49.clone())),
             color_bool(string_to_bool(btc84.clone())), color_bool(string_to_bool(eth44.clone())), color_bool(string_to_bool(trx.clone())),
             color_bool(string_to_bool(ltc_u.clone())), color_bool(string_to_bool(ltc_c.clone())), color_bool(string_to_bool(doge_u.clone())),
             color_bool(string_to_bool(doge_c.clone())), color_bool(string_to_bool(doge49.clone())), color_bool(string_to_bool(bch.clone())),
             color_bool(string_to_bool(btg44_u.clone())), color_bool(string_to_bool(btg44_c.clone())), color_bool(string_to_bool(btg49.clone())),
             green(enum_start.clone()),green(enum_end.clone()),green(step.clone()),cpu = blue("-CORE CPU"),custom =blue("-CUSTOM_HEX_DIGIT"),btc44=blue("-BTC,BCH[44u]"),
             btc44c = blue("-BTC,BCH[44c]"), btc49 =blue("-BTC[49]"),btc84=blue("-BTC[84 p2wpkh]"),eth =blue("-ETH,BNB"),trx =blue("-TRX"),
    ltcu = blue("-LTC u"),ltcc=blue("-LTC c"),dogu=blue("-DOGECOIN 44u"),dogc =blue("-DOGECOIN 44c"),
             dog49=blue("-DOGECOIN 49"),bch49=blue("-BCH[49]"),btgu =blue("-BTG[44u]"),btgc =blue("-BTG[44c]"),
             btg49 =blue("-BTG[49]"),est =blue("-ENUMERATION start"),een =blue("-ENUMERATION end"),st=blue("-STEP"));

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
// let adr = "AYNcApi5UkS5WJYujz7Tp9MA6crzG7pomm";
//     println!("{}{}:{}",style("ONLINE BALANCE BTG:").magenta(), style(&adr).magenta(), style(get_btg_balance(&adr).await).red());

    //отображает инфу в однy строку(обновляемую)
    let backspace: char = 8u8 as char;
    let mut stdout = stdout();
    for received in rx {
        let list: Vec<&str> = received.split(",").collect();
        let mut speed = list[0].to_string().parse::<u64>().unwrap();
        let mut hex = list[1].to_string().parse::<u64>().unwrap();

        if speed == 0 && hex == 0 {
            let adr_coin = list[2].to_string();
            let adr = adr_coin.split(" ").collect::<Vec<_>>()[0].to_string();
            let con = adr_coin.split(" ").collect::<Vec<_>>()[1].to_string();
            if con == "BTC" {
                println!("{}", magenta("********************************************************************"));
                println!("{}{}:{}",magenta("ONLINE BALANCE BTC:"), magenta(&adr), red(get_balance(&adr, "btc").await));
                if &adr[0..1]=="1"{
                    println!("{}{}:{}",magenta("ONLINE BALANCE BCH:"), magenta(&adr), red(get_bch_balance(&adr).await));
                }
                println!("{}", magenta("********************************************************************"));
            }
            if con == "ETH" {
                println!("{}", magenta("********************************************************************"));
                println!("{}{}:{}",magenta("ONLINE BALANCE ETH:"), magenta(&adr), red(get_balance(&adr, "eth").await));
                println!("{}{}:{}",magenta("ONLINE BALANCE BNB:"), magenta(&adr), red(get_bnb_balance(&adr).await));
                println!("{}", magenta("********************************************************************"));
            }
            if con == "DOGE" {
                println!("{}", magenta("********************************************************************"));
                println!("{}{}:{}",magenta("ONLINE BALANCE DOGE:"), magenta(&adr), red(get_balance(&adr, "doge").await));
                println!("{}", magenta("********************************************************************"));
            }
            if con == "LTC" {
                println!("{}", magenta("********************************************************************"));
                println!("{}{}:{}",magenta("ONLINE BALANCE LTC:"), magenta(&adr), red(get_balance(&adr, "ltc").await));
                println!("{}", magenta("********************************************************************"));
            }
            if con == "TRX" {
                println!("{}", magenta("********************************************************************"));
                println!("{}{}:{}",magenta("ONLINE BALANCE TRX:"), magenta(&adr), red(get_trx_balance(&adr).await));
                println!("{}", magenta("********************************************************************"));
            }
            if con == "BTG" {
                println!("{}", magenta("********************************************************************"));
                println!("{}{}:{}",magenta("ONLINE BALANCE BTG:"), magenta(&adr), red(get_btg_balance(&adr).await));
                println!("{}", magenta("********************************************************************"));
            }
            if con == "BCH" {
                println!("{}", magenta("********************************************************************"));
                println!("{}{}:{}",magenta("ONLINE BALANCE BCH:"), magenta(&adr), red(get_bch_balance(&adr).await));
                println!("{}", magenta("********************************************************************"));
            }
        } else {
            hex = hex * num_cores as u64;
            speed = speed * num_cores as u64;
            print!("\r{}{}{}{}{}{}{}{}", backspace,green("[ADDRESS:"),green(speed),green("/s][HEX:"),
                   green(hex),green("/s][HEX:"),green(list[2].to_string().trim()),green("]"));
            stdout.flush().unwrap();
        }
    }
}

fn process(file_content: &Arc<Bloom<String>>, bench: bool, tx: Sender<String>, set: &Arc<Vec<String>>) {
    let mut start = Instant::now();
    let mut speed: u32 = 0;

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

    let mut addresa = vec![];

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

                let pub_key_unc = hex::decode(&ice_pub_key_unc).unwrap();
                let pub_key_com = hex::decode(&ice_pub_key_com).unwrap();

                let btc44_comp = wallets::get_legacy(&pub_key_com, wallets::LEGACY_BTC);

                if btc44_u { addresa.push((wallets::get_legacy(&pub_key_unc, wallets::LEGACY_BTC), "BTC")) };
                if btc44_c { addresa.push((btc44_comp.clone(), "BTC")) };
                if btc49 { addresa.push((wallets::get_bip49(&pub_key_com, wallets::BIP49_BTC), "BTC")); };
                if btc84 { addresa.push((ice_library.publickey_to_address(2, true, &pub_key_unc), "BTC")); };

                let eth = wallets::get_eth_address_from_public_key(&ice_pub_key_unc);
                if eth44 { addresa.push((eth.clone(), "ETH")) };
                if eth44 { addresa.push((eip55::checksum(eth.clone().as_str())[2..].to_string(), "ETH")) };

                if trx { addresa.push((wallets::get_trx_from_eth(eth), "TRX")) };

                if ltc_u { addresa.push((wallets::get_legacy(&pub_key_unc, wallets::LEGACY_LTC), "LTC")) };
                if ltc_c { addresa.push((wallets::get_legacy(&pub_key_com, wallets::LEGACY_LTC), "LTC")) };

                if doge_u { addresa.push((wallets::get_legacy(&pub_key_unc, wallets::LEGACY_DOGE), "DOGE")) };
                if doge_c { addresa.push((wallets::get_legacy(&pub_key_com, wallets::LEGACY_DOGE), "DOGE")) };
                if doge49 { addresa.push((wallets::get_bip49(&pub_key_com, wallets::BIP49_DOGE), "DOGE")) };

                if bch { addresa.push((wallets::legasy_btc_to_bch(btc44_comp), "BCH")) };

                if btg44_u { addresa.push((wallets::get_legacy(&pub_key_unc, wallets::LEGACY_BTG), "BTG")) };
                if btg44_c { addresa.push((wallets::get_legacy(&pub_key_com, wallets::LEGACY_BTG), "BTG")) };
                if btg49 { addresa.push((wallets::get_bip49(&pub_key_com, wallets::BIP49_BTG), "BTG")); };


                hex = hex + 1;
                for a in addresa.iter() {
                    if file_content.check(&a.0) {
                        print_and_save(a, &hex_rand);
                        tx.send(format!("{},{},{} {}", 0, 0, a.0, a.1).to_string()).unwrap()
                    }

                    if bench {
                        speed = speed + 1;
                        if start.elapsed() >= Duration::from_secs(1) {
                            println!("--------------------------------------------------------");
                            println!("HEX:{}", &hex_rand);
                            for ad in addresa.iter() {
                                println!("ADDRESS:{} {}", ad.1, ad.0);
                            }
                            println!("--------------------------------------------------------");
                            start = Instant::now();
                            speed = 0;
                        }
                    } else {
                        speed = speed + 1;
                        if start.elapsed() >= Duration::from_secs(1) {
                            tx.send(format!("{speed},{hex},{} ", hex_rand)).unwrap();
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

fn print_and_save(address: &(String, &str), secret_key: &String) {
    println!("{}", cyan("\n!!!!!!!!!!!!!!!!!!!!FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
    println!("{}{}",cyan("COIN:"), cyan(&address.1));
    println!("{}{}",cyan("ADDRESS:"), cyan(&address.0));
    println!("{}{}",cyan("HEX:"), cyan(&secret_key));

    let s = format!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
    COIN:{}\n\
    ADDRESS:{}\n\
    HEX:{secret_key}\n\
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", address.1.to_string(), address.0.to_string(), );
    add_v_file("FOUND.txt", s.to_string());

    println!("{}", cyan("!!!!!!!!!!!!!!!SAVE TO FOUND.txt!!!!!!!!!!!!!!!!!!!!!!!!"));
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
