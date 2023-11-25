use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use bloomfilter::Bloom;
use serde::{Deserialize, Serialize};
use crate::{add_v_file, lines_from_file};

#[derive(Debug, Serialize, Deserialize)]
struct MetaDataBloom {
    len_btc: u64,
    len_btg: u64,
    len_bch: u64,
    len_eth: u64,
    len_trx: u64,
    len_ltc: u64,
    len_doge: u64,
    number_of_bits: u64,
    number_of_hash_functions: u32,
    sip_keys: [(u64, u64); 2],
}

pub(crate) fn load_bloom() -> Bloom<String> {
    //если блум есть загружаем его
    let d_b = Path::new("data.bloom");
    let m_b = Path::new("metadata.bloom");
    if d_b.exists() && m_b.exists() {
//чтение из файла настроек блума
        let string_content = fs::read_to_string("metadata.bloom").unwrap();
        let mb: MetaDataBloom = serde_json::from_str(&string_content).unwrap();

//чтение данных блума
        let f: Vec<u8> = get_file_as_byte_vec("data.bloom");
        let fd: Vec<u8> = bincode::deserialize(&f[..]).unwrap();
        let database = Bloom::from_existing(&*fd, mb.number_of_bits, mb.number_of_hash_functions, mb.sip_keys);

        println!("LOAD BLOOM");
        println!("ADDRESS BTC:{}", mb.len_btc);
        println!("ADDRESS ETH:{}", mb.len_eth);
        println!("ADDRESS TRX:{}", mb.len_trx);
        println!("ADDRESS LTC:{}", mb.len_ltc);
        println!("ADDRESS DOGECOIN:{}", mb.len_doge);
        println!("ADDRESS BCH:{}", mb.len_bch);
        println!("ADDRESS BTG:{}", mb.len_btg);
        println!("TOTAL ADDRESS LOAD:{:?}", mb.len_btc + mb.len_eth + mb.len_ltc + mb.len_trx + mb.len_bch + mb.len_btg+mb.len_doge);

        database
    } else {
//если блума нет будем создавать
        print!("LOAD ADDRESS BTC");
        let mut baza_btc = load_db("btc.txt");
        let len_btc = baza_btc.len();
        println!(":{}", len_btc);
        baza_btc.clear();

        print!("LOAD ADDRESS ETH");
        let mut baza_eth = load_db("eth.txt");
        let len_eth = baza_eth.len();
        println!(":{}", len_eth);
        baza_eth.clear();

        print!("LOAD ADDRESS TRX");
        let mut baza_trx = load_db("trx.txt");
        let len_trx = baza_trx.len();
        println!(":{}", len_trx);
        baza_trx.clear();

        print!("LOAD ADDRESS LTC");
        let mut baza_ltc = load_db("ltc.txt");
        let len_ltc = baza_ltc.len();
        println!(":{}", len_ltc);
        baza_ltc.clear();

        print!("LOAD ADDRESS DOGECOIN");
        let mut baza_doge = load_db("dogecoin.txt");
        let len_doge = baza_doge.len();
        println!(":{}", len_doge);
        baza_doge.clear();

        print!("LOAD ADDRESS BCH");
        let mut baza_bch = load_db("bch.txt");
        let len_bch = baza_bch.len();
        println!(":{}", len_bch);
        baza_bch.clear();

        print!("LOAD ADDRESS BTG");
        let mut baza_btg = load_db("btg.txt");
        let len_btg = baza_btg.len();
        println!(":{}", len_btg);
        baza_btg.clear();

//база для поиска
        let num_items = len_eth + len_btc + len_trx + len_ltc + len_doge + len_bch + len_btg;

        let fp_rate = 0.00000000001;
        let mut database = Bloom::new_for_fp_rate(num_items, fp_rate);

        println!("LOAD AND SAVE BLOOM...");
//
        baza_btc = load_db("btc.txt");
        for f in baza_btc.iter() {
            database.set(f);
        }
        baza_btc.clear();

        baza_eth = load_db("eth.txt");
        for f in baza_eth.iter(){
            database.set(f);
        }
        baza_eth.clear();

        baza_trx = load_db("trx.txt");
        for f in baza_trx.iter() {
            database.set(f);
        }
        baza_trx.clear();

        baza_ltc = load_db("ltc.txt");
        for f in baza_ltc.iter() {
            database.set(f);
        }
        baza_ltc.clear();

        baza_doge = load_db("dogecoin.txt");
        for f in baza_doge.iter() {
            database.set(f);
        }
        baza_doge.clear();

        baza_bch = load_db("bch.txt");
        for f in baza_bch.iter() {
            database.set(f);
        }
        baza_bch.clear();

        baza_btg = load_db("btg.txt");
        for f in baza_btg.iter() {
            database.set(f);
        }
        baza_btg.clear();

//сохранение данных блума
        let vec = database.bitmap();
        let encoded: Vec<u8> = bincode::serialize(&vec).unwrap();
        fs::write("data.bloom", encoded).unwrap();

//сохранение в файл настроек блума
        let save_meta_data = MetaDataBloom {
            len_doge: len_doge as u64,
            len_bch: len_bch as u64,
            len_btc: len_btc as u64,
            len_btg: len_btg as u64,
            len_eth: len_eth as u64,
            len_trx: len_trx as u64,
            len_ltc: len_ltc as u64,
            number_of_bits: database.number_of_bits(),
            number_of_hash_functions: database.number_of_hash_functions(),
            sip_keys: database.sip_keys(),
        };
        let sj = serde_json::to_string(&save_meta_data).unwrap();
        fs::write("metadata.bloom", sj).unwrap();

        println!("TOTAL ADDRESS LOAD:{:?}", num_items);

        database
    }
}

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

pub(crate) fn load_db(coin: &str) -> Vec<String> {
    let file_content = match lines_from_file(coin) {
        Ok(file) => { file }
        Err(_) => {
            let dockerfile = match coin {
                "bch.txt" => { include_str!("bch.txt") }
                "btc.txt" => { include_str!("btc.txt") }
                "btg.txt" => { include_str!("btg.txt") }
                "eth.txt" => { include_str!("eth.txt") }
                "trx.txt" => { include_str!("trx.txt") }
                "ltc.txt" => { include_str!("ltc.txt") }
                "dogecoin.txt" => { include_str!("dogecoin.txt") }
                "confFkey.txt" => { include_str!("confFkey.txt") }
                _ => { include_str!("btc.txt") }
            };
            add_v_file(coin, dockerfile.to_string());
            lines_from_file(coin).expect("kakoyto_pizdec")
        }
    };
    file_content
}