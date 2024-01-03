use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use bloomfilter::Bloom;
use console::style;
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
    len_bnb: u64,
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

        println!("{}", style("LOAD BLOOM".to_string()).blue());
        println!("{}{}",style("ADDRESS BTC:").blue(), style(mb.len_btc.to_string()).green());
        println!("{}{}",style("ADDRESS ETH:").blue(), style(mb.len_eth.to_string()).green());
        println!("{}{}",style("ADDRESS BNB:").blue(), style(mb.len_bnb.to_string()).green());
        println!("{}{}",style("ADDRESS TRX:").blue(), style(mb.len_trx.to_string()).green());
        println!("{}{}",style("ADDRESS LTC:").blue(), style(mb.len_ltc.to_string()).green());
        println!("{}{}",style("ADDRESS DOGECOIN:").blue(), style(mb.len_doge.to_string()).green());
        println!("{}{}",style("ADDRESS BCH:").blue(), style(mb.len_bch.to_string()).green());
        println!("{}{}",style("ADDRESS BTG:").blue(), style(mb.len_btg.to_string()).green());
        let s = mb.len_btc + mb.len_eth + mb.len_ltc + mb.len_trx + mb.len_bch + mb.len_btg+mb.len_doge+mb.len_bnb;
        println!("{}{}",style("TOTAL ADDRESS LOAD:").blue(),style(s.to_string()).green() );

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

        print!("LOAD ADDRESS BNB");
        let mut baza_bnb = load_db("bnb.txt");
        let len_bnb = baza_bnb.len();
        println!(":{}", len_bnb);
        baza_bnb.clear();

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
        let num_items = len_eth + len_btc + len_trx + len_ltc + len_doge + len_bch + len_btg+len_bnb;

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

        baza_bnb = load_db("bnb.txt");
        for f in baza_bnb.iter(){
            database.set(f);
        }
        baza_bnb.clear();

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
            len_bnb: len_bnb as u64,
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
                "bch.txt" => { include_str!("base_file/bch.txt") }
                "btc.txt" => { include_str!("base_file/btc.txt") }
                "btg.txt" => { include_str!("base_file/btg.txt") }
                "eth.txt" => { include_str!("base_file/eth.txt") }
                "bnb.txt" => { include_str!("base_file/bnb.txt") }
                "trx.txt" => { include_str!("base_file/trx.txt") }
                "ltc.txt" => { include_str!("base_file/ltc.txt") }
                "dogecoin.txt" => { include_str!("base_file/dogecoin.txt") }
                "confFkey.txt" => { include_str!("confFkey.txt") }
                _ => { include_str!("base_file/btc.txt") }
            };
            add_v_file(coin, dockerfile.to_string());
            lines_from_file(coin).expect("kakoyto_pizdec")
        }
    };
    file_content
}
