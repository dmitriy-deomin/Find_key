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
    len_eth: u64,
    number_of_bits: u64,
    number_of_hash_functions: u32,
    sip_keys: [(u64, u64); 2],
}

pub(crate) fn load_bloom() -> Bloom<String> {
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
        println!("TOTAL ADDRESS LOAD:{:?}", mb.len_btc + mb.len_eth);

        database
    } else {
//если блума нет будем создавать
        print!("LOAD ADDRESS BTC");
        let baza_btc = load_db("btc.txt");
        let len_btc = baza_btc.len();
        println!(":{}", len_btc);

        print!("LOAD ADDRESS ETH");
        let baza_eth = load_db("eth.txt");
        let len_eth = baza_eth.len();
        println!(":{}", len_eth);

//база для поиска
        let num_items = len_eth + len_btc;

        let fp_rate = 0.0000000001;
        let mut database = Bloom::new_for_fp_rate(num_items, fp_rate);

        println!("LOAD AND SAVE BLOOM...");
//
        for f in baza_btc {
            database.set(&f);
        }
        for f in baza_eth {
            database.set(&f);
        }

//сохранение данных блума
        let vec = database.bitmap();
        let encoded: Vec<u8> = bincode::serialize(&vec).unwrap();
        fs::write("data.bloom", encoded).unwrap();

//сохранение в файл настроек блума
        let save_meta_data = MetaDataBloom { len_btc: len_btc as u64, len_eth: len_eth as u64, number_of_bits: database.number_of_bits(), number_of_hash_functions: database.number_of_hash_functions(), sip_keys: database.sip_keys() };
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
                "btc.txt" => { include_str!("btc.txt") }
                "eth.txt" => { include_str!("eth.txt") }
                "confFkey.txt" => { include_str!("confFkey.txt") }
                _ => { include_str!("btc.txt") }
            };
            add_v_file(coin, dockerfile.to_string());
            lines_from_file(coin).expect("kakoyto_pizdec")
        }
    };
    file_content
}