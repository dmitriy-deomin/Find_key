//баланс с blockcypher для BTC,ETH,DOGE,LTC
pub async fn get_balance(address: &String, coin: &str) -> String {
    let url = format!("https://api.blockcypher.com/v1/{}/main/addrs/{}/balance", coin, address);
    let response = reqwest::get(&url).await;

    let text = match response {
        Ok(t) => { t.text().await.unwrap() }
        Err(_) => { "error".to_string() }
    };

    let data = r#"
        {
            "balance": "Error"
        }"#;

    let json: serde_json::Value =
        serde_json::from_str(&*text).unwrap_or(data.parse().unwrap());
    json["balance"].to_string()
}

//баланс с tronscan для TRX
pub async fn get_trx_balance(wallet_address: &str) -> String {
    let url = format!("https://apilist.tronscan.org/api/account?address={}", wallet_address);
    let response = reqwest::get(&url).await;

    let text = match response {
        Ok(t) => { t.text().await.unwrap() }
        Err(_) => { "error".to_string() }
    };

    let data = r#"
        {
            "balance": "Error"
        }"#;

    let json: serde_json::Value =
        serde_json::from_str(&*text).unwrap_or(data.parse().unwrap());
    json["balance"].to_string()
}

pub async fn get_btg_balance(wallet_address: &str) -> String {
    let url = format!("https://btg1.trezor.io/address/{}", wallet_address);
    let response = reqwest::get(&url).await;

    let text = match response {
        Ok(t) => { t.text().await.unwrap() }
        Err(_) => { "error".to_string() }
    };

    let data = r#"
        {
            "balance": "Error"
        }"#;

    let json: serde_json::Value =
        serde_json::from_str(&*text).unwrap_or(data.parse().unwrap());
    json["balance"].to_string()
}

pub async fn get_bch_balance(wallet_address: &str) -> String {
    //can be one of these: bitcoin, bitcoin-cash, litecoin, bitcoin-sv, dogecoin, dash, groestlcoin, zcash, ecash, bitcoin/testnet
    let url = format!("https://api.blockchair.com/bitcoin-cash/addresses/balances?addresses={}", wallet_address);

    let response = reqwest::get(&url).await;

    let text = match response {
        Ok(t) => { t.text().await.unwrap() }
        Err(_) => { "error".to_string() }
    };

    let data = r#"
        {
            "balance": "Error"
        }"#;

    let json: serde_json::Value =
        serde_json::from_str(&*text).unwrap_or(data.parse().unwrap());
    json["data"][wallet_address].to_string()
}

//BNB
use web3::transports::Http;
use web3::types::{Address, U256};

pub async fn get_bnb_balance(wallet_address: &str) -> String {
    // Устанавливаем соединение с узлом Binance Smart Chain
    let http = Http::new("https://bsc-dataseed.binance.org/").unwrap();
    let web3 = web3::Web3::new(http);

    // BNB кошелек для получения баланса
    let wallet_address: Address = wallet_address.parse().unwrap();

    // Получаем баланс кошелька
    let balance: U256 = web3.eth().balance(wallet_address, None).await.unwrap();

    balance.to_string()
}


