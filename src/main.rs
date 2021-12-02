use std::ops::Add;
use std::path::Path;
use std::fs::File;

use tokio;
use chrono;

use tokio::stream::StreamExt;


use loxone::{WebSocket, loxapp3::{LoxoneApp3, LoxoneController, controllers::ColorPickerV2}};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let naive_utc_now = chrono::Utc::now().naive_utc();
    let user = "admin";
    let password = "TdtuPMJjZTTutWetWMoPXy9V";
    let permission = 4;
    let uuid = "098802e1-02b4-603c-ffffeee000d80cfd";
    let info = "rust";
    let cert = tokio::fs::read_to_string("public_key.pem").await?;
    let ws_url = "ws://172.16.3.59/ws/rfc6455".parse()?;

    let (mut ws, _, rx, recv_loop) = WebSocket::connect(ws_url).await?;
    println!("webSocket handshake has been successfully completed");

    let recv_task = tokio::spawn(recv_loop);
    println!("running recv loop on dedicated task");

    let session_key = ws.key_exchange(&cert).await?;
    println!("exchanged session key: {} bytes", session_key.len());

    let jwt_path = Path::new("token.json");
    let jwt: serde_json::Map<String, serde_json::Value>;

    if jwt_path.is_file() {
        jwt = serde_json::from_str(&tokio::fs::read_to_string(jwt_path).await?)?;
        if naive_utc_now <= chrono::NaiveDate::from_ymd(2009, 1, 1).and_hms(0, 0, 0).add(chrono::Duration::seconds(jwt["validUntil"].as_i64().unwrap())) {
            ws.authenticate(jwt["token"].as_str().unwrap()).await?;
            println!("authenticated with {}", jwt_path.display());
        } else {
            panic!("{} has expired", jwt_path.display());
        }
    } else {
        jwt = ws.get_jwt(user, password, permission, uuid, info).await?;
        serde_json::to_writer(&File::create(jwt_path)?, &jwt)?;
        println!("authenticated with user credentials");
    }

    let loxapp3_path = Path::new("loxapp3.json");
    let loxapp3: LoxoneApp3;

    if loxapp3_path.is_file() {
        loxapp3 = serde_json::from_str(&tokio::fs::read_to_string(loxapp3_path).await?)?;
        if chrono::NaiveDateTime::parse_from_str(&loxapp3.last_modified, "%Y-%m-%d %H:%M:%S")? <= chrono::NaiveDateTime::parse_from_str(&ws.get_loxapp3_timestamp().await?, "%Y-%m-%d %H:%M:%S")? {
            println!("{} loaded", loxapp3_path.display());
        } else {
            panic!("{} is outdated", loxapp3_path.display());
        }
    } else {
        let loxapp3_json: serde_json::Map<String, serde_json::Value> = ws.get_loxapp3().await?;
        serde_json::to_writer(&File::create(loxapp3_path)?, &loxapp3_json)?;
        loxapp3 = serde_json::from_str(&tokio::fs::read_to_string(loxapp3_path).await?)?;
        println!("{} downloaded from miniserver", loxapp3_path.display());
    }

    let (state, mut stream) = ws.enable_status_update(rx).await?;

    while let Some(event) = stream.next().await {
        if state[&event.0] != event.1 {
            println!("event {:?}", event);
        }
    }

    tokio::try_join!(recv_task)?;
    Ok(())
}
