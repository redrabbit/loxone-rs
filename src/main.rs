use tokio;

//use std::collections::HashMap;
//use tokio::stream::StreamExt;

use loxone::{WebSocket, loxapp3::{controllers::LightControllerV2, LoxoneApp3}};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /*
    let user = "admin";
    let password = "TdtuPMJjZTTutWetWMoPXy9V";
    let permission = 4;
    let uuid = "098802e1-02b4-603c-ffffeee000d80cfd";
    let info = "rust";
    */

    let cert = tokio::fs::read_to_string("public_key.pem").await?;
    let ws_url = "ws://172.16.3.59/ws/rfc6455".parse()?;

    let (mut ws, resp, rx, recv_loop) = WebSocket::connect(ws_url).await?;
    println!("webSocket handshake has been successfully completed");
    println!("{:?}", resp);

    let recv_loop = tokio::spawn(recv_loop);
    println!("running recv loop on dedicated task");

    let reply = ws.key_exchange(&cert).await?;
    println!("exchanged session key: {} bytes", reply.len());

    let jwt: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&tokio::fs::read_to_string("token.json").await?)?;

    let reply = ws.authenticate(jwt["token"].as_str().unwrap()).await?;
    println!("authenticated: {}", serde_json::to_string(&reply)?);

    let (state, mut stream) = ws.enable_status_update(rx).await?;
    println!("received initial state");

    let loxapp3: LoxoneApp3 = serde_json::from_str(&tokio::fs::read_to_string("loxapp3.json").await?)?;

    let control_uuid = "149cfb32-033c-0a94-ffff403fb0c34b9e".to_string();
    let control = &loxapp3.controls[&control_uuid];
    ws.send_io_cmd(&control_uuid, LightControllerV2::plus()).await?;
    println!("changed mood for {} in room {}", control.name, &loxapp3.rooms[control.room.as_ref().unwrap()].name);

    /*
    while let Some(event) = stream.next().await {
        println!("event: {:?}", event);
    }
    tokio::try_join!(recv_loop)?;
    */

    Ok(())
}
