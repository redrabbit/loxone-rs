use tokio::stream::StreamExt;

mod api;

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
    let ws_url = "ws://miniserver/ws/rfc6455".parse()?;

    let (mut ws, resp, rx, recv_loop) = api::WebSocket::connect(ws_url).await?;
    println!("WebSocket handshake has been successfully completed");
    println!("{:?}", resp);

    let recv_loop = tokio::spawn(recv_loop);
    println!("running recv loop on dedicated task");

    let reply = ws.key_exchange(&cert).await?;
    println!("exchanged session key: {} bytes", reply.len());

    let jwt: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&tokio::fs::read_to_string("token.json").await?)?;

    let reply = ws.authenticate(jwt["token"].as_str().unwrap()).await?;
    println!("authenticated: {}", serde_json::to_string_pretty(&reply)?);

    let reply = ws.get_loxapp3_timestamp().await?;
    println!("loxapp3 timestamp: {}", reply);

    let _loxapp3: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&tokio::fs::read_to_string("loxapp3.json").await?)?;

    let (initial_state, mut stream) = ws.enable_status_update(rx).await?;
    println!("got {} state events", initial_state.len());

    while let Some(event) = stream.next().await {
        println!("event: {:?}", event);
    }

    tokio::try_join!(recv_loop)?;

    Ok(())
}