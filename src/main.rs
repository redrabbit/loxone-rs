use tokio::fs::read_to_string;


mod api;



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user = "admin";
    let password = "TdtuPMJjZTTutWetWMoPXy9V";
    let permission = 4;
    let uuid = "098802e1-02b4-603c-ffffeee000d80cfd";
    let info = "rust";

    let cert = read_to_string("public_key.pem").await?;
    let ws_url = "ws://miniserver/ws/rfc6455".parse()?;

    let (mut ws, resp) = api::WebSocket::connect(ws_url).await?;
    println!("WebSocket handshake has been successfully completed");
    println!("{:?}", resp);

    let reply = ws.key_exchange(&cert).await?;
    println!("key exchange: {}", reply);

    let reply = ws.get_jwt(user, password, permission, uuid, info).await?;
    println!("jwt: {:?}", reply);

    let reply = ws.get_loxapp3_timestamp().await?;
    println!("loxapp3 timestamp: {}", reply);

    let reply = ws.get_loxapp3_json().await?;
    println!("loxapp3 json: {:?}", reply);

    ws.enable_status_update().await?;

    Ok(())
}