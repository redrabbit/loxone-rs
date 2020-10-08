mod api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = reqwest::Url::parse("http://miniserver")?;

    /*
    let api_key: String = api::request(base_url.join("jdev/cfg/apiKey")?).await?;
    println!("API key: {}", serde_json::to_string_pretty(&api_key)?);

    let public_key: String = api::request(base_url.join("jdev/sys/getPublicKey")?).await?;
    println!("Public key: {}", serde_json::to_string_pretty(&public_key)?);

    let data: String = api::request(base_url.join("data/LoxAPP3.json")?).await?;
    println!("Data: {}", serde_json::to_string_pretty(&data)?);
    */

    let user = "admin";
    let password = "TdtuPMJjZTTutWetWMoPXy9V";
    let permission = 4;
    let uuid = "098802e1-02b4-603c-ffffeee000d80cfd";
    let info = "rust";

    let public_key = api::get_public_key(&base_url).await?;

    let mut client = api::Client::new(base_url, &public_key)?;
    client.authenticate(user, password, permission, uuid, info).await?;

    let loxapp3 = client.loxapp3().await?;
    println!("loxapp3.json: {:?}", loxapp3);

    Ok(())
}
