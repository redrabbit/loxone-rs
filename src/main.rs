mod api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = reqwest::Url::parse("http://miniserver")?;
    let api_key: String = api::request(base_url.join("jdev/cfg/apiKey")?).await?;
    println!("API key: {}", serde_json::to_string_pretty(&api_key)?);

    let public_key: String = api::request(base_url.join("jdev/sys/getPublicKey")?).await?;
    println!("Public key: {}", serde_json::to_string_pretty(&public_key)?);
    Ok(())
}
