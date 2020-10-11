use std::path::Path;
use tokio::{fs, io};

use futures_util::future::TryFutureExt;

mod api;

async fn read_public_key_file(path: impl AsRef<Path>) -> io::Result<String> {
    fs::read_to_string(path).await
}

async fn read_token_file(path: impl AsRef<Path>) -> io::Result<api::JsonWebToken> {
    let json = fs::read(path).await?;
    Ok(serde_json::from_slice(&json)?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = reqwest::Url::parse("http://miniserver")?;

    let x509_cert = read_public_key_file("public_key.pem").or_else(|_| api::get_x509_cert(&base_url)).await?;

    let user = "admin";
    let password = "TdtuPMJjZTTutWetWMoPXy9V";
    let permission = 4;
    let uuid = "098802e1-02b4-603c-ffffeee000d80cfd";
    let info = "rust";

    let mut client = api::Client::new(base_url, &x509_cert)?;
    client.jwt = read_token_file("token.jwt").or_else(|_| client.get_token(user, password, permission, uuid, info)).await.ok();

    let loxapp3 = client.loxapp3_last_modified().await?;
    println!("loxapp3.json: {:#?}", loxapp3);

    Ok(())
}
