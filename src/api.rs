use thiserror::Error;

use reqwest::Url;

/// The errors that may occur when interacting with the API. 
#[derive(Error, Debug)]
pub enum Error {
    #[error("request error")]
    Request(#[from] reqwest::Error),
    #[error("response error")]
    Response(#[from] serde_json::Error)
}

/// Executes a request 
pub async fn request<T: for<'de> serde::de::Deserialize<'de>>(url: Url) -> Result<T, Error> {
    let resp = reqwest::get(url)
        .await?;

    let resp_json = resp
        .json::<serde_json::Map<String, serde_json::Value>>()
        .await?;

    serde_json::from_value(resp_json["LL"]["value"].clone()).map_err(|err| Error::Response(err))
}