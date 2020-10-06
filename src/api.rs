use crypto::digest::Digest;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

use rand::RngCore;
use rand::rngs::OsRng;

use rsa::{PublicKey, RSAPublicKey};

use reqwest::Url;

use thiserror::Error;


type HmacSha1 = Hmac<Sha1>;

/// The errors that may occur when interacting with the API. 
#[derive(Error, Debug)]
pub enum Error {
    #[error("request error")]
    Request(#[from] reqwest::Error),
    #[error("json error")]
    JsonParse(#[from] serde_json::Error)
}

/// Executes a request 
pub async fn request<T: for<'de> serde::de::Deserialize<'de>>(url: Url) -> Result<T, Error> {
    let resp = reqwest::get(url).await?;
    match resp.error_for_status_ref() {
        Ok(_) => {
            let resp_body = resp.text().await?;
            match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&resp_body) {
                Ok(resp_json) => serde_json::from_value(resp_json["LL"]["value"].clone()).map_err(|err| Error::JsonParse(err)),
                Err(_err) => {
                    let resp_body = resp_body.replace("\r", ""); // TODO ignore invalid chars
                    let resp_json = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&resp_body)?;
                    serde_json::from_value(resp_json["LL"]["value"].clone()).map_err(|err| Error::JsonParse(err))
                }
            }
        },
        Err(err) => {
            Err(Error::Request(err))
        }
    }
}

pub async fn get_public_key(base_url: &Url) -> Result<RSAPublicKey, Box<dyn std::error::Error>> {
    let cert: String = request(base_url.join("jdev/sys/getPublicKey")?).await?;
    parse_cert_pub_key(cert.as_bytes()).ok_or("invalid certificate".into())
}

pub async fn get_token(base_url: &Url, public_key: &RSAPublicKey, user: &str, password: &str, permission: u8, uuid: &str, info: &str) -> Result<serde_json::Map<String, serde_json::Value>, Error> {
    let auth: serde_json::Map<String, serde_json::Value> = request(base_url.join(format!("jdev/sys/getkey2/{}", user).as_str()).unwrap()).await?;

    let mut hasher = Sha1::new();
    hasher.input_str(format!("{}:{}", password, auth["salt"].as_str().unwrap()).as_str());
    let password_hash = hasher.result_str().to_uppercase();

    let mut mac = HmacSha1::new(Sha1::new(), &hex::decode(auth["key"].as_str().unwrap()).unwrap());
    mac.input(format!("{}:{}", user, password_hash).as_bytes());
    let mac_result = mac.result();

    let hash = mac_result.code();
    let hash_hex = hex::encode(hash);

    let cmd = format!("jdev/sys/getjwt/{}/{}/{}/{}/{}", hash_hex, user, permission, uuid, info);
    let encrypted_cmd = encrypt_cmd(&cmd, &public_key);

    request(base_url.join(encrypted_cmd.as_str()).unwrap()).await
}

pub fn encrypt_cmd(cmd: &str, public_key: &RSAPublicKey) -> String {
    let mut key: [u8; 32] = [0; 32];
    let mut iv: [u8; 16] = [0; 16];

    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);

    let key_hex = hex::encode(key);
    let iv_hex = hex::encode(iv);

    let cipher_salt = "1234"; // TODO generate random salt
    let cipher = base64::encode_config(aes256_encrypt(format!("salt/{}/{}", cipher_salt, cmd).as_bytes(), &key, &iv).unwrap(), base64::STANDARD_NO_PAD);
    let encoded_cipher: String = url::form_urlencoded::byte_serialize(cipher.as_bytes()).collect();

    let mut session_key_rng = rand::rngs::OsRng;
    let session_key_data = format!("{}:{}", key_hex, iv_hex);
    let session_key = base64::encode_config(public_key.encrypt(&mut session_key_rng, rsa::PaddingScheme::PKCS1v15Encrypt, session_key_data.as_bytes()).unwrap(), base64::STANDARD_NO_PAD);
    let encoded_session_key: String = url::form_urlencoded::byte_serialize(session_key.as_bytes()).collect();

    format!("jdev/sys/enc/{}?sk={}", encoded_cipher, encoded_session_key) 
}

fn parse_cert_pub_key(cert: &[u8]) -> Option<RSAPublicKey> {
    let pem = pem::parse(cert).unwrap();
    let asn1_blocks = simple_asn1::from_der(&pem.contents).unwrap();
    if let Some(simple_asn1::ASN1Block::Sequence(_ofs, blocks)) = asn1_blocks.first() {
        if let Some(simple_asn1::ASN1Block::BitString(_ofs, _len, der)) = blocks.last() {
            return Some(rsa::RSAPublicKey::from_pkcs1(der).unwrap());
        }
    }
    None
}

fn aes256_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}