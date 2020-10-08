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
pub enum RequestError {
    #[error("url error")]
    UrlParse(#[from] url::ParseError),
    #[error("request error")]
    Request(#[from] reqwest::Error),
    #[error("invalid response mime")]
    ResponseNotJson,
    #[error("json parse error")]
    ResponseJsonParse(#[from] serde_json::Error),
    #[error("encryption error")]
    Encryption(symmetriccipher::SymmetricCipherError)
}

#[derive(Error, Debug)]
pub enum X509CertError {
    #[error("request error")]
    Request(#[from] RequestError),
    #[error("pem error")]
    PemDecode(#[from] pem::PemError),
    #[error("asn1 error")]
    ASN1Decode(#[from] simple_asn1::ASN1DecodeErr),
    #[error("asn1 error")]
    ASN1MissingBlock,
    #[error("pkcs1 error")]
    PKCS1Decode(#[from] rsa::errors::Error),
}

pub struct Client {
    client: reqwest::Client,
    base_url: reqwest::Url,
    cmd_session: CommandSession,
}

struct CommandSession {
    session_key: Vec<u8>,
    rsa_key: [u8; 32],
    rsa_iv: [u8; 16]
}

impl Client {
    pub fn new(base_url: Url, public_key: &RSAPublicKey) -> Result<Self, rsa::errors::Error> {
        Ok(Client { client: reqwest::Client::new(), base_url, cmd_session: CommandSession::new(public_key)? })
    }

    pub async fn authenticate(&mut self, user: &str, password: &str, permission: u8, uuid: &str, info: &str) -> Result<(), RequestError> {
        let auth: serde_json::Map<String, serde_json::Value> = self.call(&format!("jdev/sys/getkey2/{}", user)).await?;

        let mut hasher = Sha1::new();
        hasher.input_str(format!("{}:{}", password, auth["salt"].as_str().unwrap()).as_str());
        let password_hash = hasher.result_str().to_uppercase();

        let mut mac = HmacSha1::new(Sha1::new(), &hex::decode(auth["key"].as_str().unwrap()).unwrap());
        mac.input(format!("{}:{}", user, password_hash).as_bytes());
        let mac_result = mac.result();

        let hash = mac_result.code();
        let hash_hex = hex::encode(hash);

        let jwt: serde_json::Map<String, serde_json::Value> = self.call_enc(&format!("jdev/sys/getjwt/{}/{}/{}/{}/{}", hash_hex, user, permission, uuid, info)).await?;

        let mut headers = reqwest::header::HeaderMap::new();
        let bearer_token = format!("Bearer {}", jwt["token"].as_str().unwrap());
        headers.insert(reqwest::header::AUTHORIZATION, reqwest::header::HeaderValue::from_str(&bearer_token).unwrap());

        self.client = reqwest::Client::builder()
            .default_headers(headers) // TODO use RequestBuilder instead
            .build()?;
        Ok(())
    }

    pub async fn loxapp3(&self) -> Result<serde_json::Map<String, serde_json::Value>, RequestError> {
        Self::request_json(&self.client, self.base_url.join("data/LoxApp3.json")?).await
    }

    async fn call_enc<T: for<'de> serde::Deserialize<'de>>(&self, cmd: &str) -> Result<T, RequestError> {
        let encrypted_cmd = Self::encrypt_cmd(cmd, &self.cmd_session).map_err(|err| RequestError::Encryption(err))?;
        Self::request_cmd(&self.client, self.base_url.join(&encrypted_cmd)?).await
    }

    async fn call<T: for<'de> serde::Deserialize<'de>>(&self, cmd: &str) -> Result<T, RequestError> {
        Self::request_cmd(&self.client, self.base_url.join(cmd)?).await
    }

    async fn request_json(client: &reqwest::Client, url: Url) -> Result<serde_json::Map<String, serde_json::Value>, RequestError> {
        let resp = client.get(url).send().await?;
        match resp.error_for_status_ref() {
            Ok(_) => {
                match resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|content_type| content_type.to_str().ok()) {
                    Some("application/json") => {
                        let resp_body = resp.text().await?;
                        let resp_body = resp_body.replace("\r", ""); // TODO escape control chars in strs
                        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&resp_body).map_err(|err| RequestError::ResponseJsonParse(err))
                    },
                    _ => {
                        let resp_body = resp.text().await?;
                        eprintln!("{}", resp_body);
                        Err(RequestError::ResponseNotJson)
                    }
                }
            },
            Err(err) => Err(RequestError::Request(err))
        }
    }

    async fn request_cmd<T: for<'de> serde::Deserialize<'de>>(client: &reqwest::Client, url: Url) -> Result<T, RequestError> {
        let resp_json = Self::request_json(client, url).await?;
        serde_json::from_value(resp_json["LL"]["value"].clone()).map_err(|err| RequestError::ResponseJsonParse(err))
    }

    fn encrypt_cmd(cmd: &str, session: &CommandSession) -> Result<String, symmetriccipher::SymmetricCipherError> {
        let cipher_salt = "1234"; // TODO generate random salt
        let cipher_plaintext = format!("salt/{}/{}", cipher_salt, cmd);

        let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize256, &session.rsa_key, &session.rsa_iv, blockmodes::PkcsPadding);

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(cipher_plaintext.as_bytes());
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

        let encoded_cipher: String = url::form_urlencoded::byte_serialize(base64::encode_config(final_result, base64::STANDARD_NO_PAD).as_bytes()).collect();
        let encoded_session_key: String = url::form_urlencoded::byte_serialize(base64::encode_config(&session.session_key, base64::STANDARD_NO_PAD).as_bytes()).collect();

        Ok(format!("jdev/sys/enc/{}?sk={}", encoded_cipher, encoded_session_key))
    }
}

impl CommandSession {
    fn new(public_key: &RSAPublicKey) -> Result<Self, rsa::errors::Error> {
        let mut rsa_key: [u8; 32] = [0; 32];
        let mut rsa_iv: [u8; 16] = [0; 16];

        OsRng.fill_bytes(&mut rsa_key);
        OsRng.fill_bytes(&mut rsa_iv);

        let mut session_key_rng = rand::rngs::OsRng;
        let session_key_data = format!("{}:{}", hex::encode(rsa_key), hex::encode(rsa_iv));
        let session_key = public_key.encrypt(&mut session_key_rng, rsa::PaddingScheme::PKCS1v15Encrypt, session_key_data.as_bytes())?;

        Ok(Self { session_key, rsa_key, rsa_iv })
    }
}

pub async fn get_public_key(base_url: &Url) -> Result<RSAPublicKey, X509CertError> {
    let cert: String = Client::request_cmd(&reqwest::Client::new(), base_url.join("jdev/sys/getPublicKey").map_err(|err| RequestError::UrlParse(err))?).await?;
    let pem = pem::parse(cert)?;
    let asn1_blocks = simple_asn1::from_der(&pem.contents)?;
    match asn1_blocks.first() {
        Some(simple_asn1::ASN1Block::Sequence(_ofs, seq_blocks)) =>
            match seq_blocks.last() {
                Some(simple_asn1::ASN1Block::BitString(_ofs, _len, der)) => rsa::RSAPublicKey::from_pkcs1(der).map_err(|err| X509CertError::PKCS1Decode(err)),
                _ => Err(X509CertError::ASN1MissingBlock)
            },
        _ => Err(X509CertError::ASN1MissingBlock)
    }
}
