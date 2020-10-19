use crypto::digest::Digest;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

use futures_util::{future, StreamExt, SinkExt};
use futures_util::stream::{SplitSink, SplitStream};

use http::Request;

use rand::RngCore;
use rand::rngs::OsRng;

use rsa::{PublicKey, RSAPublicKey};

use thiserror::Error;

use tokio::net;

use tokio_tungstenite::{connect_async, tungstenite, WebSocketStream};

use tungstenite::Message;

pub struct WebSocket {
    tx: SplitSink<WebSocketStream<net::TcpStream>, Message>,
    rx: SplitStream<WebSocketStream<net::TcpStream>>,
    session: Option<Session>,
}

struct Session {
    session_key: Vec<u8>,
    rsa_key: [u8; 32],
    rsa_iv: [u8; 16],
    salt: [u8; 2],
}

#[derive(Error, Debug)]
pub enum X509CertError {
    #[error("pem error")]
    PemDecode(#[from] pem::PemError),
    #[error("asn1 decode error")]
    ASN1Decode(#[from] simple_asn1::ASN1DecodeErr),
    #[error("asn1 decode error")]
    ASN1MissingBlock,
    #[error("pkcs1 decode error")]
    PKCS1Decode(#[from] rsa::errors::Error),
    #[error("pkcs1 encrypt error")]
    PKCS1Encrypt(rsa::errors::Error)
}

impl WebSocket {
    /// Connects to the given uri.
    pub async fn connect(uri: http::uri::Uri) -> Result<(Self, tungstenite::handshake::client::Response), tungstenite::Error> {
        let request = Request::builder()
            .uri(uri)
            .header("Sec-WebSocket-protocol", "remotecontrol")
            .body(())?;

        let (ws_stream, resp) = connect_async(request).await?;
        let (tx, rx) = ws_stream.split();

        Ok((Self{tx, rx, session: None}, resp))
    }

    pub async fn key_exchange(&mut self, cert: &str) -> Result<String, tungstenite::Error> {
        self.session = Some(Session::new(cert).unwrap());

        let reply = self.send_recv(&format!("jdev/sys/keyexchange/{}", base64::encode_config(self.session.as_ref().unwrap(), base64::STANDARD_NO_PAD))).await?;
        let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();

        Ok(reply_json["LL"]["value"].as_str().unwrap().to_string())
    }

    async fn get_key(&mut self, user: &str) -> Result<serde_json::Map<String, serde_json::Value>, tungstenite::Error> {
        let reply = self.send_recv(&format!("jdev/sys/getkey2/{}", user)).await?;
        let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();

        Ok(reply_json["LL"]["value"].as_object().unwrap().clone())
    }

    pub async fn get_jwt(&mut self, user: &str, password: &str, permission: u8, uuid: &str, info: &str) -> Result<serde_json::Map<String, serde_json::Value>, tungstenite::Error> {
        let auth = self.get_key(user).await?;
        let hash = hash_pwd(user, password, &hex::decode(auth["key"].as_str().unwrap()).unwrap(), auth["salt"].as_str().unwrap(), auth["hashAlg"].as_str().unwrap());

        let reply = self.send_recv_enc(&format!("jdev/sys/getjwt/{}/{}/{}/{}/{}", hex::encode(hash), user, permission, uuid, info)).await?;
        let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply.replace("\r", "")).unwrap();

        Ok(reply_json["LL"]["value"].as_object().unwrap().clone())
    }

    pub async fn get_loxapp3_json(&mut self) -> Result<serde_json::Map<String, serde_json::Value>, tungstenite::Error> {
        let reply = self.send_recv("data/LoxAPP3.json").await?;
        let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();

        Ok(reply_json)
    }

    pub async fn get_loxapp3_timestamp(&mut self) -> Result<String, tungstenite::Error> {
        let reply = self.send_recv("jdev/sps/LoxAPPversion3").await?;
        let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();

        Ok(reply_json["LL"]["value"].as_str().unwrap().to_string())
    }

    async fn send_recv(&mut self, cmd: &str) -> Result<String, tungstenite::Error> {
        self.tx.send(Message::from(cmd)).await?;
        self.recv().await
    }

    async fn send_recv_enc(&mut self, cmd: &str) -> Result<String, tungstenite::Error> {
        self.send_recv(&encrypt_cmd_ws("enc", &cmd, self.session.as_ref().unwrap()).unwrap()).await
    }

    async fn recv(&mut self) -> Result<String, tungstenite::Error> {
        let mut rx_txt = self.rx
            .by_ref()
            .filter_map(|item| {
                if let Ok(Message::Text(msg_txt)) = item {
                    future::ready(Some(msg_txt))
                } else {
                    future::ready(None)
                }
            });

        rx_txt.next().await.ok_or(tungstenite::Error::Http(http::StatusCode::SERVICE_UNAVAILABLE))
    }
}

impl Session {
    fn new(cert: &str) -> Result<Self, X509CertError> {
        let public_key = parse_cert(cert)?;

        let mut rsa_key: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut rsa_key);

        let mut rsa_iv: [u8; 16] = [0; 16];
        OsRng.fill_bytes(&mut rsa_iv);

        let mut salt: [u8; 2] = [0; 2];
        OsRng.fill_bytes(&mut salt);

        let mut session_key_rng = rand::rngs::OsRng;
        let session_key_data = format!("{}:{}", hex::encode(rsa_key), hex::encode(rsa_iv));
        let session_key = public_key.encrypt(&mut session_key_rng, rsa::PaddingScheme::PKCS1v15Encrypt, session_key_data.as_bytes()).map_err(|err| X509CertError::PKCS1Encrypt(err))?;

        Ok(Self { session_key, rsa_key, rsa_iv, salt })
    }

}

impl std::convert::AsRef<[u8]> for Session {
    fn as_ref(&self) -> &[u8] {
        &self.session_key
    }
}

fn parse_cert(cert: &str) -> Result<RSAPublicKey, X509CertError> {
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

fn hash_pwd(user: &str, pwd: &str, key: &[u8], salt: &str, hash: &str) -> Vec<u8> {
    match hash {
        "SHA1" => {
            let mut hasher = Sha1::new();
            hasher.input_str(format!("{}:{}", pwd, salt).as_str());
            let password_hash = hasher.result_str().to_uppercase();

            let mut mac = Hmac::<Sha1>::new(Sha1::new(), key);
            mac.input(format!("{}:{}", user, password_hash).as_bytes());

            let mac_result = mac.result();
            mac_result.code().to_vec()
        }
        "SHA256" => {
            let mut hasher = Sha256::new();
            hasher.input_str(format!("{}:{}", pwd, salt).as_str());
            let password_hash = hasher.result_str().to_uppercase();

            let mut mac = Hmac::<Sha256>::new(Sha256::new(), key);
            mac.input(format!("{}:{}", user, password_hash).as_bytes());

            let mac_result = mac.result();
            mac_result.code().to_vec()
        },
        _ => panic!("Can only use SHA1 and SHA256 here.")
    }
}

fn encrypt_cmd(cmd: &str, session: &Session) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let salted_cmd = format!("salt/{}/{}", hex::encode(session.salt), cmd);

    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize256, &session.rsa_key, &session.rsa_iv, blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(salted_cmd.as_bytes());
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

fn encrypt_cmd_ws(endpoint: &str, cmd: &str, session: &Session) -> Result<String, symmetriccipher::SymmetricCipherError> {
    let encoded_cipher: String = url::form_urlencoded::byte_serialize(base64::encode_config(encrypt_cmd(cmd, session)?, base64::STANDARD_NO_PAD).as_bytes()).collect();
    Ok(format!("jdev/sys/{}/{}", endpoint, encoded_cipher))
}
