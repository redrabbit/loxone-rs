#![allow(dead_code)]

use tokio::stream::Stream;
use crypto::digest::Digest;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

use futures_util::{future, StreamExt, SinkExt};
use futures_util::stream::{self, SplitSink};

use http::Request;

use rand::RngCore;
use rand::rngs::OsRng;

use rsa::{PublicKey, RSAPublicKey};

use std::convert::TryInto;

use thiserror::Error;

use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{connect_async, tungstenite, WebSocketStream};

pub struct WebSocket {
    session: Option<Session>,
    rx: mpsc::UnboundedReceiver<LoxoneMessage>,
    sink: SplitSink<WebSocketStream<TcpStream>, tungstenite::Message>,
}

struct Session {
    rsa_key: [u8; 32],
    rsa_iv: [u8; 16],
    salt: [u8; 2],
    session_key: Vec<u8>,
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

#[derive(Debug)]
enum LoxoneMessage {
    Text(String),
    BinaryText(String),
    BinaryFile(Vec<u8>),
    EventTable(EventTable),
    OutOfServiceIndicator,
    KeepAlive,
}

#[derive(Debug)]
struct ValueEvent(String, f64);
#[derive(Debug)]
struct TextEvent(String, String, String);
#[derive(Debug)]
struct DaytimerEvent(String, f64, Vec<DaytimerEntry>);
#[derive(Debug)]
struct WeatherEvent(String, u32, Vec<WeatherEntry>);

#[derive(Debug)]
pub enum Event {
    Value(String, f64),
    Text(String, String, String),
    Daytimer(String, f64, Vec<DaytimerEntry>),
    Weather(String, u32, Vec<WeatherEntry>),
}

#[derive(Debug)]
enum EventTable {
    ValueEvents(Vec<ValueEvent>),
    TextEvents(Vec<TextEvent>),
    DaytimerEvents(Vec<DaytimerEvent>),
    WeatherEvents(Vec<WeatherEvent>),
}

#[derive(Debug)]
pub struct DaytimerEntry {
    mode: i32,
    from: i32,
    to: i32,
    need_activate: i32,
    value: f64,
}

#[derive(Debug)]
pub struct WeatherEntry {
    timestamp: i32,
    weather_type: i32,
    wind_direction: i32,
    solar_radiation: i32,
    relative_humidity: i32,
    temperature: f64,
    perceived_temperature: f64,
    dew_point: f64,
    precipitation: f64,
    wind_speed: f64,
    barometic_pressure: f64,
}

pub struct EventReceiver {
    rx: mpsc::UnboundedReceiver<EventTable>
}

impl WebSocket {
    /// Connects to the given uri.
    pub async fn connect(uri: http::uri::Uri) -> Result<(Self, tungstenite::handshake::client::Response, EventReceiver, impl future::Future<Output = ()>), tungstenite::Error> {
        let request = Request::builder()
            .uri(uri)
            .header("Sec-WebSocket-protocol", "remotecontrol")
            .body(())?;

        let (ws_stream, resp) = connect_async(request).await?;
        let (sink, stream) = ws_stream.split();
        let (tx, rx) = mpsc::unbounded_channel();
        let (tx_events, rx_events) = mpsc::unbounded_channel();

        Ok((Self{sink, rx, session: None}, resp, EventReceiver::new(rx_events), Self::recv_loop(tx, tx_events, stream)))
    }

    pub async fn key_exchange(&mut self, cert: &str) -> Result<Vec<u8>, tungstenite::Error> {
        self.session = Some(Session::new(cert).unwrap());
        match self.send_recv(&format!("jdev/sys/keyexchange/{}", base64::encode_config(self.session.as_ref().unwrap(), base64::STANDARD_NO_PAD))).await? {
            LoxoneMessage::Text(reply) => {
                let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();
                Ok(base64::decode(reply_json["LL"]["value"].as_str().unwrap()).unwrap())
            },
            reply => panic!("invalid reply type #{:?}", reply)
        }
    }

    async fn get_key(&mut self, user: &str) -> Result<serde_json::Map<String, serde_json::Value>, tungstenite::Error> {
        match self.send_recv(&format!("jdev/sys/getkey2/{}", user)).await? {
            LoxoneMessage::Text(reply) => {
                let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();
                Ok(reply_json["LL"]["value"].as_object().unwrap().clone())
            },
            reply => panic!("invalid reply type #{:?}", reply)
        }
    }

    pub async fn get_jwt(&mut self, user: &str, password: &str, permission: u8, uuid: &str, info: &str) -> Result<serde_json::Map<String, serde_json::Value>, tungstenite::Error> {
        let auth = self.get_key(user).await?;
        let hash = hash_pwd(user, password, &hex::decode(auth["key"].as_str().unwrap()).unwrap(), auth["salt"].as_str().unwrap(), auth["hashAlg"].as_str().unwrap());
        match self.send_recv_enc(&format!("jdev/sys/getjwt/{}/{}/{}/{}/{}", hex::encode(hash), user, permission, uuid, info)).await? {
            LoxoneMessage::Text(reply) => {
                let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply.replace("\r", "")).unwrap();
                Ok(reply_json["LL"]["value"].as_object().unwrap().clone())
            },
            reply => panic!("invalid reply type #{:?}", reply)
        }
    }

    pub async fn get_loxapp3_json(&mut self) -> Result<serde_json::Map<String, serde_json::Value>, tungstenite::Error> {
        match self.send_recv("data/LoxAPP3.json").await? {
            LoxoneMessage::BinaryText(reply) => {
                let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();
                Ok(reply_json)
            },
            reply => panic!("invalid reply type #{:?}", reply)
        }
    }

    pub async fn get_loxapp3_timestamp(&mut self) -> Result<String, tungstenite::Error> {
        match self.send_recv("jdev/sps/LoxAPPversion3").await? {
            LoxoneMessage::Text(reply) => {
                let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();
                Ok(reply_json["LL"]["value"].as_str().unwrap().to_string())
            },
            reply => panic!("invalid reply type #{:?}", reply)
        }
    }

    pub async fn enable_status_update(&mut self, mut event_rx: EventReceiver) -> Result<(Vec<Event>, impl Stream<Item=Event>), tungstenite::Error> {
        match self.send_recv("jdev/sps/enablebinstatusupdate").await? {
            LoxoneMessage::Text(reply) => {
                let reply_json: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&reply).unwrap();
                assert_eq!(reply_json["LL"]["value"].as_str().unwrap().parse::<u8>().unwrap(), 1);
                let initial_state = event_rx.rx.by_ref().take(4).map(|event_table| event_table.into()).concat().await;
                let stream = event_rx.rx.flat_map(|event_table|stream::iter::<Vec<Event>>(event_table.into()));
                Ok((initial_state, stream))
            },
            reply => panic!("invalid reply type #{:?}", reply)
        }
    }

    async fn send_recv(&mut self, cmd: &str) -> Result<LoxoneMessage, tungstenite::Error> {
        self.sink.send(tungstenite::Message::from(cmd)).await?;
        self.recv().await
    }

    async fn send_recv_enc(&mut self, cmd: &str) -> Result<LoxoneMessage, tungstenite::Error> {
        self.send_recv(&encrypt_cmd_ws("enc", &cmd, self.session.as_ref().unwrap()).unwrap()).await
    }

    async fn recv(&mut self) -> Result<LoxoneMessage, tungstenite::Error> {
        Ok(self.rx.recv().await.unwrap())
    }

    async fn recv_loop<S: StreamExt<Item=Result<tungstenite::Message, tungstenite::Error>> + Unpin>(tx: mpsc::UnboundedSender<LoxoneMessage>, tx_events: mpsc::UnboundedSender<EventTable>, stream: S) {
        let mut stream = stream.filter_map(|item| future::ready(item.ok()));
        while let Ok(msg) = parse_msg_next(&mut stream).await {
            match msg {
                LoxoneMessage::KeepAlive => println!("KEEP ALIVE"),
                LoxoneMessage::OutOfServiceIndicator => println!("OUT OF SERVICE"),
                LoxoneMessage::EventTable(event_table) => tx_events.send(event_table).unwrap(),
                _ => tx.send(msg).unwrap()
            }
        }
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

impl AsRef<[u8]> for Session {
    fn as_ref(&self) -> &[u8] {
        &self.session_key
    }
}

impl From<ValueEvent> for Event {
    fn from(event: ValueEvent) -> Self { Self::Value(event.0, event.1) }
}

impl From<TextEvent> for Event {
    fn from(event: TextEvent) -> Self { Self::Text(event.0, event.1, event.2) }
}

impl From<DaytimerEvent> for Event {
    fn from(event: DaytimerEvent) -> Self { Self::Daytimer(event.0, event.1, event.2) }
}

impl From<WeatherEvent> for Event {
    fn from(event: WeatherEvent) -> Self { Self::Weather(event.0, event.1, event.2) }
}

impl Into<Vec<Event>> for EventTable {
    fn into(self) -> Vec<Event> {
        match self { // TODO
            Self::ValueEvents(events) => events.into_iter().map(From::from).collect(),
            Self::TextEvents(events) => events.into_iter().map(From::from).collect(),
            Self::DaytimerEvents(events) => events.into_iter().map(From::from).collect(),
            Self::WeatherEvents(events) => events.into_iter().map(From::from).collect(),
        }
    }
}

impl EventReceiver {
    fn new(rx: mpsc::UnboundedReceiver<EventTable>) -> Self {
        Self{ rx }
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

async fn parse_msg_next<S: StreamExt<Item=tungstenite::Message> + Unpin>(stream: &mut S) -> Result<LoxoneMessage, tungstenite::Error> {
    match parse_msg_header(stream.next().await.unwrap()) {
        (msg_type, Some(msg_len)) =>
            Ok(parse_msg_body(msg_type, msg_len, stream).await),
        (msg_type, None) =>
            Ok(parse_msg_body(msg_type, parse_msg_len(stream.next().await.unwrap()), stream).await)
    }
}

fn parse_msg_header(header_msg: tungstenite::Message) -> (u8, Option<usize>) {
    assert!(header_msg.is_binary());
    let header = header_msg.into_data();
    assert_eq!(header[0], 0x03);
    match header[2] {
        0x00 => (header[1], Some(u32::from_le_bytes(header[4..].try_into().unwrap()).try_into().unwrap())),
        _ => (header[1], None)
    }
}

fn parse_msg_len(header_msg: tungstenite::Message) -> usize {
    let header = header_msg.into_data();
    u32::from_le_bytes(header[4..].try_into().unwrap()).try_into().unwrap()
}

async fn parse_msg_body<S: StreamExt<Item=tungstenite::Message> + Unpin>(msg_type: u8, msg_len: usize, stream: &mut S) -> LoxoneMessage {
    match msg_type {
        0x00 => {
            let body_msg = stream.next().await.unwrap();
            assert_eq!(body_msg.len(), msg_len);
            assert!(body_msg.is_text());
            LoxoneMessage::Text(body_msg.into_text().unwrap())
        },
        0x01 => {
            let body_msg = stream.next().await.unwrap();
            assert_eq!(body_msg.len(), msg_len);
            if body_msg.is_text() {
                LoxoneMessage::BinaryText(body_msg.into_text().unwrap())
            } else {
                LoxoneMessage::BinaryFile(body_msg.into_data())
            }
        }
        0x02 => { // TODO
            let body_msg = stream.next().await.unwrap();
            assert_eq!(body_msg.len(), msg_len);
            assert!(body_msg.is_binary());
            let pack = body_msg.into_data();
            let mut events: Vec<ValueEvent> = Vec::new();
            let mut n = 0;
            while n < pack.len() {
                let uuid = parse_uuid(&pack[n..n+16]);
                n += 16;
                let val = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                n += 8;
                events.push(ValueEvent(uuid, val));
            }
            LoxoneMessage::EventTable(EventTable::ValueEvents(events))
        },
        0x03 => { // TODO
            let body_msg = stream.next().await.unwrap();
            assert_eq!(body_msg.len(), msg_len);
            assert!(body_msg.is_binary());
            let pack = body_msg.into_data();
            let mut events: Vec<TextEvent> = Vec::new();
            let mut n = 0;
            while n < pack.len() {
                let uuid = parse_uuid(&pack[n..n+16]);
                n += 16;
                let uuid_icon = parse_uuid(&pack[n..n+16]);
                n += 16;
                let text_len: usize = u32::from_le_bytes(pack[n..n+4].try_into().unwrap()).try_into().unwrap();
                n += 4;
                let text = String::from_utf8_lossy(&pack[n..n+text_len]).to_string();
                n += text_len;
                match text_len % 4 {
                    0 => (),
                    r => (n += 4 - r)
                }
                events.push(TextEvent(uuid, uuid_icon, text));
            }
            LoxoneMessage::EventTable(EventTable::TextEvents(events))
        }
        0x04 => { // TODO
            let body_msg = stream.next().await.unwrap();
            assert!(body_msg.is_binary());
            let pack = body_msg.into_data();
            let mut events: Vec<DaytimerEvent> = Vec::new();
            let mut n = 0;
            while n < pack.len() {
                let uuid = parse_uuid(&pack[n..n+16]);
                n += 16;
                let default_val = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                n += 8;
                let entries_len: usize = i32::from_le_bytes(pack[n..n+4].try_into().unwrap()).try_into().unwrap();
                n += 4;
                let mut entries: Vec<DaytimerEntry> = Vec::new();
                for _ in 0..entries_len {
                    let mode = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let from = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let to = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let need_activate = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let value = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                    n += 8;
                    entries.push(DaytimerEntry{
                        mode,
                        from,
                        to,
                        need_activate,
                        value
                    })
                }
                events.push(DaytimerEvent(uuid, default_val, entries))
            }
            LoxoneMessage::EventTable(EventTable::DaytimerEvents(events))
        },
        0x05 => LoxoneMessage::OutOfServiceIndicator,
        0x06 => LoxoneMessage::KeepAlive,
        0x07 => { // TODO
            let body_msg = stream.next().await.unwrap();
            assert!(body_msg.is_binary());
            let pack = body_msg.into_data();
            let mut events: Vec<WeatherEvent> = Vec::new();
            let mut n = 0;
            while n < pack.len() {
                let uuid = parse_uuid(&pack[n..n+16]);
                n += 16;
                let last_update = u32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                n += 4;
                let entries_len: usize = i32::from_le_bytes(pack[n..n+4].try_into().unwrap()).try_into().unwrap();
                n += 4;
                let mut entries: Vec<WeatherEntry> = Vec::new();
                for _ in 0..entries_len {
                    let timestamp = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let weather_type = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let wind_direction = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let solar_radiation = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let relative_humidity = i32::from_le_bytes(pack[n..n+4].try_into().unwrap());
                    n += 4;
                    let temperature = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                    n += 8;
                    let perceived_temperature = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                    n += 8;
                    let dew_point = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                    n += 8;
                    let precipitation = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                    n += 8;
                    let wind_speed = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                    n += 8;
                    let barometic_pressure = f64::from_le_bytes(pack[n..n+8].try_into().unwrap());
                    n += 8;
                    entries.push(WeatherEntry{
                        timestamp,
                        weather_type,
                        wind_direction,
                        solar_radiation,
                        relative_humidity,
                        temperature,
                        perceived_temperature,
                        dew_point,
                        precipitation,
                        wind_speed,
                        barometic_pressure
                    })
                }
                events.push(WeatherEvent(uuid, last_update, entries))
            }
            LoxoneMessage::EventTable(EventTable::WeatherEvents(events))
        },
        bad_identifier => panic!("unknown message identifier {}", bad_identifier)
    }
}

fn parse_uuid(pack: &[u8]) -> String {
    let d1 = u32::from_le_bytes(pack[..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(pack[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(pack[6..8].try_into().unwrap());
    let d4 = &pack[8..16];
    format!("{:08x}-{:04x}-{:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7])
}
