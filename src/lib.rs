//! Rust implementation of the Loxone™ communication protocol (Web Socket).

mod loxapp3;
mod ws;


/// Universally Unique Identifier (UUID).
pub type LoxoneUUID = String;

pub use ws::WebSocket;
pub use ws::EventSubscriber;
pub use ws::DaytimerEntry;
pub use ws::WeatherEntry;
pub use ws::Event;

pub use loxapp3::LoxoneApp3;

pub mod errors {
    pub use crate::ws::AuthenticationError;
    pub use crate::ws::JwtRequestError;
    pub use crate::ws::KeyExchangeError;
    pub use crate::ws::LoxAPP3RequestError;
    pub use crate::ws::RequestError;
    pub use crate::ws::X509CertError;
}