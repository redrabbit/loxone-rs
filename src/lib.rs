//! Rust implementation of the Loxone™ communication protocol (Web Socket).

pub mod loxapp3;

mod ws;

pub use crate::ws::WebSocket;
pub use crate::ws::EventReceiver;

pub mod errors {
    pub use crate::ws::AuthenticationError;
    pub use crate::ws::JwtRequestError;
    pub use crate::ws::KeyExchangeError;
    pub use crate::ws::LoxAPP3RequestError;
    pub use crate::ws::RequestError;
    pub use crate::ws::X509CertError;
}