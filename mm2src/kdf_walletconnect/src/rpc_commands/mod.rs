mod delete_connection;
mod get_chain_id;
mod get_session;
mod new_connection;
mod ping;

pub use delete_connection::delete_connection;
pub use get_chain_id::get_chain_id;
pub use get_session::get_session;
pub use new_connection::new_connection;
pub use ping::ping_session;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct EmptyRpcRequst {}
