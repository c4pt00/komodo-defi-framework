use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value as Json;

/// Multi-purpose/generic event type that can easily be used over the event streaming
pub struct Event {
    /// The type of the event (balance, network, swap, etc...).
    event_type: String,
    /// The message to be sent to the client.
    message: Json,
    /// The filter object to be used to determine whether the event should be sent or not.
    /// It could also alter the event content
    ///
    /// The filter is wrapped in an `Arc` since the event producer should use it as a singleton
    /// by using the same filter over and over again with multiple events.
    filter: Option<Arc<dyn Filter>>,
}

impl Event {
    /// Creates a new `Event` instance with the specified event type and message.
    #[inline]
    pub fn new(event_type: String, message: Json, filter: Option<Arc<dyn Filter>>) -> Self {
        Self {
            event_type,
            message,
            filter,
        }
    }

    /// Create a new error `Event` instance with the specified error event type and message.
    #[inline]
    pub fn err(event_type: String, message: Json, filter: Option<Arc<dyn Filter>>) -> Self {
        Self {
            event_type: format!("ERROR_{event_type}"),
            message,
            filter,
        }
    }

    /// Returns the event type and message to be sent or `None` if the event should not be sent.
    ///
    /// Uses the `requested_events` to determine whether the event should be sent or not.
    /// If `requested_events` is empty, this doesn't mean the event won't be sent, this is
    /// decided by the event's filtering mechanism.
    ///
    /// `requested_events` could also be used to alter the event content (e.g. remove certain fields)
    pub fn get_data(&self, requested_events: &HashSet<String>) -> Option<(String, Json)> {
        self.filter.as_ref().map_or_else(
            // If no filter is set, send the event as is.
            || Some((self.event_type.clone(), self.message.clone())),
            |filter| {
                filter
                    .filter(&self.message, requested_events)
                    .map(|message| (self.event_type.clone(), message))
            },
        )
    }
}

/// A trait that defines the filtering mechanism for events.
///
/// Each event has a filter that determines whether the event should be send out
/// to the client or not based on the client's requested events.
pub trait Filter: Send + Sync {
    /// Filters the event based on the requested events.
    ///
    /// Returns the (maybe altered) message to be sent or `None` if the event should not be sent.
    /// `requested_events` is a set of the events that the client asked to subscribe to (e.g. `BALANCE:BTC`)
    fn filter(&self, message: &Json, requested_events: &HashSet<String>) -> Option<Json>;
}

/// Event types streamed to clients through channels like Server-Sent Events (SSE).
#[derive(Deserialize, Eq, Hash, PartialEq)]
pub enum EventName {
    /// Indicates a change in the balance of a coin.
    BALANCE,
    /// Event triggered at regular intervals to indicate that the system is operational.
    HEARTBEAT,
    /// Returns p2p network information at a regular interval.
    NETWORK,
}

impl fmt::Display for EventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BALANCE => write!(f, "COIN_BALANCE"),
            Self::HEARTBEAT => write!(f, "HEARTBEAT"),
            Self::NETWORK => write!(f, "NETWORK"),
        }
    }
}