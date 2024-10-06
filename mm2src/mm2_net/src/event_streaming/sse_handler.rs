use hyper::{body::Bytes, Body, Request, Response};
use mm2_core::mm_ctx::MmArc;
use serde_json::json;
use std::convert::Infallible;

pub const SSE_ENDPOINT: &str = "/event-stream";

/// Handles broadcasted messages from `mm2_event_stream` continuously.
pub async fn handle_sse(request: Request<Body>, ctx_h: u32) -> Result<Response<Body>, Infallible> {
    let ctx = match MmArc::from_ffi_handle(ctx_h) {
        Ok(ctx) => ctx,
        Err(err) => return handle_internal_error(err).await,
    };

    let event_streaming_config = ctx.event_streaming_configuration();
    if event_streaming_config.disabled {
        return handle_internal_error("Event streaming is explicitly disabled".to_string()).await;
    }

    let client_id = match request.uri().query().and_then(|query| {
        query
            .split('&')
            .find(|param| param.starts_with("id="))
            .map(|id_param| id_param.trim_start_matches("id=").parse::<u64>())
    }) {
        Some(Ok(id)) => id,
        // Default to zero when client ID isn't passed, most of the cases we will have a single user/client.
        _ => 0,
    };

    let event_stream_manager = ctx.event_stream_manager.clone();
    let Ok(mut rx) = event_stream_manager.new_client(client_id) else {
        // FIXME: Such an error means that one client generated an id that is already in use
        // by another (or it might be the same client all along). This is dangerous since
        // that client now knows this id is in use and can open up and shut down streamers
        // on the original id owner's behalf.
        return handle_internal_error(format!("Bad id")).await
    };
    let body = Body::wrap_stream(async_stream::stream! {
        while let Some(event) = rx.recv().await {
            // The event's filter will decide whether to expose the event data to this client or not.
            // This happens based on the events that this client has subscribed to.
            let (event_type, message) = event.get();
            let data = json!({
                "_type": event_type,
                "message": message,
            });

            yield Ok::<_, hyper::Error>(Bytes::from(format!("data: {data} \n\n")));
        }
        // Inform the event stream manager that the client has disconnected.
        event_stream_manager.remove_client(client_id).ok();
    });

    let response = Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header(
            "Access-Control-Allow-Origin",
            event_streaming_config.access_control_allow_origin,
        )
        .body(body);

    match response {
        Ok(res) => Ok(res),
        Err(err) => handle_internal_error(err.to_string()).await,
    }
}

/// Fallback function for handling errors in SSE connections
async fn handle_internal_error(message: String) -> Result<Response<Body>, Infallible> {
    let response = Response::builder()
        .status(500)
        .body(Body::from(message))
        .expect("Returning 500 should never fail.");

    Ok(response)
}
