//! End-to-end exercise of the signaling WebSocket flow.
//!
//! These drive a real server over a real socket, because the parts most likely
//! to break silently are the ordering of the handshake and the relay
//! authorisation, neither of which the unit tests can observe.

use futures_util::{SinkExt, StreamExt};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};
use waypad_signal::{
    auth,
    registry::{Limits, Registry},
    server,
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start_server() -> SocketAddr {
    let registry = Registry::new(Limits::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            server::router(registry).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    address
}

async fn connect(address: SocketAddr) -> Socket {
    let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
        .await
        .unwrap();
    socket
}

async fn send(socket: &mut Socket, value: serde_json::Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}

async fn recv(socket: &mut Socket) -> serde_json::Value {
    loop {
        let message = socket.next().await.unwrap().unwrap();
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

struct Host {
    key: EcdsaKeyPair,
    public_key: Vec<u8>,
    fingerprint: String,
}

fn host_identity() -> Host {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public_key = key.public_key().as_ref().to_vec();
    let fingerprint = auth::fingerprint(&public_key);
    Host {
        key,
        public_key,
        fingerprint,
    }
}

/// Runs the full register → challenge → proof handshake.
async fn register(socket: &mut Socket, host: &Host) {
    assert_eq!(recv(socket).await["type"], "welcome");
    send(
        socket,
        serde_json::json!({
            "type": "register",
            "fingerprint": host.fingerprint,
            "public_key": auth::encode(&host.public_key),
        }),
    )
    .await;

    let challenge = recv(socket).await;
    assert_eq!(challenge["type"], "challenge");
    let nonce = auth::decode(challenge["nonce"].as_str().unwrap(), "nonce").unwrap();

    let transcript = auth::register_transcript(&host.fingerprint, &nonce);
    let signature = host.key.sign(&SystemRandom::new(), &transcript).unwrap();
    send(
        socket,
        serde_json::json!({
            "type": "register_proof",
            "signature": auth::encode(signature.as_ref()),
        }),
    )
    .await;

    let registered = recv(socket).await;
    assert_eq!(registered["type"], "registered");
}

#[tokio::test]
async fn relays_an_offer_and_answer_between_host_and_phone() {
    let address = start_server().await;
    let host = host_identity();

    let mut host_socket = connect(address).await;
    register(&mut host_socket, &host).await;

    let mut phone = connect(address).await;
    assert_eq!(recv(&mut phone).await["type"], "welcome");
    send(
        &mut phone,
        serde_json::json!({"type": "connect", "fingerprint": host.fingerprint}),
    )
    .await;

    let connected = recv(&mut phone).await;
    assert_eq!(connected["type"], "connected");
    let session = connected["session"].as_str().unwrap().to_string();

    let joined = recv(&mut host_socket).await;
    assert_eq!(joined["type"], "peer_joined");
    assert_eq!(joined["session"], session);

    // Phone → host (the SDP offer).
    send(
        &mut phone,
        serde_json::json!({
            "type": "signal",
            "session": session,
            "payload": {"sdp": "v=0 offer"},
        }),
    )
    .await;
    let forwarded = recv(&mut host_socket).await;
    assert_eq!(forwarded["type"], "signal");
    assert_eq!(forwarded["payload"]["sdp"], "v=0 offer");

    // Host → phone (the SDP answer).
    send(
        &mut host_socket,
        serde_json::json!({
            "type": "signal",
            "session": session,
            "payload": {"sdp": "v=0 answer"},
        }),
    )
    .await;
    let forwarded = recv(&mut phone).await;
    assert_eq!(forwarded["type"], "signal");
    assert_eq!(forwarded["payload"]["sdp"], "v=0 answer");
}

#[tokio::test]
async fn rejects_a_fingerprint_the_caller_cannot_prove() {
    let address = start_server().await;
    let honest = host_identity();
    let attacker = host_identity();

    let mut socket = connect(address).await;
    assert_eq!(recv(&mut socket).await["type"], "welcome");

    // Claim the honest host's fingerprint while presenting your own key.
    send(
        &mut socket,
        serde_json::json!({
            "type": "register",
            "fingerprint": honest.fingerprint,
            "public_key": auth::encode(&attacker.public_key),
        }),
    )
    .await;

    let response = recv(&mut socket).await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["reason"], "fingerprint_mismatch");
}

#[tokio::test]
async fn rejects_a_proof_signed_by_the_wrong_key() {
    let address = start_server().await;
    let host = host_identity();
    let attacker = host_identity();

    let mut socket = connect(address).await;
    assert_eq!(recv(&mut socket).await["type"], "welcome");
    send(
        &mut socket,
        serde_json::json!({
            "type": "register",
            "fingerprint": host.fingerprint,
            "public_key": auth::encode(&host.public_key),
        }),
    )
    .await;
    let challenge = recv(&mut socket).await;
    let nonce = auth::decode(challenge["nonce"].as_str().unwrap(), "nonce").unwrap();

    // Sign the right transcript with the wrong private key.
    let transcript = auth::register_transcript(&host.fingerprint, &nonce);
    let signature = attacker
        .key
        .sign(&SystemRandom::new(), &transcript)
        .unwrap();
    send(
        &mut socket,
        serde_json::json!({
            "type": "register_proof",
            "signature": auth::encode(signature.as_ref()),
        }),
    )
    .await;

    let response = recv(&mut socket).await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["reason"], "bad_signature");
}

#[tokio::test]
async fn connecting_to_an_offline_host_reports_it() {
    let address = start_server().await;
    let mut phone = connect(address).await;
    assert_eq!(recv(&mut phone).await["type"], "welcome");
    send(
        &mut phone,
        serde_json::json!({"type": "connect", "fingerprint": "aaaa:bbbb"}),
    )
    .await;

    let response = recv(&mut phone).await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["reason"], "host_offline");
}

#[tokio::test]
async fn a_third_party_cannot_inject_into_a_session() {
    let address = start_server().await;
    let host = host_identity();
    let mut host_socket = connect(address).await;
    register(&mut host_socket, &host).await;

    let mut phone = connect(address).await;
    assert_eq!(recv(&mut phone).await["type"], "welcome");
    send(
        &mut phone,
        serde_json::json!({"type": "connect", "fingerprint": host.fingerprint}),
    )
    .await;
    let session = recv(&mut phone).await["session"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(recv(&mut host_socket).await["type"], "peer_joined");

    // An unrelated connection that somehow learned the session id.
    let mut intruder = connect(address).await;
    assert_eq!(recv(&mut intruder).await["type"], "welcome");
    send(
        &mut intruder,
        serde_json::json!({"type": "connect", "fingerprint": host.fingerprint}),
    )
    .await;
    assert_eq!(recv(&mut intruder).await["type"], "connected");
    assert_eq!(recv(&mut host_socket).await["type"], "peer_joined");

    send(
        &mut intruder,
        serde_json::json!({
            "type": "signal",
            "session": session,
            "payload": {"sdp": "malicious"},
        }),
    )
    .await;

    let response = recv(&mut intruder).await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["reason"], "not_a_session_member");
}

#[tokio::test]
async fn the_host_learns_when_the_phone_disappears() {
    let address = start_server().await;
    let host = host_identity();
    let mut host_socket = connect(address).await;
    register(&mut host_socket, &host).await;

    let mut phone = connect(address).await;
    assert_eq!(recv(&mut phone).await["type"], "welcome");
    send(
        &mut phone,
        serde_json::json!({"type": "connect", "fingerprint": host.fingerprint}),
    )
    .await;
    assert_eq!(recv(&mut phone).await["type"], "connected");
    assert_eq!(recv(&mut host_socket).await["type"], "peer_joined");

    drop(phone);

    let notice = recv(&mut host_socket).await;
    assert_eq!(notice["type"], "peer_left");
    assert_eq!(notice["reason"], "peer_disconnected");
}

#[tokio::test]
async fn signalling_before_identifying_is_refused() {
    let address = start_server().await;
    let mut socket = connect(address).await;
    assert_eq!(recv(&mut socket).await["type"], "welcome");
    send(
        &mut socket,
        serde_json::json!({
            "type": "signal",
            "session": "whatever",
            "payload": {},
        }),
    )
    .await;

    let response = recv(&mut socket).await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["reason"], "not_identified");
}
