//! Shared state: which hosts are online and which sessions are relaying.
//!
//! A session always has exactly two ends, a host and a peer. Relay
//! authorisation is decided purely by connection identity: a connection may
//! only forward into a session it is actually one end of, so a third party that
//! guesses a session id cannot inject or read anything.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;
use tracing::{debug, info};
use uuid::Uuid;

use crate::protocol::ServerMessage;

pub type Sender = mpsc::UnboundedSender<ServerMessage>;

/// Identifies one WebSocket connection for the lifetime of that socket.
pub type ConnectionId = Uuid;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_sessions_per_host: usize,
    pub max_hosts: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions_per_host: 8,
            max_hosts: 512,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("host_offline")]
    HostOffline,
    #[error("host_busy")]
    HostBusy,
    #[error("server_full")]
    ServerFull,
    #[error("unknown_session")]
    UnknownSession,
    #[error("not_a_session_member")]
    NotAMember,
}

struct HostEntry {
    connection: ConnectionId,
    tx: Sender,
    sessions: HashSet<String>,
}

struct Session {
    host_fingerprint: String,
    host_connection: ConnectionId,
    host_tx: Sender,
    peer_connection: ConnectionId,
    peer_tx: Sender,
}

#[derive(Default)]
struct State {
    hosts: HashMap<String, HostEntry>,
    sessions: HashMap<String, Session>,
}

pub struct Registry {
    state: Mutex<State>,
    limits: Limits,
}

impl Registry {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            limits,
        })
    }

    /// Publishes a host under its fingerprint. A second registration for the
    /// same fingerprint replaces the first: the daemon may legitimately
    /// reconnect before the server noticed the old socket was dead.
    pub fn register_host(
        &self,
        fingerprint: &str,
        connection: ConnectionId,
        tx: Sender,
    ) -> Result<(), RegistryError> {
        let mut state = self.lock();
        let replacing = state.hosts.contains_key(fingerprint);
        if !replacing && state.hosts.len() >= self.limits.max_hosts {
            return Err(RegistryError::ServerFull);
        }
        if replacing {
            self.drop_host_locked(&mut state, fingerprint, "replaced_by_new_registration");
        }
        state.hosts.insert(
            fingerprint.to_string(),
            HostEntry {
                connection,
                tx,
                sessions: HashSet::new(),
            },
        );
        info!(%fingerprint, %connection, replacing, "host registered");
        Ok(())
    }

    /// Opens a session between a waiting host and a newly arrived peer.
    pub fn open_session(
        &self,
        fingerprint: &str,
        peer_connection: ConnectionId,
        peer_tx: Sender,
    ) -> Result<String, RegistryError> {
        let mut state = self.lock();
        let host = state
            .hosts
            .get(fingerprint)
            .ok_or(RegistryError::HostOffline)?;
        if host.sessions.len() >= self.limits.max_sessions_per_host {
            return Err(RegistryError::HostBusy);
        }
        let host_tx = host.tx.clone();
        let host_connection = host.connection;
        let session_id = Uuid::new_v4().to_string();

        state.sessions.insert(
            session_id.clone(),
            Session {
                host_fingerprint: fingerprint.to_string(),
                host_connection,
                host_tx: host_tx.clone(),
                peer_connection,
                peer_tx,
            },
        );
        if let Some(host) = state.hosts.get_mut(fingerprint) {
            host.sessions.insert(session_id.clone());
        }
        drop(state);

        let _ = host_tx.send(ServerMessage::PeerJoined {
            session: session_id.clone(),
        });
        info!(%fingerprint, session = %session_id, "session opened");
        Ok(session_id)
    }

    /// Forwards an opaque payload to the other end of a session.
    pub fn relay(
        &self,
        session_id: &str,
        from: ConnectionId,
        payload: serde_json::Value,
    ) -> Result<(), RegistryError> {
        let state = self.lock();
        let session = state
            .sessions
            .get(session_id)
            .ok_or(RegistryError::UnknownSession)?;
        let target = if from == session.host_connection {
            &session.peer_tx
        } else if from == session.peer_connection {
            &session.host_tx
        } else {
            return Err(RegistryError::NotAMember);
        };
        let _ = target.send(ServerMessage::Signal {
            session: session_id.to_string(),
            payload,
        });
        Ok(())
    }

    /// Tears down one session and tells the surviving end why.
    pub fn close_session(&self, session_id: &str, from: Option<ConnectionId>, reason: &str) {
        let mut state = self.lock();
        let Some(session) = state.sessions.get(session_id) else {
            return;
        };
        if let Some(from) = from
            && from != session.host_connection
            && from != session.peer_connection
        {
            return;
        }
        let session = state.sessions.remove(session_id).expect("just looked up");
        if let Some(host) = state.hosts.get_mut(&session.host_fingerprint) {
            host.sessions.remove(session_id);
        }
        drop(state);

        let notice = ServerMessage::PeerLeft {
            session: session_id.to_string(),
            reason: reason.to_string(),
        };
        let _ = session.host_tx.send(notice.clone());
        let _ = session.peer_tx.send(notice);
        debug!(session = %session_id, reason, "session closed");
    }

    /// Cleans up everything owned by a socket that just went away.
    pub fn drop_connection(&self, connection: ConnectionId) {
        let mut state = self.lock();
        let owned_host: Option<String> = state
            .hosts
            .iter()
            .find(|(_, host)| host.connection == connection)
            .map(|(fingerprint, _)| fingerprint.clone());
        if let Some(fingerprint) = owned_host {
            self.drop_host_locked(&mut state, &fingerprint, "host_disconnected");
            info!(%fingerprint, "host unregistered");
        }

        let peer_sessions: Vec<String> = state
            .sessions
            .iter()
            .filter(|(_, session)| session.peer_connection == connection)
            .map(|(id, _)| id.clone())
            .collect();
        for session_id in peer_sessions {
            let Some(session) = state.sessions.remove(&session_id) else {
                continue;
            };
            if let Some(host) = state.hosts.get_mut(&session.host_fingerprint) {
                host.sessions.remove(&session_id);
            }
            let _ = session.host_tx.send(ServerMessage::PeerLeft {
                session: session_id,
                reason: "peer_disconnected".into(),
            });
        }
    }

    /// Removes a host and drops every session hanging off it.
    fn drop_host_locked(&self, state: &mut State, fingerprint: &str, reason: &str) {
        let Some(host) = state.hosts.remove(fingerprint) else {
            return;
        };
        for session_id in host.sessions {
            if let Some(session) = state.sessions.remove(&session_id) {
                let _ = session.peer_tx.send(ServerMessage::PeerLeft {
                    session: session_id,
                    reason: reason.to_string(),
                });
            }
        }
    }

    pub fn host_count(&self) -> usize {
        self.lock().hosts.len()
    }

    pub fn session_count(&self) -> usize {
        self.lock().sessions.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> (Sender, mpsc::UnboundedReceiver<ServerMessage>) {
        mpsc::unbounded_channel()
    }

    #[test]
    fn opening_a_session_notifies_the_host() {
        let registry = Registry::new(Limits::default());
        let (host_tx, mut host_rx) = channel();
        let host_conn = Uuid::new_v4();
        registry.register_host("fp", host_conn, host_tx).unwrap();

        let (peer_tx, _peer_rx) = channel();
        let session = registry
            .open_session("fp", Uuid::new_v4(), peer_tx)
            .unwrap();

        let message = host_rx.try_recv().unwrap();
        assert!(matches!(message, ServerMessage::PeerJoined { session: s } if s == session));
    }

    #[test]
    fn relays_in_both_directions() {
        let registry = Registry::new(Limits::default());
        let (host_tx, mut host_rx) = channel();
        let host_conn = Uuid::new_v4();
        registry.register_host("fp", host_conn, host_tx).unwrap();
        let (peer_tx, mut peer_rx) = channel();
        let peer_conn = Uuid::new_v4();
        let session = registry.open_session("fp", peer_conn, peer_tx).unwrap();
        let _ = host_rx.try_recv();

        registry
            .relay(&session, peer_conn, serde_json::json!({"sdp": "offer"}))
            .unwrap();
        assert!(matches!(
            host_rx.try_recv().unwrap(),
            ServerMessage::Signal { .. }
        ));

        registry
            .relay(&session, host_conn, serde_json::json!({"sdp": "answer"}))
            .unwrap();
        assert!(matches!(
            peer_rx.try_recv().unwrap(),
            ServerMessage::Signal { .. }
        ));
    }

    #[test]
    fn a_stranger_cannot_relay_into_someone_elses_session() {
        let registry = Registry::new(Limits::default());
        let (host_tx, _host_rx) = channel();
        registry
            .register_host("fp", Uuid::new_v4(), host_tx)
            .unwrap();
        let (peer_tx, _peer_rx) = channel();
        let session = registry
            .open_session("fp", Uuid::new_v4(), peer_tx)
            .unwrap();

        let err = registry
            .relay(&session, Uuid::new_v4(), serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, RegistryError::NotAMember));
    }

    #[test]
    fn connecting_to_an_absent_host_fails() {
        let registry = Registry::new(Limits::default());
        let (peer_tx, _peer_rx) = channel();
        let err = registry
            .open_session("missing", Uuid::new_v4(), peer_tx)
            .unwrap_err();
        assert!(matches!(err, RegistryError::HostOffline));
    }

    #[test]
    fn enforces_the_session_cap_per_host() {
        let limits = Limits {
            max_sessions_per_host: 1,
            ..Limits::default()
        };
        let registry = Registry::new(limits);
        let (host_tx, _host_rx) = channel();
        registry
            .register_host("fp", Uuid::new_v4(), host_tx)
            .unwrap();
        let (first, _r1) = channel();
        registry.open_session("fp", Uuid::new_v4(), first).unwrap();
        let (second, _r2) = channel();
        let err = registry
            .open_session("fp", Uuid::new_v4(), second)
            .unwrap_err();
        assert!(matches!(err, RegistryError::HostBusy));
    }

    #[test]
    fn dropping_the_host_socket_closes_its_sessions() {
        let registry = Registry::new(Limits::default());
        let (host_tx, _host_rx) = channel();
        let host_conn = Uuid::new_v4();
        registry.register_host("fp", host_conn, host_tx).unwrap();
        let (peer_tx, mut peer_rx) = channel();
        registry
            .open_session("fp", Uuid::new_v4(), peer_tx)
            .unwrap();

        registry.drop_connection(host_conn);

        assert_eq!(registry.host_count(), 0);
        assert_eq!(registry.session_count(), 0);
        assert!(matches!(
            peer_rx.try_recv().unwrap(),
            ServerMessage::PeerLeft { .. }
        ));
    }

    #[test]
    fn dropping_a_peer_socket_leaves_the_host_registered() {
        let registry = Registry::new(Limits::default());
        let (host_tx, mut host_rx) = channel();
        registry
            .register_host("fp", Uuid::new_v4(), host_tx)
            .unwrap();
        let (peer_tx, _peer_rx) = channel();
        let peer_conn = Uuid::new_v4();
        registry.open_session("fp", peer_conn, peer_tx).unwrap();
        let _ = host_rx.try_recv();

        registry.drop_connection(peer_conn);

        assert_eq!(registry.host_count(), 1);
        assert_eq!(registry.session_count(), 0);
        assert!(matches!(
            host_rx.try_recv().unwrap(),
            ServerMessage::PeerLeft { .. }
        ));
    }

    #[test]
    fn re_registering_a_fingerprint_evicts_the_previous_socket() {
        let registry = Registry::new(Limits::default());
        let (first_tx, _first_rx) = channel();
        registry
            .register_host("fp", Uuid::new_v4(), first_tx)
            .unwrap();
        let (peer_tx, mut peer_rx) = channel();
        registry
            .open_session("fp", Uuid::new_v4(), peer_tx)
            .unwrap();

        let (second_tx, _second_rx) = channel();
        registry
            .register_host("fp", Uuid::new_v4(), second_tx)
            .unwrap();

        assert_eq!(registry.host_count(), 1);
        assert_eq!(registry.session_count(), 0);
        assert!(matches!(
            peer_rx.try_recv().unwrap(),
            ServerMessage::PeerLeft { .. }
        ));
    }
}
