//! Live WebSocket connections, by device. A device may have more than one
//! (two browser tabs, say); a frame goes to all of them.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use messenger_protocol::ServerFrame;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// One live connection: its id and where to send it frames.
type Conn = (u64, UnboundedSender<ServerFrame>);

#[derive(Default)]
pub struct Hub {
    conns: Mutex<HashMap<String, Vec<Conn>>>,
    next_id: AtomicU64,
}

impl Hub {
    pub fn register(&self, device_id: &str) -> (u64, UnboundedReceiver<ServerFrame>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = unbounded_channel();
        self.conns
            .lock()
            .expect("hub lock poisoned")
            .entry(device_id.to_owned())
            .or_default()
            .push((id, tx));
        (id, rx)
    }

    pub fn unregister(&self, device_id: &str, conn_id: u64) {
        let mut conns = self.conns.lock().expect("hub lock poisoned");
        if let Some(list) = conns.get_mut(device_id) {
            list.retain(|(id, _)| *id != conn_id);
            if list.is_empty() {
                conns.remove(device_id);
            }
        }
    }

    /// Sends to every live connection of the device. Returns whether any
    /// connection took it.
    pub fn send(&self, device_id: &str, frame: &ServerFrame) -> bool {
        let mut conns = self.conns.lock().expect("hub lock poisoned");
        let Some(list) = conns.get_mut(device_id) else {
            return false;
        };
        list.retain(|(_, tx)| tx.send(frame.clone()).is_ok());
        let delivered = !list.is_empty();
        if !delivered {
            conns.remove(device_id);
        }
        delivered
    }

    pub fn is_online(&self, device_id: &str) -> bool {
        self.conns
            .lock()
            .expect("hub lock poisoned")
            .get(device_id)
            .is_some_and(|l| !l.is_empty())
    }
}
