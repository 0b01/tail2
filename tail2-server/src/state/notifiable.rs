use std::sync::Arc;

use tokio::sync::Notify;
use serde::{Serialize, Deserialize};

pub struct Notifiable<T> {
    pub inner: T,
    pub changed: Arc<Notify>,
}

impl<T> Notifiable<T> {
    pub fn new(inner: T) -> Self {
        let changed = Arc::new(Notify::new());

        Self {
            changed,
            inner,
        }
    }

    pub async fn with_notify<F>(&mut self, f: F) 
        where F: Fn(&mut T)
    {
        self.changed.notify_one();
        f(&mut self.inner)
    }
}

impl<T: Serialize> Serialize for Notifiable<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        self.inner.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Notifiable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        Ok(Self {
            changed: Arc::new(Notify::new()),
            inner: T::deserialize(deserializer)?,
        })
    }
}