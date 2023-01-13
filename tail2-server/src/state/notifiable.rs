use std::{sync::Arc};

use tokio::sync::Notify;
use serde::{Serialize, Deserialize};

#[derive(Clone)]
pub struct Notifiable<T> {
    inner: Arc<T>,
    notify: Arc<Notify>,
}

impl<T> AsRef<T> for Notifiable<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> Notifiable<T> {
    pub fn new(inner: T) -> Self {
        let changed = Arc::new(Notify::new());

        Self {
            notify: changed,
            inner: Arc::new(inner),
        }
    }

    pub fn notify_one(&self) {
        self.notify.notify_one()
    }

    pub fn notify_waiters(&self) {
        self.notify.notify_waiters()
    }

    pub fn notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
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
            notify: Arc::new(Notify::new()),
            inner: Arc::<T>::deserialize(deserializer)?,
        })
    }
}