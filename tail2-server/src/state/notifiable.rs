use std::{sync::Arc};

use tokio::sync::{Notify, Mutex, MutexGuard};
use serde::Deserialize;

pub struct Notifiable<T> {
    inner: Arc<Mutex<T>>,
    notify: Arc<Notify>,
}

impl<T> Clone for Notifiable<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            notify: Arc::clone(&self.notify),
        }
    }
}

impl<T: Default> Default for Notifiable<T> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Default::default())),
            notify: Arc::new(Notify::new())
        }
    }
}

impl<T> Notifiable<T> {
    pub fn new(inner: T) -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn new_wrapped(t: Arc<Mutex<T>>) -> Notifiable<T> {
        Self {
            notify: Arc::new(Notify::new()),
            inner: t,
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

    pub async fn lock(&self) -> MutexGuard<'_, T> {
        self.inner.lock().await
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Notifiable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        Ok(Self {
            notify: Arc::new(Notify::new()),
            inner: Arc::new(Mutex::new(T::deserialize(deserializer)?)),
        })
    }
}