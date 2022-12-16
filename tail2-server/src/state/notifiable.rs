use std::sync::Arc;

use rocket::tokio::sync::Notify;

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

    pub fn notify(&self) {
        self.changed.notify_one();
    }
}
