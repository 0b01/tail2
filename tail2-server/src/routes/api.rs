use std::{rc::Rc, sync::Arc};

use axum::{extract::State, debug_handler};
use tail2::{
    calltree::inner::{serialize::Node, CallTreeFrame},
    dto::FrameDto,
    symbolication::elf::ElfCache,
};
use axum::{
    Router,
    routing::get,
    response::sse::{Event, KeepAlive, Sse},
};
use std::{time::Duration, convert::Infallible};
use tokio_stream::StreamExt as _ ;
use futures::stream::{self, Stream};


use crate::{state::{CurrentCallTree, Connections}, Notifiable};

pub(crate) async fn current<'a>(State(ct): State<Arc<Connections>>) -> String {
    let ct = ct.calltree.inner.ct.lock().await;
    let node = Node::new(ct.root, &ct.arena);

    serde_json::to_string(&node).unwrap()
}

use async_stream::{stream, try_stream};

pub(crate) async fn events(State(ct): State<Arc<Connections>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // let changed = ct.calltree.changed.clone();
    // changed.notify_one();
    // let s = try_stream! {
    //     loop {
    //         yield Event::default().data("_");
    //         changed.notified().await;
    //     }
    // };

    struct Guard {
        // whatever state you need here
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            tracing::info!("stream closed");
        }
    }

    let stream = async_stream::try_stream! {
        let _guard = Guard {};
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        yield Event::default().event("stream started").data("test");
        loop {
            interval.tick().await;
            tracing::info!("new msg");
            yield Event::default().event("hi").data("test");
        }
        // `_guard` is dropped
    };


    Sse::new(stream)
}
