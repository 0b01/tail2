use crate::metrics::Metrics;

#[derive(Copy, Clone)]
pub struct PidEvent {
    pub pid: u32,
    pub event_type: Metrics,
}