#[macro_use] extern crate common;
#[cfg(not(target_arch = "wasm32"))]
#[macro_use]
extern crate gstuff;
#[macro_use] extern crate serde_derive;

#[macro_use]
pub mod mm_metrics;
pub mod recorder;
pub use metrics;
#[cfg(not(target_arch = "wasm32"))]
pub use mm_metrics::prometheus;

use derive_more::Display;
use mm2_err_handle::prelude::MmError;
use mm_metrics::Metrics;
use recorder::{MmRecorder, TryRecorder};
use serde_json::Value as Json;
use std::collections::HashMap;
use std::sync::{Arc, Weak};

pub type MmMetricsResult<T> = Result<T, MmError<MmMetricsError>>;

#[derive(Debug, Display)]
pub enum MmMetricsError {
    PrometheusTransport(String),
    #[display(fmt = "Internal: {}", _0)]
    Internal(String),
}

pub trait MetricsOps {
    /// Initializes mm2 Metrics.
    fn init(&self)
    where
        Self: Sized;

    /// Initializes mm2 Metrics with dashboard.
    fn init_with_dashboard(&self, log_state: common::log::LogWeak, interval: f64) -> MmMetricsResult<()>;

    /// Collect the metrics in a Json data format.
    fn collect_json(&self) -> MmMetricsResult<crate::Json>;
}

#[derive(Clone)]
pub struct MetricsArc(pub(crate) Arc<Metrics>);

impl Default for MetricsArc {
    fn default() -> Self { Self(Arc::new(Metrics::default())) }
}

impl MetricsArc {
    // Create new instance of our metrics recorder set to default.
    pub fn new() -> Self { Self(Default::default()) }

    /// Try to obtain the `Metrics` from the weak pointer.
    pub fn from_weak(weak: &MetricsWeak) -> Option<MetricsArc> { weak.0.upgrade().map(MetricsArc) }

    /// Create a weak pointer from `MetricsWeak`.
    pub fn weak(&self) -> MetricsWeak { MetricsWeak(Arc::downgrade(&self.0)) }
}

impl TryRecorder for MetricsArc {
    fn try_recorder(&self) -> Option<Arc<MmRecorder>> { Some(self.0.recorder.to_owned()) }
}

impl MetricsOps for MetricsArc {
    fn init(&self) { self.0.init(); }

    fn init_with_dashboard(&self, log_state: common::log::LogWeak, interval: f64) -> MmMetricsResult<()> {
        self.0.init_with_dashboard(log_state, interval)
    }

    fn collect_json(&self) -> MmMetricsResult<crate::Json> { self.0.collect_json() }
}

#[derive(Clone, Default)]
pub struct MetricsWeak(pub Weak<Metrics>);

impl MetricsWeak {
    /// Create a default MmWeak without allocating any memory.
    pub fn new() -> MetricsWeak { MetricsWeak::default() }

    pub fn dropped(&self) -> bool { self.0.strong_count() == 0 }
}

impl TryRecorder for MetricsWeak {
    fn try_recorder(&self) -> Option<Arc<MmRecorder>> {
        let metrics = MetricsArc::from_weak(self)?;
        metrics.try_recorder()
    }
}

#[derive(Serialize, Debug, Default, Deserialize)]
pub struct MetricsJson {
    pub metrics: Vec<MetricType>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type")]
pub enum MetricType {
    Counter {
        key: String,
        labels: HashMap<String, String>,
        value: u64,
    },
    Gauge {
        key: String,
        labels: HashMap<String, String>,
        value: f64,
    },
    Histogram {
        key: String,
        labels: HashMap<String, String>,
        #[serde(flatten)]
        quantiles: HashMap<String, f64>,
    },
}
