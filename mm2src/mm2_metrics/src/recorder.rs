use std::{collections::HashMap, slice::Iter, sync::atomic::Ordering};

use crate::{native::{Integer, MetricNameValueMap, TagMetric},
            MetricType, MetricsJson};
use common::log::Tag;
use fomat_macros::wite;
use itertools::Itertools;
use metrics::{Counter, Gauge, Key, KeyName, Label, Recorder, Unit};
use metrics_core::ScopedString;
use metrics_exporter_prometheus::formatting::key_to_parts;
use metrics_util::registry::{GenerationalAtomicStorage, Registry};
use std::fmt::Write;

pub struct Snapshot {
    pub counters: HashMap<String, HashMap<Vec<Label>, u64>>,
    pub gauges: HashMap<String, HashMap<Vec<Label>, u64>>,
    pub histograms: HashMap<String, HashMap<Vec<Label>, f64>>,
}

pub struct MmRecorder {
    pub(crate) registry: Registry<Key, GenerationalAtomicStorage>,
}

impl Default for MmRecorder {
    fn default() -> Self {
        Self {
            registry: Registry::new(metrics_util::registry::GenerationalStorage::atomic()),
        }
    }
}

impl MmRecorder {
    pub fn get_metrics(&self) -> Snapshot {
        let counters = self
            .registry
            .get_counter_handles()
            .into_iter()
            .map(|(key, counter)| {
                let value = counter.get_inner().load(Ordering::Acquire);
                let inner = key_value_to_snapshot_entry(key.clone(), value);
                (key.into_parts().0.as_str().to_string(), inner)
            })
            .collect::<HashMap<_, _>>();

        let gauges = self
            .registry
            .get_gauge_handles()
            .into_iter()
            .map(|(key, gauge)| {
                gauge.get_generation();
                let value = gauge.get_inner().load(Ordering::Acquire);
                let inner = key_value_to_snapshot_entry(key.clone(), value);
                (key.into_parts().0.as_str().to_string(), inner)
            })
            .collect::<HashMap<_, _>>();

        let histograms = self
            .registry
            .get_histogram_handles()
            .into_iter()
            .map(|(key, histogram)| {
                histogram.get_generation();
                let value: f64 = histogram.get_inner().data().iter().sum();
                let inner = key_value_to_snapshot_entry(key.clone(), value);
                (key.into_parts().0.as_str().to_string(), inner)
            })
            .collect::<HashMap<_, _>>();

        Snapshot {
            counters,
            gauges,
            histograms,
        }
    }

    pub fn collect_tag_metrics(&self) -> Vec<TagMetric> {
        let Snapshot {
            counters,
            gauges,
            histograms,
        } = self.get_metrics();
        let mut output: Vec<TagMetric> = vec![];

        for (key, counter) in counters {
            let value = counter.into_values().collect::<Vec<_>>();
            output.push(map_metric_to_prepare_metric(key, value[0]));
        }

        for (key, gauge) in gauges {
            let value = gauge.into_values().collect::<Vec<_>>();
            output.push(map_metric_to_prepare_metric(key, value[0]));
        }

        for (key, histogram) in histograms {
            let value: f64 = histogram.into_values().collect::<Vec<_>>().iter().sum();
            output.push(map_metric_to_prepare_metric(key, value as u64));
        }

        output
    }

    pub fn prepare_json(&self) -> MetricsJson {
        let Snapshot {
            counters,
            gauges,
            histograms,
        } = self.get_metrics();

        let mut output = vec![];

        for counters in counters {
            for (labels, value) in counters.1.iter() {
                output.push(MetricType::Counter {
                    key: counters.clone().0,
                    labels: labels_into_parts(labels.clone().iter()),
                    value: *value,
                });
            }
        }

        for gauge in gauges {
            for (labels, value) in gauge.1.iter() {
                output.push(MetricType::Gauge {
                    key: gauge.clone().0,
                    labels: labels_into_parts(labels.clone().iter()),
                    value: *value as i64,
                });
            }
        }

        for histograms in histograms {
            for (labels, value) in histograms.1.iter() {
                let mut qauntiles_value = HashMap::new();
                qauntiles_value.insert(histograms.clone().0, *value as u64);
                output.push(MetricType::Histogram {
                    key: histograms.clone().0,
                    labels: labels_into_parts(labels.clone().iter()),
                    quantiles: qauntiles_value,
                });
            }
        }

        MetricsJson { metrics: output }
    }
}

impl Recorder for MmRecorder {
    fn describe_counter(&self, _key_name: KeyName, _unit: Option<Unit>, _description: &'static str) {
        // mm2_metrics doesn't use this method
    }

    fn describe_gauge(&self, _key_name: KeyName, _unit: Option<Unit>, _description: &'static str) {
        // mm2_metrics doesn't use this method
    }

    fn describe_histogram(&self, _key_name: KeyName, _unit: Option<Unit>, _description: &'static str) {
        // mm2_metrics doesn't use this method
    }

    fn register_counter(&self, key: &Key) -> Counter { self.registry.get_or_create_counter(key, |e| e.clone().into()) }

    fn register_gauge(&self, key: &Key) -> Gauge { self.registry.get_or_create_gauge(key, |e| e.clone().into()) }

    fn register_histogram(&self, key: &Key) -> metrics::Histogram {
        self.registry.get_or_create_histogram(key, |e| e.clone().into())
    }
}

fn key_value_to_snapshot_entry<T: Clone>(key: Key, value: T) -> HashMap<Vec<Label>, T> {
    let (_name, labels) = key.into_parts();
    let mut entry = HashMap::new();
    entry.insert(labels, value);
    entry
}

fn map_metric_to_prepare_metric<T: Clone>(key: String, value: T) -> TagMetric
where
    u64: From<T>,
{
    let key = Key::from_name(key);
    let (name, _labels) = key_to_parts(&key, None);
    let mut name_value_map = HashMap::new();

    name_value_map.insert(ScopedString::Owned(name), Integer::Unsigned(u64::from(value)));
    TagMetric {
        tags: labels_to_tags(key.labels()),
        message: name_value_map_to_message(&name_value_map),
    }
}

fn labels_to_tags(labels: Iter<Label>) -> Vec<Tag> {
    // let key_name = label.into_parts().clone().0;
    labels
        .map(|label| Tag {
            key: label.clone().into_parts().0.to_string(),
            val: Some(label.value().to_string()),
        })
        .collect()
}

fn name_value_map_to_message(name_value_map: &MetricNameValueMap) -> String {
    let mut message = String::with_capacity(256);
    match wite!(message, for (key, value) in name_value_map.iter().sorted() { (key) "=" (value.to_string()) } separated {' '})
    {
        Ok(_) => message,
        Err(err) => {
            log!("Error " (err) " on format hist to message");
            String::new()
        },
    }
}

fn labels_into_parts(labels: Iter<Label>) -> HashMap<String, String> {
    labels
        .map(|label| (label.key().to_string(), label.value().to_string()))
        .collect()
}