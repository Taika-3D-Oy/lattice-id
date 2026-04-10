use std::collections::{BTreeMap, BTreeSet};

const CORE_REQUEST_BUCKETS_MS: &[u64] = &[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

#[derive(Default)]
pub struct Metrics {
    counters: BTreeMap<MetricKey, u64>,
    histograms: BTreeMap<MetricKey, Histogram>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MetricKey {
    name: String,
    labels: Vec<(String, String)>,
}

struct Histogram {
    buckets: Vec<u64>,
    counts: Vec<u64>,
    sum: u64,
    count: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_counter(&mut self, name: &str, labels: &[(&str, &str)]) {
        let key = MetricKey::new(name, labels);
        *self.counters.entry(key).or_insert(0) += 1;
    }

    pub fn observe_core_request(&mut self, op: &str, duration_ms: u64, ok: bool) {
        let result = if ok { "success" } else { "error" };
        self.increment_counter(
            "lattice_id_core_requests_total",
            &[("op", op), ("result", result)],
        );
        self.observe_histogram(
            "lattice_id_core_request_duration_ms",
            &[("op", op)],
            duration_ms,
            CORE_REQUEST_BUCKETS_MS,
        );
    }

    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();
        let counter_names: BTreeSet<_> = self.counters.keys().map(|key| key.name.as_str()).collect();
        for name in counter_names {
            output.push_str(&format!("# TYPE {name} counter\n"));
            for (key, value) in self.counters.iter().filter(|(key, _)| key.name == name) {
                output.push_str(&format!("{}{} {}\n", key.name, format_labels(&key.labels), value));
            }
        }

        let histogram_names: BTreeSet<_> = self.histograms.keys().map(|key| key.name.as_str()).collect();
        for name in histogram_names {
            output.push_str(&format!("# TYPE {name} histogram\n"));
            for (key, histogram) in self.histograms.iter().filter(|(key, _)| key.name == name) {
                let mut cumulative = 0u64;
                for (index, upper_bound) in histogram.buckets.iter().enumerate() {
                    cumulative += histogram.counts[index];
                    let labels = with_extra_label(&key.labels, "le", &upper_bound.to_string());
                    output.push_str(&format!(
                        "{}_bucket{} {}\n",
                        key.name,
                        format_labels(&labels),
                        cumulative
                    ));
                }
                let inf_labels = with_extra_label(&key.labels, "le", "+Inf");
                output.push_str(&format!(
                    "{}_bucket{} {}\n",
                    key.name,
                    format_labels(&inf_labels),
                    histogram.count
                ));
                output.push_str(&format!(
                    "{}_sum{} {}\n",
                    key.name,
                    format_labels(&key.labels),
                    histogram.sum
                ));
                output.push_str(&format!(
                    "{}_count{} {}\n",
                    key.name,
                    format_labels(&key.labels),
                    histogram.count
                ));
            }
        }

        output
    }

    fn observe_histogram(
        &mut self,
        name: &str,
        labels: &[(&str, &str)],
        value: u64,
        buckets: &[u64],
    ) {
        let key = MetricKey::new(name, labels);
        let histogram = self.histograms.entry(key).or_insert_with(|| Histogram {
            buckets: buckets.to_vec(),
            counts: vec![0; buckets.len()],
            sum: 0,
            count: 0,
        });

        histogram.sum += value;
        histogram.count += 1;
        for (index, upper_bound) in histogram.buckets.iter().enumerate() {
            if value <= *upper_bound {
                histogram.counts[index] += 1;
                break;
            }
        }
    }
}

impl MetricKey {
    fn new(name: &str, labels: &[(&str, &str)]) -> Self {
        let mut normalized: Vec<(String, String)> = labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        normalized.sort();
        Self {
            name: name.to_string(),
            labels: normalized,
        }
    }
}

fn format_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let rendered = labels
        .iter()
        .map(|(key, value)| format!(r#"{key}="{}""#, escape_label_value(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{rendered}}}")
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', r#"\\"#)
        .replace('\n', r#"\n"#)
        .replace('"', r#"\""#)
}

fn with_extra_label(labels: &[(String, String)], key: &str, value: &str) -> Vec<(String, String)> {
    let mut combined = labels.to_vec();
    combined.push((key.to_string(), value.to_string()));
    combined.sort();
    combined
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn renders_counter_and_histogram_samples() {
        let mut metrics = Metrics::new();
        metrics.increment_counter(
            "lattice_id_login_attempts_total",
            &[("flow", "password"), ("result", "success")],
        );
        metrics.observe_core_request("exchange_code", 12, true);

        let rendered = metrics.render_prometheus();

        assert!(rendered.contains("# TYPE lattice_id_login_attempts_total counter"));
        assert!(rendered.contains("lattice_id_login_attempts_total{flow=\"password\",result=\"success\"} 1"));
        assert!(rendered.contains("# TYPE lattice_id_core_request_duration_ms histogram"));
        assert!(rendered.contains("lattice_id_core_request_duration_ms_count{op=\"exchange_code\"} 1"));
    }
}