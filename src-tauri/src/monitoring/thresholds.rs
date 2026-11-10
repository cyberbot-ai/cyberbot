//! Editable numeric boundaries for built-in monitoring rules.
use crate::services::MetricSpec;
use serde::Serialize;
use std::collections::BTreeMap;

pub type Fields = BTreeMap<String, f64>;
pub type Thresholds = BTreeMap<String, Fields>;

const MAX_COUNT: f64 = 9_007_199_254_740_991.;
const MAX_LOG_COUNT: f64 = 2_097_152.;
const MAX_SECONDS: f64 = 86_400.;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    key: &'static str,
    label: &'static str,
    unit: &'static str,
    default: f64,
    min: f64,
    max: f64,
    integer: bool,
}

impl Field {
    fn number(key: &'static str, label: &'static str, unit: &'static str, default: f64) -> Self {
        Self {
            key,
            label,
            unit,
            default,
            min: 0.,
            max: MAX_COUNT,
            integer: false,
        }
    }

    fn count(key: &'static str, label: &'static str, default: f64, max: f64) -> Self {
        Self {
            min: 1.,
            max,
            integer: true,
            ..Self::number(key, label, "events", default)
        }
    }

    fn percent(key: &'static str, label: &'static str, default: f64) -> Self {
        Self {
            max: 100.,
            ..Self::number(key, label, "%", default)
        }
    }

    fn seconds(key: &'static str, label: &'static str, default: f64) -> Self {
        Self {
            min: 1.,
            max: MAX_SECONDS,
            integer: true,
            ..Self::number(key, label, "s", default)
        }
    }

    fn valid(&self, value: f64) -> bool {
        value.is_finite()
            && (self.min..=self.max).contains(&value)
            && (!self.integer || value.fract() == 0.)
    }
}

#[derive(Clone, Serialize)]
pub struct ThresholdRule {
    pub key: String,
    label: String,
    fields: Vec<Field>,
}

impl ThresholdRule {
    fn new(key: &str, label: &str, fields: Vec<Field>) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            fields,
        }
    }

    fn percent_pair(key: &str, label: &str, warning: f64, critical: f64) -> Self {
        Self::new(
            key,
            label,
            vec![
                Field::percent("warning", "Warning", warning),
                Field::percent("critical", "Critical", critical),
            ],
        )
    }

    pub fn defaults(&self) -> Fields {
        self.fields
            .iter()
            .map(|field| (field.key.to_owned(), field.default))
            .collect()
    }

    fn valid(&self, fields: &Fields) -> bool {
        fields.len() == self.fields.len()
            && self
                .fields
                .iter()
                .all(|field| fields.get(field.key).is_some_and(|v| field.valid(*v)))
            && fields
                .get("warning")
                .zip(fields.get("critical"))
                .is_none_or(|(w, c)| w < c)
    }
}

pub fn for_definition(kind: &str, metrics: &[MetricSpec]) -> Vec<ThresholdRule> {
    let count = |key, label, default| Field::count(key, label, default, MAX_LOG_COUNT);
    let warning = |default| count("warning", "Warning", default);
    let critical = |default| count("critical", "Critical", default);
    let seconds = Field::seconds;
    let mut rules = match kind {
        "metrics" => vec![
            ThresholdRule::percent_pair("cpu", "CPU usage", 90., 97.),
            ThresholdRule::percent_pair("memory", "Memory usage", 90., 97.),
            ThresholdRule::percent_pair("disk", "Disk usage", 90., 97.),
        ],
        "postgresql" => vec![
            ThresholdRule::percent_pair("connections", "Connection usage", 90., 97.),
            ThresholdRule::new(
                "freeze_age",
                "Transaction ID age",
                vec![
                    Field {
                        unit: "transactions",
                        ..Field::count("warning", "Warning", 1_000_000_000., 2_147_483_647.)
                    },
                    Field {
                        unit: "transactions",
                        ..Field::count("critical", "Critical", 1_500_000_000., 2_147_483_647.)
                    },
                ],
            ),
            ThresholdRule::new(
                "locks",
                "Lock waits",
                vec![seconds("seconds", "Minimum wait", 30.), warning(1.)],
            ),
            ThresholdRule::new(
                "long_queries",
                "Long-running queries",
                vec![seconds("seconds", "Query duration", 60.), warning(1.)],
            ),
            ThresholdRule::new(
                "idle_transactions",
                "Idle transactions",
                vec![seconds("seconds", "Idle duration", 300.), warning(1.)],
            ),
            ThresholdRule::new(
                "replication",
                "Replication backlog",
                vec![Field {
                    min: 1.,
                    ..Field::number("warning", "Warning", "MiB", 64.)
                }],
            ),
            ThresholdRule::new(
                "slots",
                "Replication slot backlog",
                vec![Field {
                    min: 1.,
                    ..Field::number("warning", "Warning", "MiB", 1024.)
                }],
            ),
        ],
        "nginx" => vec![
            ThresholdRule::new(
                "http_5xx",
                "HTTP 5xx responses",
                vec![warning(10.), Field::percent("share", "Minimum share", 5.)],
            ),
            ThresholdRule::new(
                "latency",
                "Slow requests",
                vec![
                    Field {
                        min: 1.,
                        max: 86_400_000.,
                        integer: true,
                        ..Field::number("milliseconds", "Request duration", "ms", 1000.)
                    },
                    warning(20.),
                    Field::percent("share", "Minimum share", 20.),
                ],
            ),
            ThresholdRule::new("upstream", "Upstream errors", vec![warning(5.)]),
            ThresholdRule::new("capacity", "Connection limit events", vec![critical(1.)]),
            ThresholdRule::new(
                "critical_error",
                "Critical error events",
                vec![critical(1.)],
            ),
        ],
        "logs" => vec![
            ThresholdRule::new("oom", "Out-of-memory events", vec![critical(1.)]),
            ThresholdRule::new("disk_io", "Disk and filesystem errors", vec![critical(1.)]),
            ThresholdRule::new(
                "service_crash",
                "Process and service failures",
                vec![warning(1.)],
            ),
            ThresholdRule::new("protection_failure", "Fail2ban errors", vec![warning(1.)]),
            ThresholdRule::new(
                "ssh_suspicious_success",
                "SSH logins after repeated failures",
                vec![
                    warning(1.),
                    count("failedAttempts", "Preceding failures", 10.),
                    Field {
                        min: 300.,
                        max: 1800.,
                        ..seconds("lookbackSeconds", "Lookback window", 1800.)
                    },
                ],
            ),
            ThresholdRule::new(
                "system_error_spike",
                "System error spike",
                vec![
                    Field::number("rate", "Minimum rate", "events / 10 min", 20.),
                    Field {
                        min: 1.,
                        ..Field::number("medianMultiplier", "Median multiplier", "×", 5.)
                    },
                    Field::number("deviationMultiplier", "Deviation multiplier", "×", 6.),
                ],
            ),
            ThresholdRule::new(
                "new_error_pattern",
                "New recurring error pattern",
                vec![warning(5.)],
            ),
        ],
        _ => Vec::new(),
    };
    rules.extend(metrics.iter().filter_map(|metric| {
        let rule = metric.rule.as_ref()?;
        let field = |key, label, default| {
            if rule.mode == "delta_per_10m" {
                Field {
                    min: 0.001,
                    ..Field::number(key, label, "events / 10 min", default)
                }
            } else {
                match metric.unit.as_str() {
                    "%" | "percent" => Field::percent(key, label, default),
                    "s" | "seconds" => Field::number(key, label, "s", default),
                    "count" => Field {
                        unit: "count",
                        ..Field::count(key, label, default, MAX_COUNT)
                    },
                    _ => Field::number(key, label, "", default),
                }
            }
        };
        let mut fields = Vec::new();
        if rule.critical != Some(rule.threshold) {
            fields.push(field("warning", "Warning", rule.threshold));
        }
        if let Some(critical) = rule.critical {
            fields.push(field("critical", "Critical", critical));
        }
        if matches!(
            (kind, metric.key.as_str()),
            ("mysql" | "clickhouse", "longQueries") | ("mysql", "longTransactions")
        ) {
            let (label, default) = if metric.key == "longQueries" {
                ("Query duration", 60.)
            } else {
                ("Transaction duration", 300.)
            };
            fields.push(seconds("seconds", label, default));
        }
        Some(ThresholdRule::new(&metric.key, &metric.label, fields))
    }));
    rules
}

pub fn validate(rules: &[ThresholdRule], overrides: &Thresholds) -> bool {
    overrides.iter().all(|(key, fields)| {
        rules
            .iter()
            .any(|rule| rule.key == *key && rule.valid(fields))
    })
}

pub fn activation(fields: &Fields) -> f64 {
    *fields.get("warning").unwrap_or_else(|| &fields["critical"])
}

pub fn severity(fields: &Fields, value: f64) -> &'static str {
    if fields
        .get("critical")
        .is_some_and(|threshold| value >= *threshold)
    {
        "critical"
    } else {
        "warning"
    }
}

// The remote protocol accepts just the boundaries used to produce aggregates.
pub fn collector_values(kind: &str, values: &Thresholds) -> BTreeMap<&'static str, u64> {
    let fields: &[(&str, &str, &str)] = match kind {
        "mysql" => &[
            ("longQuerySeconds", "longQueries", "seconds"),
            ("longTransactionSeconds", "longTransactions", "seconds"),
        ],
        "clickhouse" => &[("longQuerySeconds", "longQueries", "seconds")],
        "postgresql" => &[
            ("longQuerySeconds", "long_queries", "seconds"),
            ("idleTransactionSeconds", "idle_transactions", "seconds"),
        ],
        "nginx" => &[("slowRequestMs", "latency", "milliseconds")],
        "logs" => &[
            (
                "sshFailedAttempts",
                "ssh_suspicious_success",
                "failedAttempts",
            ),
            (
                "sshLookbackSeconds",
                "ssh_suspicious_success",
                "lookbackSeconds",
            ),
        ],
        _ => &[],
    };
    fields
        .iter()
        .map(|(name, rule, field)| (*name, values[*rule][*field] as u64))
        .collect()
}
