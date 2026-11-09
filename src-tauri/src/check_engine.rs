//! Capability-free, finite check language. Shared verbatim with the isolated runner.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const ENGINE: u32 = 1;
pub const MAX_SPEC: usize = 16384;
const OS_FIELDS: &[&str] = &[
    "cpu_percent",
    "memory_percent",
    "swap_percent",
    "disk_max_percent",
    "inode_max_percent",
    "uptime_seconds",
    "failed_services",
    "logs_oom",
    "logs_disk_io",
    "logs_service_crash",
];
pub fn fields() -> &'static [String] {
    static FIELDS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        let catalog: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../../collectors/connectors/catalog.json"))
                .expect("Service catalog");
        OS_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .chain(
                catalog
                    .values()
                    .flat_map(|spec| spec["checkInputs"].as_array().into_iter().flatten())
                    .filter_map(|field| field.as_str().map(str::to_owned)),
            )
            .collect()
    });
    &FIELDS
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Number {
    Field {
        name: String,
    },
    Constant {
        value: f64,
    },
    Add {
        left: Box<Number>,
        right: Box<Number>,
    },
    Sub {
        left: Box<Number>,
        right: Box<Number>,
    },
    Mul {
        left: Box<Number>,
        right: Box<Number>,
    },
    Div {
        left: Box<Number>,
        right: Box<Number>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Gt { left: Number, right: Number },
    Gte { left: Number, right: Number },
    Lt { left: Number, right: Number },
    Lte { left: Number, right: Number },
    Eq { left: Number, right: Number },
    All { items: Vec<Condition> },
    Any { items: Vec<Condition> },
    Not { item: Box<Condition> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Healthy,
    Warning,
    Critical,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fixture {
    pub name: String,
    pub values: BTreeMap<String, Option<f64>>,
    pub expected: Status,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Spec {
    pub format: u32,
    pub name: String,
    pub description: String,
    pub interval_seconds: u64,
    pub bad_windows: u32,
    pub inputs: Vec<String>,
    pub severity: Status,
    pub condition: Condition,
    pub tests: Vec<Fixture>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseResult {
    pub name: String,
    pub expected: Status,
    pub actual: Status,
    pub passed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub engine: u32,
    pub passed: bool,
    pub cases: Vec<CaseResult>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub spec: Spec,
    pub values: BTreeMap<String, Option<f64>>,
    pub test: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub engine: u32,
    pub status: Status,
    pub report: Option<Report>,
}
fn bounded(v: f64) -> bool {
    v.is_finite() && v.abs() <= 1e12
}
fn text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
struct Validation {
    nodes: usize,
    fields: BTreeSet<String>,
}
impl Validation {
    fn enter(&mut self, depth: usize) -> Result<(), String> {
        self.nodes += 1;
        if depth > 8 || self.nodes > 64 {
            return Err("No more than 64 knots and 8 levels of expression".into());
        }
        Ok(())
    }
    fn number(&mut self, n: &Number, d: usize) -> Result<(), String> {
        self.enter(d)?;
        match n {
            Number::Field { name } => {
                if !fields().contains(name) {
                    return Err(format!("Inaccessible entrance: {name}"));
                }
                self.fields.insert(name.clone());
            }
            Number::Constant { value } => {
                if !bounded(*value) {
                    return Err("Incorrect numerical constant".into());
                }
            }
            Number::Add { left, right }
            | Number::Sub { left, right }
            | Number::Mul { left, right }
            | Number::Div { left, right } => {
                self.number(left, d + 1)?;
                self.number(right, d + 1)?;
            }
        }
        Ok(())
    }
    fn condition(&mut self, c: &Condition, d: usize) -> Result<(), String> {
        self.enter(d)?;
        match c {
            Condition::Gt { left, right }
            | Condition::Gte { left, right }
            | Condition::Lt { left, right }
            | Condition::Lte { left, right }
            | Condition::Eq { left, right } => {
                self.number(left, d + 1)?;
                self.number(right, d + 1)?;
            }
            Condition::All { items } | Condition::Any { items } => {
                if items.is_empty() || items.len() > 8 {
                    return Err("The group must contain 1-8 conditions".into());
                }
                for c in items {
                    self.condition(c, d + 1)?;
                }
            }
            Condition::Not { item } => self.condition(item, d + 1)?,
        }
        Ok(())
    }
}
pub fn validate(s: &Spec) -> Result<(), String> {
    if serde_json::to_vec(s).map_err(|e| e.to_string())?.len() > MAX_SPEC
        || s.format != ENGINE
        || !text(&s.name, 120)
        || !text(&s.description, 1200)
        || !(60..=86400).contains(&s.interval_seconds)
        || !(1..=5).contains(&s.bad_windows)
        || !(1..=8).contains(&s.inputs.len())
        || !matches!(s.severity, Status::Warning | Status::Critical)
    {
        return Err("Incorrect format or verification limits".into());
    }
    let mut v = Validation {
        nodes: 0,
        fields: BTreeSet::new(),
    };
    v.condition(&s.condition, 0)?;
    let declared = s.inputs.iter().cloned().collect::<BTreeSet<_>>();
    if declared.len() != s.inputs.len() || declared != v.fields {
        return Err("The inputs must coincide exactly with the fields of expression".into());
    }
    if !(3..=16).contains(&s.tests.len()) {
        return Err("We need 3-16 tests: operation, normality and lack of data".into());
    }
    let mut names = BTreeSet::new();
    for t in &s.tests {
        if !text(&t.name, 100)
            || !names.insert(&t.name)
            || t.values.keys().any(|k| !declared.contains(k))
            || t.values.values().flatten().any(|v| !bounded(*v))
        {
            return Err("Wrong test set".into());
        }
    }
    for expected in [&Status::Healthy, &Status::Unknown, &s.severity] {
        if !s.tests.iter().any(|t| &t.expected == expected) {
            return Err("Tests should include norm, response and unknown result".into());
        }
    }
    Ok(())
}
#[allow(dead_code)] // Also compiled into the isolated worker.
fn number(n: &Number, v: &BTreeMap<String, Option<f64>>) -> Option<f64> {
    let result = match n {
        Number::Field { name } => *v.get(name)?,
        Number::Constant { value } => Some(*value),
        Number::Add { left, right } => Some(number(left, v)? + number(right, v)?),
        Number::Sub { left, right } => Some(number(left, v)? - number(right, v)?),
        Number::Mul { left, right } => Some(number(left, v)? * number(right, v)?),
        Number::Div { left, right } => {
            let d = number(right, v)?;
            if d == 0.0 {
                return None;
            }
            Some(number(left, v)? / d)
        }
    }?;
    bounded(result).then_some(result)
}
#[allow(dead_code)]
fn condition(c: &Condition, v: &BTreeMap<String, Option<f64>>) -> Option<bool> {
    match c {
        Condition::Gt { left, right } => Some(number(left, v)? > number(right, v)?),
        Condition::Gte { left, right } => Some(number(left, v)? >= number(right, v)?),
        Condition::Lt { left, right } => Some(number(left, v)? < number(right, v)?),
        Condition::Lte { left, right } => Some(number(left, v)? <= number(right, v)?),
        Condition::Eq { left, right } => Some(number(left, v)? == number(right, v)?),
        Condition::All { items } => {
            let values = items.iter().map(|c| condition(c, v)).collect::<Vec<_>>();
            if values.contains(&Some(false)) {
                Some(false)
            } else if values.contains(&None) {
                None
            } else {
                Some(true)
            }
        }
        Condition::Any { items } => {
            let values = items.iter().map(|c| condition(c, v)).collect::<Vec<_>>();
            if values.contains(&Some(true)) {
                Some(true)
            } else if values.contains(&None) {
                None
            } else {
                Some(false)
            }
        }
        Condition::Not { item } => condition(item, v).map(|v| !v),
    }
}
#[allow(dead_code)]
pub fn evaluate(s: &Spec, values: &BTreeMap<String, Option<f64>>) -> Status {
    if s.inputs
        .iter()
        .any(|k| values.get(k).copied().flatten().is_none_or(|v| !bounded(v)))
    {
        return Status::Unknown;
    }
    match condition(&s.condition, values) {
        Some(true) => s.severity.clone(),
        Some(false) => Status::Healthy,
        None => Status::Unknown,
    }
}
#[allow(dead_code)]
pub fn execute(request: Request) -> Result<Response, String> {
    validate(&request.spec)?;
    if request.values.len() > 8
        || request
            .values
            .keys()
            .any(|k| !request.spec.inputs.contains(k))
        || request.values.values().flatten().any(|v| !bounded(*v))
    {
        return Err("Inadmissible entry".into());
    }
    let status = evaluate(&request.spec, &request.values);
    let report = if request.test {
        let mut cases = request
            .spec
            .tests
            .iter()
            .map(|t| {
                let actual = evaluate(&request.spec, &t.values);
                CaseResult {
                    name: t.name.clone(),
                    expected: t.expected.clone(),
                    passed: actual == t.expected,
                    actual,
                }
            })
            .collect::<Vec<_>>();
        for field in &request.spec.inputs {
            let mut values = request.spec.tests[0].values.clone();
            values.remove(field);
            let actual = evaluate(&request.spec, &values);
            cases.push(CaseResult {
                name: format!("Mandatory entrance: {field}"),
                expected: Status::Unknown,
                passed: actual == Status::Unknown,
                actual,
            });
        }
        Some(Report {
            engine: ENGINE,
            passed: cases.iter().all(|c| c.passed),
            cases,
        })
    } else {
        None
    };
    Ok(Response {
        engine: ENGINE,
        status,
        report,
    })
}
pub fn example() -> Spec {
    Spec {
        format: ENGINE,
        name: "Memory above 90%".into(),
        description: "Two fresh observations of high memory load; omissions don’t mean normal."
            .into(),
        interval_seconds: 180,
        bad_windows: 2,
        inputs: vec!["memory_percent".into()],
        severity: Status::Warning,
        condition: Condition::Gt {
            left: Number::Field {
                name: "memory_percent".into(),
            },
            right: Number::Constant { value: 90.0 },
        },
        tests: vec![
            Fixture {
                name: "High load".into(),
                values: BTreeMap::from([("memory_percent".into(), Some(95.0))]),
                expected: Status::Warning,
            },
            Fixture {
                name: "Norma".into(),
                values: BTreeMap::from([("memory_percent".into(), Some(50.0))]),
                expected: Status::Healthy,
            },
            Fixture {
                name: "No data".into(),
                values: BTreeMap::new(),
                expected: Status::Unknown,
            },
        ],
    }
}

// Field-level schema reduces model retries; recursive expressions are still strictly
// validated against the finite AST above, including exact declared inputs.
#[allow(dead_code)]
pub fn schema() -> serde_json::Value {
    serde_json::json!({"type":"object","additionalProperties":false,"required":["format","name","description","intervalSeconds","badWindows","inputs","severity","condition","tests"],"properties":{
        "format":{"type":"integer","enum":[1]},"name":{"type":"string","minLength":1,"maxLength":120},"description":{"type":"string","minLength":1,"maxLength":1200},
        "intervalSeconds":{"type":"integer","minimum":60,"maximum":86400},"badWindows":{"type":"integer","minimum":1,"maximum":5},
        "inputs":{"type":"array","minItems":1,"maxItems":8,"uniqueItems":true,"items":{"type":"string","enum":fields()}},"severity":{"type":"string","enum":["warning","critical"]},
        "condition":{"type":"object","description":"Condition from get_check_contract grammar. Comparisons use left/right Number objects; field numbers use {op:field,name}; constants use {op:constant,value}.","required":["op"],"properties":{"op":{"type":"string","enum":["gt","gte","lt","lte","eq","all","any","not"]},"left":{"type":"object"},"right":{"type":"object"},"items":{"type":"array","items":{"type":"object"}},"item":{"type":"object"}},"additionalProperties":false},
        "tests":{"type":"array","minItems":3,"maxItems":16,"items":{"type":"object","additionalProperties":false,"required":["name","values","expected"],"properties":{"name":{"type":"string","minLength":1,"maxLength":100},"values":{"type":"object","description":"Only declared input names, numeric values or null; use {} to test missing data.","additionalProperties":{"type":["number","null"]}},"expected":{"type":"string","enum":["healthy","warning","critical","unknown"]}}}}
    }})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_capabilities_and_limits() {
        let mut s = example();
        s.inputs = vec!["/etc/shadow".into()];
        assert!(validate(&s).is_err());
        for raw in [
            r#"{"op":"exec","command":"id"}"#,
            r#"{"op":"field","name":"memory_percent","path":"/etc/shadow"}"#,
        ] {
            assert!(serde_json::from_str::<Number>(raw).is_err());
        }
        let mut s = example();
        s.interval_seconds = 0;
        assert!(validate(&s).is_err());
        s = example();
        for _ in 0..10 {
            s.condition = Condition::Not {
                item: Box::new(s.condition),
            };
        }
        assert!(validate(&s).is_err());
    }
    #[test]
    fn missing_division_and_failed_fixtures_are_not_healthy() {
        let mut s = example();
        assert_eq!(evaluate(&s, &BTreeMap::new()), Status::Unknown);
        s.condition = Condition::Gt {
            left: Number::Div {
                left: Box::new(Number::Field {
                    name: "memory_percent".into(),
                }),
                right: Box::new(Number::Constant { value: 0.0 }),
            },
            right: Number::Constant { value: 1.0 },
        };
        let r = execute(Request {
            spec: s,
            values: BTreeMap::from([("memory_percent".into(), Some(99.0))]),
            test: true,
        })
        .unwrap();
        assert_eq!(r.status, Status::Unknown);
        assert!(!r.report.unwrap().passed);
    }
}
