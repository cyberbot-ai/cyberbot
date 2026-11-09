//! Provider-specific, immutable per-run model profiles. Catalog reads never start a turn.
use crate::store::Store;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub model: String,
    pub effort: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profiles {
    pub revision: u64,
    pub providers: BTreeMap<String, BTreeMap<String, Profile>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Selection {
    pub revision: u64,
    pub alias: String,
    pub primary: Profile,
    pub low: Profile,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub efforts: Vec<String>,
    pub resolved_model: Option<String>,
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
impl Default for Profiles {
    fn default() -> Self {
        Self {
            revision: 1,
            providers: [
                ("codex", ["gpt-6-luna", "gpt-6.1-terra", "gpt-6.1-sol"]),
                ("claude", ["haiku", "sonnet", "opus"]),
            ]
            .into_iter()
            .map(|(provider, models)| {
                (
                    provider.into(),
                    ["low", "medium", "high"]
                        .into_iter()
                        .zip(models)
                        .map(|(alias, model)| {
                            (
                                alias.into(),
                                Profile {
                                    model: model.into(),
                                    effort: "high".into(),
                                },
                            )
                        })
                        .collect(),
                )
            })
            .collect(),
        }
    }
}
impl Profiles {
    pub fn validate(&self) -> Result<(), String> {
        if self.providers.len() != 2
            || self
                .providers
                .keys()
                .any(|p| !matches!(p.as_str(), "codex" | "claude"))
        {
            return Err("You need separate Codex and Claude profiles".into());
        }
        for (provider, roles) in &self.providers {
            if roles.len() != 3
                || ["low", "medium", "high"]
                    .iter()
                    .any(|a| !roles.contains_key(*a))
            {
                return Err("We need low, medium and high".into());
            }
            for p in roles.values() {
                if p.model.is_empty()
                    || p.model.len() > 128
                    || !p
                        .model
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c))
                    || !["low", "medium", "high", "xhigh", "max", "ultra"]
                        .contains(&p.effort.as_str())
                    || provider == "claude" && p.effort == "ultra"
                {
                    return Err("Incorrect ID model or effort".into());
                }
            }
        }
        Ok(())
    }
}
pub fn migrate(db: &Connection) -> Result<(), String> {
    db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS ai_profiles(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL); PRAGMA user_version=15; COMMIT;").map_err(err)
}
pub(crate) fn read(db: &Connection) -> Result<Profiles, String> {
    use rusqlite::OptionalExtension;
    let value: Option<String> = db
        .query_row("SELECT payload FROM ai_profiles WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(err)?;
    value
        .map(|v| serde_json::from_str(&v).map_err(err))
        .unwrap_or_else(|| Ok(Profiles::default()))
}
impl Store {
    pub(crate) fn current_ai_selection(&self, alias: &str) -> Result<(String, Selection), String> {
        if !matches!(alias, "low" | "medium" | "high") {
            return Err("Choose low, medium or high".into());
        }
        let db = self.0.lock().map_err(err)?;
        let provider = Self::read_settings(&db)?.auto_agent;
        let profiles = read(&db)?;
        let roles = profiles
            .providers
            .get(&provider)
            .ok_or("Unknown AI Agent")?;
        let selection = Selection {
            revision: profiles.revision,
            alias: alias.into(),
            primary: roles.get(alias).ok_or("Unknown profile")?.clone(),
            low: roles["low"].clone(),
        };
        Ok((provider, selection))
    }
    pub(crate) fn ai_profiles(&self) -> Result<Profiles, String> {
        read(&*self.0.lock().map_err(err)?)
    }
    pub(crate) fn configure_ai_profiles(&self, config: Profiles) -> Result<Profiles, String> {
        config.validate()?;
        let mut db = self.0.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let current = read(&tx)?;
        if config.revision != current.revision {
            return Err("Profiles have changed: update the settings".into());
        }
        let mut next = config;
        next.revision = current.revision.checked_add(1).ok_or("Limit of versions")?;
        tx.execute("INSERT INTO ai_profiles VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![serde_json::to_string(&next).map_err(err)?]).map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(next)
    }
    pub(crate) fn ai_selection(&self, provider: &str, alias: &str) -> Result<Selection, String> {
        let all = self.ai_profiles()?;
        let roles = all.providers.get(provider).ok_or("Unknown agent")?;
        Ok(Selection {
            revision: all.revision,
            alias: alias.into(),
            primary: roles.get(alias).ok_or("Unknown profile")?.clone(),
            low: roles["low"].clone(),
        })
    }
}
pub fn codex_models(v: &Value) -> Result<Vec<ModelInfo>, String> {
    v["data"]
        .as_array()
        .filter(|a| a.len() <= 100)
        .ok_or("Improper Codex directory")?
        .iter()
        .map(|m| {
            Ok(ModelInfo {
                id: m["model"].as_str().ok_or("No ID model")?.into(),
                name: m["displayName"].as_str().unwrap_or("").into(),
                resolved_model: None,
                efforts: m["supportedReasoningEfforts"]
                    .as_array()
                    .ok_or("No effort")?
                    .iter()
                    .filter_map(|e| e["reasoningEffort"].as_str().map(str::to_owned))
                    .collect(),
            })
        })
        .collect()
}
pub fn claude_models(v: &Value) -> Result<Vec<ModelInfo>, String> {
    v["models"]
        .as_array()
        .filter(|a| a.len() <= 100)
        .ok_or("Claude did not provide a catalog of models")?
        .iter()
        .map(|m| {
            Ok(ModelInfo {
                id: m["value"].as_str().ok_or("No ID model")?.into(),
                name: m["displayName"].as_str().unwrap_or("").into(),
                resolved_model: m["resolvedModel"].as_str().map(str::to_owned),
                efforts: m["supportedEffortLevels"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}
pub fn validate_available(p: &Profile, catalog: &[ModelInfo]) -> Result<(), String> {
    let m = catalog.iter().find(|m| m.id == p.model).ok_or_else(|| {
        format!(
            "Model {} inaccessible in the installed CLI. Select available in the section AI.",
            p.model
        )
    })?;
    if !m.efforts.contains(&p.effort) {
        return Err(format!(
            "Model {} failed to confirm the effort {}",
            p.model, p.effort
        ));
    }
    Ok(())
}
pub fn validate_claude_actual(p: &Profile, actual: &str) -> Result<(), String> {
    let matches = if matches!(p.model.as_str(), "haiku" | "sonnet" | "opus") {
        actual.starts_with(&format!("claude-{}-", p.model))
    } else {
        actual == p.model
    };
    if matches {
        Ok(())
    } else {
        Err(format!(
            "Claude replaced the model {} on {actual}; stoppage",
            p.model
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migration_defaults_and_cas() {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let before = db.ai_profiles().unwrap();
        assert_eq!(before.providers["codex"]["low"].model, "gpt-6-luna");
        let mut config = before.clone();
        config
            .providers
            .get_mut("claude")
            .unwrap()
            .get_mut("medium")
            .unwrap()
            .model = "claude-sonnet-5-5".into();
        let next = db.configure_ai_profiles(config).unwrap();
        assert_eq!(next.revision, 2);
        assert_eq!(next.providers["codex"], before.providers["codex"]);
        assert!(db.configure_ai_profiles(before).is_err());
        assert_eq!(
            db.ai_selection("claude", "medium").unwrap().primary.model,
            "claude-sonnet-5-5"
        );
    }
    #[test]
    fn no_silent_fallback() {
        let p = Profile {
            model: "gpt-6-luna".into(),
            effort: "high".into(),
        };
        assert!(validate_available(&p, &[]).is_err());
        assert!(validate_available(
            &p,
            &[ModelInfo {
                id: p.model.clone(),
                name: "".into(),
                efforts: vec!["low".into()],
                resolved_model: None
            }]
        )
        .is_err());
        let p = Profile {
            model: "haiku".into(),
            effort: "high".into(),
        };
        assert!(validate_claude_actual(&p, "claude-sonnet-5-5").is_err());
        assert!(validate_claude_actual(&p, "claude-haiku-5-5").is_ok());
    }
    #[test]
    fn global_selection_includes_all_aliases_and_preserves_the_inactive_provider() {
        let db = Store::open(std::path::Path::new(":memory:")).unwrap();
        let codex = db.ai_profiles().unwrap().providers["codex"].clone();
        db.update_settings(
            serde_json::from_value(serde_json::json!({"autoAgent":"claude"})).unwrap(),
        )
        .unwrap();
        for alias in ["low", "medium", "high"] {
            let (agent, selection) = db.current_ai_selection(alias).unwrap();
            assert_eq!(agent, "claude");
            assert_eq!(selection.alias, alias);
            assert_eq!(
                selection.primary,
                db.ai_profiles().unwrap().providers["claude"][alias]
            );
            assert_eq!(
                selection.low,
                db.ai_profiles().unwrap().providers["claude"]["low"]
            );
        }
        assert_eq!(db.ai_profiles().unwrap().providers["codex"], codex);
        assert!(db.current_ai_selection("other").is_err());
        assert!(db.investigations().unwrap().is_empty());
        assert_eq!(db.auto_status(crate::model::now()).unwrap().runs, 0);
    }
}
