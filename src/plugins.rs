//! WASM rule plugins (SPEC_EXT_OPS O10, A-30): operator-supplied modules that can only add
//! blocks. Each call runs in a fresh wasmtime store and instance with fuel metering and a memory
//! limiter; modules import nothing, so a plugin has no access to the host beyond the request view
//! it is handed. Built only with the `plugins` cargo feature; without it the set is always empty
//! (config validation refuses enabled plugins, so this never silently drops a rule).
#![forbid(unsafe_code)]

use std::sync::atomic::AtomicU64;

use crate::config::PluginConfig;
use crate::normalize::NormalizedTarget;

/// Largest module file.
pub const MAX_MODULE_BYTES: u64 = 4 * 1024 * 1024;
/// Largest request view.
pub const MAX_VIEW_BYTES: usize = 8 * 1024;
/// Path bytes kept in the view.
pub const MAX_VIEW_PATH: usize = 2048;
/// Query keys kept in the view.
pub const MAX_QUERY_KEYS: usize = 32;

/// What a plugin decided about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The plugin blocks it.
    Block {
        /// Plugin name.
        plugin: String,
    },
    /// The plugin failed; `block` follows its `on_error`.
    Error {
        /// Plugin name.
        plugin: String,
        /// Fail closed.
        block: bool,
        /// Short cause (trap, fuel, memory, result) for the system log.
        detail: String,
        /// Log it now (at most once a minute per plugin).
        log: bool,
    },
}

/// Per-plugin counters (`/api/v1/plugins`, metrics).
#[derive(Debug, Default)]
pub struct Counters {
    /// Calls.
    pub calls: AtomicU64,
    /// Blocks.
    pub blocks: AtomicU64,
    /// Errors.
    pub errors: AtomicU64,
}

/// The request view handed to plugins (O10): no query values, headers, bodies, client or user.
pub fn view(t: &NormalizedTarget, connect: bool, profile: &str) -> Vec<u8> {
    let mut path = t.path.as_str();
    if path.len() > MAX_VIEW_PATH {
        let mut end = MAX_VIEW_PATH;
        while !path.is_char_boundary(end) {
            end -= 1;
        }
        path = path.get(..end).unwrap_or("/");
    }
    let keys: Vec<&str> = t
        .query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split('=').next())
        .filter(|k| !k.is_empty())
        .take(MAX_QUERY_KEYS)
        .map(|k| k.get(..k.len().min(64)).unwrap_or(""))
        .collect();
    let v = serde_json::json!({
        "v": 1,
        "phase": if connect { "connect" } else { "request" },
        "scheme": t.scheme.as_str(),
        "host": t.host.to_string(),
        "port": t.port,
        "path": path,
        "query_keys": keys,
        "profile": profile,
    });
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.truncate(MAX_VIEW_BYTES);
    out
}

#[cfg(feature = "plugins")]
mod imp {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

    use super::{Counters, MAX_MODULE_BYTES, Outcome, PluginConfig};
    use crate::config::PluginOnError;
    use crate::util::LockExt;

    struct State {
        limits: StoreLimits,
    }

    pub(super) struct Plugin {
        pub(super) name: String,
        on_error: PluginOnError,
        fuel: u64,
        max_memory: usize,
        engine: Engine,
        module: Module,
        pub(super) counters: Counters,
        last_log: Mutex<Option<Instant>>,
    }

    enum CallError {
        Fault(String),
    }

    impl Plugin {
        pub(super) fn load(cfg: &PluginConfig, engine: &Engine) -> Result<Self, String> {
            let name = &cfg.name;
            let meta = std::fs::metadata(&cfg.path).map_err(|e| format!("{name}: {e}"))?;
            if meta.len() > MAX_MODULE_BYTES {
                return Err(format!("{name}: module larger than 4 MiB"));
            }
            let bytes = std::fs::read(&cfg.path).map_err(|e| format!("{name}: {e}"))?;
            let module = Module::new(engine, &bytes).map_err(|e| format!("{name}: {e}"))?;
            if module.imports().len() != 0 {
                return Err(format!(
                    "{name}: modules must not import anything (no WASI, no host functions)"
                ));
            }
            let p = Self {
                name: name.clone(),
                on_error: cfg.on_error,
                fuel: cfg.fuel,
                max_memory: cfg.max_memory_bytes,
                engine: engine.clone(),
                module,
                counters: Counters::default(),
                last_log: Mutex::new(None),
            };
            // Probe: instantiation fits the limits and the exports have the right types. The
            // decision function itself is not run (its faults are handled per call).
            p.call(None).map(|_| ()).map_err(|CallError::Fault(e)| format!("{name}: {e}"))?;
            Ok(p)
        }

        /// Instantiate and resolve the exports; with a view, run the decision.
        fn call(&self, view: Option<&[u8]>) -> Result<i32, CallError> {
            let fault =
                |what: &str, e: &dyn std::fmt::Display| CallError::Fault(format!("{what}: {e}"));
            let limits = StoreLimitsBuilder::new()
                .memory_size(self.max_memory)
                .memories(1)
                .instances(1)
                .tables(4)
                .table_elements(10_000)
                .build();
            let mut store = Store::new(&self.engine, State { limits });
            store.limiter(|s| &mut s.limits);
            store.set_fuel(self.fuel).map_err(|e| fault("fuel", &e))?;
            let inst = Instance::new(&mut store, &self.module, &[])
                .map_err(|e| fault("instantiate", &e))?;
            let memory = inst
                .get_memory(&mut store, "memory")
                .ok_or_else(|| CallError::Fault("missing export `memory`".into()))?;
            let alloc = inst
                .get_typed_func::<i32, i32>(&mut store, "wf_alloc")
                .map_err(|e| fault("export `wf_alloc(i32) -> i32`", &e))?;
            let decide = inst
                .get_typed_func::<(i32, i32), i32>(&mut store, "wf_decide")
                .map_err(|e| fault("export `wf_decide(i32, i32) -> i32`", &e))?;
            let Some(view) = view else { return Ok(0) };
            let len = i32::try_from(view.len()).map_err(|e| fault("view", &e))?;
            let ptr = alloc.call(&mut store, len).map_err(|e| fault("wf_alloc", &e))?;
            let offset = usize::try_from(ptr)
                .map_err(|_| CallError::Fault("wf_alloc returned a negative pointer".into()))?;
            memory.write(&mut store, offset, view).map_err(|e| fault("view out of bounds", &e))?;
            decide.call(&mut store, (ptr, len)).map_err(|e| fault("wf_decide", &e))
        }

        pub(super) fn check(&self, view: &[u8]) -> Option<Outcome> {
            self.counters.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let err = match self.call(Some(view)) {
                Ok(0) => return None,
                Ok(1) => {
                    self.counters.blocks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Some(Outcome::Block { plugin: self.name.clone() });
                }
                Ok(other) => format!("wf_decide returned {other} (expected 0 or 1)"),
                Err(CallError::Fault(e)) => e,
            };
            self.counters.errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let now = Instant::now();
            let log = {
                let mut last = self.last_log.lock_or_recover();
                let due = last.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(60));
                if due {
                    *last = Some(now);
                }
                due
            };
            let detail: String = err.chars().take(200).collect();
            Some(Outcome::Error {
                plugin: self.name.clone(),
                block: self.on_error == PluginOnError::Block,
                detail,
                log,
            })
        }
    }

    pub(super) fn engine() -> Result<Engine, String> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.max_wasm_stack(256 * 1024);
        Engine::new(&cfg).map_err(|e| e.to_string())
    }
}

/// The loaded, enabled plugins in config order.
#[derive(Default)]
pub struct Plugins {
    #[cfg(feature = "plugins")]
    list: Vec<imp::Plugin>,
}

impl std::fmt::Debug for Plugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugins").field("names", &self.names()).finish()
    }
}

impl Plugins {
    /// Compile and probe every enabled plugin; any failure fails the whole set (the caller keeps
    /// the previous one on reload).
    #[cfg(feature = "plugins")]
    pub fn load(cfgs: &[PluginConfig]) -> Result<Self, String> {
        let enabled: Vec<&PluginConfig> = cfgs.iter().filter(|c| c.enabled).collect();
        if enabled.is_empty() {
            return Ok(Self::default());
        }
        let engine = imp::engine()?;
        let list =
            enabled.into_iter().map(|c| imp::Plugin::load(c, &engine)).collect::<Result<_, _>>()?;
        Ok(Self { list })
    }

    /// Without the `plugins` feature nothing can be enabled (config validation refuses it).
    #[cfg(not(feature = "plugins"))]
    pub fn load(cfgs: &[PluginConfig]) -> Result<Self, String> {
        if cfgs.iter().any(|c| c.enabled) {
            return Err("this binary was built without the `plugins` feature".into());
        }
        Ok(Self::default())
    }

    /// No plugin loaded.
    pub fn is_empty(&self) -> bool {
        self.names().is_empty()
    }

    /// Plugin names in order.
    pub fn names(&self) -> Vec<String> {
        #[cfg(feature = "plugins")]
        return self.list.iter().map(|p| p.name.clone()).collect();
        #[cfg(not(feature = "plugins"))]
        Vec::new()
    }

    /// Run the plugins in order on `view`; the first block or error decides.
    ///
    /// WASM runs synchronously and can take up to its fuel budget, so on a multi-thread tokio
    /// runtime it runs inside `block_in_place` and never stalls a worker (RV2-L2). Elsewhere
    /// (current-thread runtime, where `block_in_place` would panic, or no runtime) it runs
    /// directly.
    pub fn check(&self, view: &[u8]) -> Option<Outcome> {
        #[cfg(feature = "plugins")]
        {
            if !self.list.is_empty() {
                let run = || self.list.iter().find_map(|p| p.check(view));
                let multi_thread = tokio::runtime::Handle::try_current().is_ok_and(|h| {
                    h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
                });
                return if multi_thread { tokio::task::block_in_place(run) } else { run() };
            }
        }
        let _ = view;
        None
    }

    /// (name, calls, blocks, errors) per plugin.
    pub fn stats(&self) -> Vec<(String, u64, u64, u64)> {
        #[cfg(feature = "plugins")]
        return self
            .list
            .iter()
            .map(|p| {
                let c = &p.counters;
                (
                    p.name.clone(),
                    c.calls.load(std::sync::atomic::Ordering::Relaxed),
                    c.blocks.load(std::sync::atomic::Ordering::Relaxed),
                    c.errors.load(std::sync::atomic::Ordering::Relaxed),
                )
            })
            .collect();
        #[cfg(not(feature = "plugins"))]
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{TargetContext, canonicalize};

    #[test]
    fn view_has_no_query_values_and_is_bounded() {
        let long = "a".repeat(5000);
        let t = canonicalize(
            &format!("http://ex.test/{long}?token=SECRET&b=2"),
            TargetContext::PlainAbsolute,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&view(&t, false, "kids")).unwrap();
        assert_eq!(v["query_keys"], serde_json::json!(["token", "b"]));
        assert_eq!(v["profile"], "kids");
        assert!(v["path"].as_str().unwrap().len() <= MAX_VIEW_PATH);
        assert!(!serde_json::to_string(&v).unwrap().contains("SECRET"));
    }
}
