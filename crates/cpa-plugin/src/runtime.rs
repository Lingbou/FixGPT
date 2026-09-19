use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use fixgpt_core::policy::now_seconds;
use fixgpt_core::token::TurnState;
use fixgpt_core::{
    AccountKind, CredentialLimit, HEADER_NAME as STATE_HEADER, InjectionMode, RejectedStatus,
    Snapshot, StateFallback, StatePolicy, StateStore,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::host;
use crate::modeltrace;
use crate::modeltrace::INTERNAL_HEADER;

const PROBE_COOLDOWN_SECONDS: i64 = 180;
/// 降智信号：服务端会下发这个长度的 state，表示当前会话已被降级。
const DEGRADED_STATE_LEN: usize = 312;

/// 每次探测结束后让宿主喘息的时间：探测是同步的嵌套调用，会阻塞宿主处理其它请求。
const PROBE_YIELD: Duration = Duration::from_secs(5);
/// 卸载前等后台线程退出循环的上限。
///
/// 宿主会在 `cliproxy_plugin_shutdown` 返回后立刻 `dlclose`：线程如果还在跑，
/// 就会执行已经解除映射的代码页。空闲时线程几十毫秒内就能退出，这里只兜住那一小段时间。
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// 后台线程睡眠的切片长度，保证停止信号最多 50ms 就被看到。
const SLEEP_SLICE: Duration = Duration::from_millis(50);
/// 拒绝之后的最短冷却；上游给出更长的 Retry-After 时以它为准。
const REJECT_COOLDOWN_SECONDS: i64 = 180;
/// 检测结果落盘的位置。放在插件目录下，容器重启后仍在（该目录是挂载进来的）。
const MODELTRACE_RESULTS_FILE: &str = "modeltrace-results.json";
/// 采到的 state 落盘：重启后不必等一轮采集才能继续注入。
const STATE_FILE: &str = "turn-state.json";
/// 292/312 计数落盘：这是长期观测数据，不该因为重启归零。
const STATE_STATS_FILE: &str = "state-stats.json";
/// 采集出口池：由 ip-pool 脚本生成，挂在 state 目录里。
const EGRESS_POOL_FILE: &str = "pool.json";
/// 一轮采集最多换几个出口。
const HARVEST_ATTEMPTS: usize = 8;
/// 同轮两次尝试之间的间隔：宿主在嵌套调用期间是串行的，得给它喘息。
const HARVEST_ATTEMPT_INTERVAL: Duration = Duration::from_secs(3);
/// 一轮全失败后的冷却。
const HARVEST_FAIL_COOLDOWN_SECONDS: i64 = 600;
/// 一整轮下来"每个出口都只给降级响应"（312 / 被换成别的模型）时的冷却。
///
/// 这种窗口是上游容量/调度问题，通常持续几十分钟：继续贴着打只会白烧额度，
/// 还可能把账号状态弄得更糟，所以停久一点，等窗口过去再采。
const DEGRADED_HARVEST_COOLDOWN_SECONDS: i64 = 1800;
/// 上游报过载（5xx）之后，整个采集停多久。
///
/// 反复探测只会让上游更不愿意发 state，还会把账号自己打进限流；
/// sub2api 那边也是"401/403/429 立刻终止本轮"，这里对 5xx 同样处理。
const OVERLOAD_PAUSE_SECONDS: i64 = 900;
/// 一轮全失败后的冷却（上游不稳时别贴着 5 分钟打）。
const EGRESS_GOOD_TTL_SECONDS: i64 = 1800;
/// 单个出口失败后的冷却。免费订阅里大量节点已被 Cloudflare 拉黑，
/// 太短的冷却等于让它们马上回到轮换里继续浪费额度。
const EGRESS_FAIL_COOLDOWN_SECONDS: i64 = 1800;
/// 出口回了"降级响应"（200 却没有 state，或直接给 312 字节）后的冷却。
///
/// 这类失败跟着出口 IP 走：同一个出口换一次会话往往就能拿到 292，
/// 所以只把它停一小会儿，让轮换尽快去试别的出口。
const EGRESS_DEGRADED_COOLDOWN_SECONDS: i64 = 300;
/// 自动采集扫描间隔。
const AUTO_HARVEST_SCAN_SECONDS: i64 = 30;

/// 一轮采集失败后这个「账号 × 模型」停多久。
///
/// 全是降级响应（312 / 模型被换）说明是上游窗口问题，停久一点；
/// 其它失败（连接、被拦）按常规冷却。
fn harvest_cooldown(settled: bool, degraded_round: bool) -> i64 {
    if settled {
        PROBE_COOLDOWN_SECONDS
    } else if degraded_round {
        DEGRADED_HARVEST_COOLDOWN_SECONDS
    } else {
        HARVEST_FAIL_COOLDOWN_SECONDS
    }
}

fn modeltrace_results_path() -> PathBuf {
    // 插件目录是只读挂载，不能存运行期状态；按可写性依次尝试。
    let candidates = [
        PathBuf::from("/CLIProxyAPI/state").join(MODELTRACE_RESULTS_FILE),
        PathBuf::from("/CLIProxyAPI/logs").join(MODELTRACE_RESULTS_FILE),
        std::env::temp_dir().join(MODELTRACE_RESULTS_FILE),
    ];
    candidates
        .into_iter()
        .find(|path| {
            path.parent()
                .is_some_and(|parent| parent.is_dir() && is_writable(parent))
        })
        .unwrap_or_else(|| std::env::temp_dir().join(MODELTRACE_RESULTS_FILE))
}

/// 判断一份持久化的 state 现在是否还能用。
///
fn state_stats_path() -> PathBuf {
    modeltrace_results_path().with_file_name(STATE_STATS_FILE)
}

fn save_state_stats(stats: &HashMap<String, u64>) {
    let target = state_stats_path();
    let Some(parent) = target.parent().map(PathBuf::from) else {
        return;
    };
    let Ok(payload) = serde_json::to_vec_pretty(stats) else {
        return;
    };
    let temporary = parent.join(format!("{STATE_STATS_FILE}.tmp"));
    if std::fs::write(&temporary, payload).is_ok() {
        let _ = std::fs::rename(&temporary, target);
    }
}

fn load_state_stats() -> HashMap<String, u64> {
    std::fs::read(state_stats_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<HashMap<String, u64>>(&bytes).ok())
        .unwrap_or_default()
}

fn state_file_path() -> PathBuf {
    modeltrace_results_path().with_file_name(STATE_FILE)
}

/// 找出下一个到期的采集任务；`only_model` 用于优先补默认模型。
fn due_job(
    jobs: &mut HashMap<StateKey, Job>,
    now: i64,
    only_model: Option<&str>,
) -> Option<(StateKey, ProbeJob)> {
    for (key, job) in jobs.iter_mut() {
        if only_model.is_some_and(|model| job.model != model) {
            continue;
        }
        if now < job.next_probe {
            continue;
        }
        if job.limit.rejection(now).is_some() {
            continue;
        }
        if !job.store.needs_refresh(now) {
            job.next_probe = now.saturating_add(PROBE_COOLDOWN_SECONDS);
            continue;
        }
        return Some((
            key.clone(),
            ProbeJob {
                key: key.clone(),
                auth_id: job.auth_id.clone(),
                auth_index: job.auth_index.clone(),
                model: job.model.clone(),
                store: Arc::clone(&job.store),
            },
        ));
    }
    None
}

/// 持久化每个账号 + 模型当前可用的 state。
fn save_states(jobs: &HashMap<StateKey, Job>) {
    let now = now_seconds();
    let records: Vec<Value> = jobs
        .values()
        .filter_map(|job| {
            let snapshot = job.store.acquire(now)?;
            Some(json!({
                "auth_id": job.auth_id,
                "auth_index": job.auth_index,
                "model": job.model,
                "account": job.account,
                "value": snapshot.token.value,
            }))
        })
        .collect();
    let target = state_file_path();
    let Some(parent) = target.parent().map(PathBuf::from) else {
        return;
    };
    let Ok(payload) = serde_json::to_vec_pretty(&records) else {
        return;
    };
    let temporary = parent.join(format!("{STATE_FILE}.tmp"));
    if std::fs::write(&temporary, payload).is_ok() {
        let _ = std::fs::rename(&temporary, target);
    }
}

fn load_states_at(path: &std::path::Path) -> Vec<Value> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Vec<Value>>(&bytes).ok())
        .unwrap_or_default()
}

/// 用磁盘上的 state 直接重建采集任务。
///
/// 任务本身就是"这份 state 属于哪个账号 + 哪个模型"的载体。重建它，插件重启后
/// 就继续续采，不必等下一条真实请求；磁盘记录也是 state 的唯一一份真值。
fn restore_jobs() -> HashMap<StateKey, Job> {
    restore_jobs_at(&state_file_path())
}

fn restore_jobs_at(path: &std::path::Path) -> HashMap<StateKey, Job> {
    let now = now_seconds();
    let mut jobs: HashMap<StateKey, Job> = HashMap::new();
    for record in load_states_at(path) {
        let Some(auth_id) = record.get("auth_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(model) = record.get("model").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = record.get("value").and_then(Value::as_str) else {
            continue;
        };
        let Ok(token) = TurnState::parse(value) else {
            continue;
        };
        let account = record
            .get("account")
            .and_then(|raw| serde_json::from_value::<AccountKind>(raw.clone()).ok())
            .unwrap_or(AccountKind::Personal);
        let auth_index = record
            .get("auth_index")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut job = Job::new(auth_id.to_owned(), auth_index, model.to_owned(), account);
        if job.store.offer(token, now) {
            job.last_result = Some("已从磁盘恢复 state".to_owned());
            jobs.insert(
                StateKey {
                    auth_id: auth_id.to_owned(),
                    model: model.to_owned(),
                },
                job,
            );
        }
    }
    jobs
}

fn is_writable(directory: &std::path::Path) -> bool {
    let probe = directory.join(".fixgpt-write-probe");
    match std::fs::write(&probe, b"1") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// 把检测结果写到磁盘；失败只影响持久化，不影响本次检测结论。
fn save_modeltrace_results(results: &HashMap<String, Value>) {
    save_modeltrace_results_at(&modeltrace_results_path(), results);
}

fn save_modeltrace_results_at(target: &std::path::Path, results: &HashMap<String, Value>) {
    let Some(parent) = target.parent().map(PathBuf::from) else {
        return;
    };
    let records: Vec<Value> = results
        .iter()
        .map(|(key, report)| json!({ "key": key, "report": report }))
        .collect();
    let Ok(payload) = serde_json::to_vec_pretty(&records) else {
        return;
    };
    let temporary = parent.join(format!("{MODELTRACE_RESULTS_FILE}.tmp"));
    if std::fs::write(&temporary, payload).is_ok() {
        let _ = std::fs::rename(&temporary, target);
    }
}

/// 启动时读回上次的结果。文件缺失或损坏时按"没有历史结果"处理。
fn load_modeltrace_results() -> HashMap<String, Value> {
    load_modeltrace_results_at(&modeltrace_results_path())
}

fn load_modeltrace_results_at(path: &std::path::Path) -> HashMap<String, Value> {
    let Ok(bytes) = std::fs::read(path) else {
        return HashMap::new();
    };
    let Ok(records) = serde_json::from_slice::<Vec<Value>>(&bytes) else {
        return HashMap::new();
    };
    records
        .into_iter()
        .filter_map(|record| {
            let key = record.get("key").and_then(Value::as_str)?.to_owned();
            let report = record.get("report").cloned()?;
            Some((key, report))
        })
        .collect()
}

/// 采集出口：一个代理地址 + 一个好认的名字（页面上显示用）。
#[derive(Clone, Debug, PartialEq, Eq)]
struct EgressNode {
    url: String,
    label: String,
}

fn egress_pool_path() -> PathBuf {
    modeltrace_results_path().with_file_name(EGRESS_POOL_FILE)
}

/// 没有历史请求时，用模型库里的默认模型作为采集目标。
fn default_harvest_model() -> String {
    let models = modeltrace::supported_models();
    if models.iter().any(|model| model == "gpt-6-astra") {
        return "gpt-6-astra".to_owned();
    }
    models
        .into_iter()
        .next()
        .unwrap_or_else(|| "gpt-6-astra".to_owned())
}

/// 读出口池。文件缺失或格式不对 = 没有池子，自动采集随之停用，
/// 插件退回原来的"单出口 + 真实请求触发"行为。
fn load_egress_pool() -> Vec<EgressNode> {
    load_egress_pool_at(&egress_pool_path())
}

fn load_egress_pool_at(path: &std::path::Path) -> Vec<EgressNode> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    value
        .get("proxies")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let url = item.get("url").and_then(Value::as_str)?.trim().to_owned();
                    if url.is_empty() {
                        return None;
                    }
                    let label = item
                        .get("label")
                        .and_then(Value::as_str)
                        .unwrap_or(&url)
                        .to_owned();
                    Some(EgressNode { url, label })
                })
                .collect()
        })
        .unwrap_or_default()
}

static RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();

pub fn start() {
    let runtime = RUNTIME.get_or_init(|| Arc::new(Runtime::new())).clone();
    runtime.start_worker();
}

pub fn stop() {
    if let Some(runtime) = RUNTIME.get() {
        runtime.stop_worker();
    }
}

/// 插件即将被卸载：停掉后台线程并等待所有检测线程退出。
pub fn quiesce() {
    if let Some(runtime) = RUNTIME.get() {
        runtime.quiesce();
    }
}

/// 宿主侧"没有可用凭据"的报错。
///
/// CPA 会因为 401/403/429、上游过载等原因把一条凭据短暂冷掉，之后对
/// `host.model.execute` 直接回这类错误。这是**凭据级**结论：换出口、换 IP
/// 都不会好，继续轮换只是浪费时间和额度，还会把好出口误标成失败。
fn credential_unavailable(error: &str) -> bool {
    const CODES: [&str; 4] = [
        "auth_unavailable",
        "auth_not_found",
        // 上游吊销了这条会话：refresh 也会 401（refresh_token_invalidated），
        // 只能重新登录，换出口、换模型都没用。
        "token_revoked",
        "refresh_token_invalidated",
    ];
    // host.rs 把宿主错误码放在消息最前面（`<code>: <message>`），优先按它判定。
    if let Some((prefix, _)) = error.split_once(':')
        && CODES.contains(&prefix.trim().to_ascii_lowercase().as_str())
    {
        return true;
    }
    // 兼容没有错误码的形态。
    let lower = error.to_ascii_lowercase();
    CODES.iter().any(|code| lower.contains(code))
        || lower.contains("no auth available")
        || lower.contains("invalidated oauth token")
}

/// 从失败响应里取一小段提示，用来说明"为什么没有 state 头"。
///
/// 出口被 Cloudflare 拦下来时上游会回一整个 HTML 页面，直接把状态码和首段
/// 文本带出来，比"没有 state 头"有用得多。
fn response_hint(result: &Value) -> String {
    let Some(body) = result.get("body").and_then(Value::as_str) else {
        return String::new();
    };
    let Ok(bytes) = STANDARD.decode(body) else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let snippet = plain_text_snippet(&text, 60);
    if snippet.is_empty() {
        String::new()
    } else {
        format!("（响应：{snippet}…）")
    }
}

/// 把一个出口 URL 展开成"这一次真正要用"的 URL。
///
/// 动态 IP 服务的用法是"同一个地址、换会话 id = 换出口 IP"：
/// - URL 里的 `{sid}` / `{random}` 占位符会被替换成随机会话号；
/// - 1024proxy 这类把会话写在用户名里的服务（`...-sid-xxxx-t-5`），
///   这里直接把 `-sid-` 段轮换掉，没有的话补一个。
///
/// 出口池里的条目身份（失败记录、成功记录）仍然按原始 URL 算，不受影响。
fn expand_egress_url(raw: &str) -> String {
    let sid = format!("{:06}", rand::random::<u32>() % 900_000 + 100_000);
    let expanded = raw.replace("{sid}", &sid).replace("{random}", &sid);
    let Some(scheme_end) = expanded.find("://") else {
        return expanded;
    };
    let prefix = &expanded[..scheme_end + 3];
    let rest = &expanded[scheme_end + 3..];
    let Some(at) = rest.rfind('@') else {
        return expanded;
    };
    let (userinfo, host) = (&rest[..at], &rest[at + 1..]);
    let hostname = host
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if hostname != "1024proxy.io" && !hostname.ends_with(".1024proxy.io") {
        return expanded;
    }
    let (user, password) = match userinfo.split_once(':') {
        Some((user, password)) => (user, Some(password)),
        None => (userinfo, None),
    };
    let rotated = match user.to_ascii_lowercase().find("-sid-") {
        Some(position) => {
            let after = position + "-sid-".len();
            let tail = user[after..].find('-').unwrap_or(user.len() - after);
            format!("{}-sid-{}{}", &user[..position], sid, &user[after + tail..])
        }
        None => format!("{user}-sid-{sid}"),
    };
    match password {
        Some(password) => format!("{prefix}{rotated}:{password}@{host}"),
        None => format!("{prefix}{rotated}@{host}"),
    }
}

/// 错误文本同样要过一遍：宿主的报错里经常整段带着上游的 HTML。
fn compact_error(error: &str) -> String {
    plain_text_snippet(error, 160)
}

/// 把响应压成一小段人话：先丢掉 script/style 整块，再去掉所有标签。
///
/// 出口被 Cloudflare 拦下来时回的是整页 HTML，直接贴到页面上既长又看不懂；
/// 处理完之后通常正好剩下 "Sorry, you have been blocked" 这类关键信息。
fn plain_text_snippet(text: &str, limit: usize) -> String {
    let without_scripts = strip_blocks(text, "script");
    let without_styles = strip_blocks(&without_scripts, "style");
    let mut out = String::new();
    let mut rest = without_styles.as_str();
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        match rest[start..].find('>') {
            Some(end) => rest = &rest[start + end + 1..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(limit)
        .collect()
}

/// 丢掉 `<tag ...>…</tag>` 整块内容（大小写不敏感）。
fn strip_blocks(text: &str, tag: &str) -> String {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let lower = text.to_ascii_lowercase();
    let mut out = String::new();
    let mut cursor = 0_usize;
    while let Some(offset) = lower[cursor..].find(&open) {
        let start = cursor + offset;
        let Some(close_offset) = lower[start..].find(&close) else {
            break;
        };
        out.push_str(&text[cursor..start]);
        cursor = start + close_offset + close.len();
    }
    out.push_str(&text[cursor..]);
    out
}

/// 分片睡眠：停止信号一置位就尽快返回，别让宿主等满一整轮。
fn interruptible_sleep(running: &AtomicBool, total: Duration) {
    let mut left = total;
    while left > Duration::ZERO {
        if !running.load(Ordering::Acquire) {
            return;
        }
        let slice = SLEEP_SLICE.min(left);
        thread::sleep(slice);
        left -= slice;
    }
}

fn runtime() -> Result<&'static Arc<Runtime>, String> {
    RUNTIME
        .get()
        .ok_or_else(|| "FixGPT runtime is not initialized".to_owned())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StateKey {
    auth_id: String,
    model: String,
}

#[derive(Clone)]
struct Job {
    auth_id: String,
    auth_index: Option<String>,
    model: String,
    account: AccountKind,
    store: Arc<StateStore>,
    next_probe: i64,
    last_result: Option<String>,
    /// 上游对该凭据给出的 401/403/429 结论；优先于任何有效的 turn-state。
    limit: CredentialLimit,
    /// 最近一次生成请求的处理方式（注入 / 兜底 / 拒绝）。
    last_mode: Option<InjectionMode>,
    /// 最近一次采集的外部观测：上游实际返回的模型、state 长度、是否被接受。
    probe_observation: Option<Value>,
}

impl Job {
    fn new(
        auth_id: String,
        auth_index: Option<String>,
        model: String,
        account: AccountKind,
    ) -> Self {
        let store = Arc::new(StateStore::new(StatePolicy::for_account(&account)));
        Self {
            auth_id,
            auth_index,
            model,
            account,
            store,
            next_probe: 0,
            last_result: None,
            limit: CredentialLimit::new(),
            last_mode: None,
            probe_observation: None,
        }
    }
}

#[derive(Clone)]
struct Inflight {
    key: StateKey,
    snapshot: Snapshot,
}

/// 本次请求最终的处理方式；响应回来时据此给出明确标记。
#[derive(Clone)]
struct RequestMode {
    mode: InjectionMode,
    auth_id: String,
}

struct Runtime {
    jobs: Mutex<HashMap<StateKey, Job>>,
    inflight: Mutex<HashMap<String, Inflight>>,
    modes: Mutex<HashMap<String, RequestMode>>,
    /// 每种处理方式累计出现次数，用于在页面上确认注入是否真的生效。
    mode_stats: Mutex<HashMap<String, u64>>,
    /// 上游返回的 state 长度计数：292（正常）/ 332（Team）/ 312（降智）/ 其它。
    state_stats: Mutex<HashMap<String, u64>>,
    /// 已经观测过的请求。
    ///
    /// 流式响应会按 chunk 多次调用响应拦截，同一个请求必须只观测一次——
    /// 否则 strikes 会被重复累加（可能触发错误的状态切换），计数也会被放大。
    observed: Mutex<HashSet<String>>,
    modeltrace_results: Mutex<HashMap<String, Value>>,
    modeltrace_tasks: Mutex<HashMap<String, ModeltraceTask>>,
    modeltrace_seq: AtomicU64,
    running: AtomicBool,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// 检测线程句柄：插件卸载前必须全部 join，否则 dlclose 后线程会跑进已解除映射的代码页。
    detect_threads: Mutex<Vec<JoinHandle<()>>>,
    /// 关闭后既不注入也不采集，等于原项目的 passthrough 开关。
    injection_enabled: AtomicBool,
    /// 没有可用 state 时的策略（严格 / 兜底），对应原项目 state_fallback。
    fallback: Mutex<StateFallback>,
    /// 采集出口池。空 = 没有池子：不轮换、也不自动采集。
    egress_pool: Mutex<Vec<EgressNode>>,
    /// 出口轮换游标。
    egress_cursor: AtomicU64,
    /// 出口失败冷却：url -> 冷却到的时间。
    egress_failures: Mutex<HashMap<String, i64>>,
    /// 真的采到过合格 state 的出口：url -> 最后一次成功的时间。
    ///
    /// 免费订阅里"能用的出口"是少数，逮到一个就优先继续用它，比每轮重新抽签靠谱。
    egress_good: Mutex<HashMap<String, i64>>,
    /// 上一次自动采集扫描的时间。
    last_auto_scan: AtomicU64,
    /// 上游过载时的全局暂停：暂停到的秒数（0 = 没暂停）。
    harvest_pause_until: AtomicU64,
    /// 暂停原因，用于页面显示。
    harvest_pause_reason: Mutex<Option<String>>,
    /// 上一轮是"账号降级/上游过载"收场的：恢复后只轻轻试一次，
    /// 确认账号好了再回到正常的多次尝试。
    gentle_harvest: AtomicBool,
}

impl Runtime {
    fn new() -> Self {
        Self {
            jobs: Mutex::new(restore_jobs()),
            inflight: Mutex::new(HashMap::new()),
            modes: Mutex::new(HashMap::new()),
            mode_stats: Mutex::new(HashMap::new()),
            state_stats: Mutex::new(load_state_stats()),
            observed: Mutex::new(HashSet::new()),
            modeltrace_results: Mutex::new(load_modeltrace_results()),
            modeltrace_tasks: Mutex::new(HashMap::new()),
            modeltrace_seq: AtomicU64::new(1),
            running: AtomicBool::new(true),
            worker: Mutex::new(None),
            detect_threads: Mutex::new(Vec::new()),
            injection_enabled: AtomicBool::new(true),
            fallback: Mutex::new(StateFallback::default()),
            egress_pool: Mutex::new(load_egress_pool()),
            egress_cursor: AtomicU64::new(0),
            egress_failures: Mutex::new(HashMap::new()),
            egress_good: Mutex::new(HashMap::new()),
            last_auto_scan: AtomicU64::new(0),
            harvest_pause_until: AtomicU64::new(0),
            harvest_pause_reason: Mutex::new(None),
            gentle_harvest: AtomicBool::new(false),
        }
    }

    fn start_worker(self: &Arc<Self>) {
        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if worker.is_some() {
            return;
        }
        self.running.store(true, Ordering::Release);
        let runtime = Arc::clone(self);
        *worker = Some(thread::spawn(move || runtime.worker_loop()));
    }

    /// 停止后台线程：置停止位，然后有限度地等它们真的退出。
    ///
    /// 线程池不能无限等（探测卡在上游时可能几分钟不返回），但完全不等也不行：
    /// `dlclose` 之后仍在运行的线程会踩到已解除映射的代码页。所以等待有上限，
    /// 空闲情况下睡眠被切成 50ms 片，几十毫秒就能收干净。
    fn stop_worker(&self) {
        self.running.store(false, Ordering::Release);
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let mut handles: Vec<JoinHandle<()>> = worker.into_iter().collect();
        {
            let mut threads = self
                .detect_threads
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            handles.append(&mut threads);
        }

        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while Instant::now() < deadline && handles.iter().any(|handle| !handle.is_finished()) {
            thread::sleep(SLEEP_SLICE);
        }

        // 已经结束的句柄直接回收；还在跑的只能留着，由进程退出收尾。
        handles.retain(|handle| handle.is_finished());
        *self
            .detect_threads
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = handles;
    }

    /// 插件即将被卸载：停止接收新任务，让所有循环尽快自行退出。
    fn quiesce(&self) {
        self.stop_worker();
    }

    fn worker_loop(self: Arc<Self>) {
        while self.running.load(Ordering::Acquire) {
            self.maybe_auto_harvest();
            if let Some(job) = self.next_due_job() {
                self.probe_job(job);
                continue;
            }
            self.run_probe_round();
            interruptible_sleep(&self.running, PROBE_YIELD);
        }
    }
    fn resolve_auth_id_values(
        &self,
        auth_id: &str,
        auth_index: Option<&str>,
    ) -> Result<String, String> {
        if !auth_id.is_empty() {
            return Ok(auth_id.to_owned());
        }
        let Some(index) = auth_index else {
            return Err("job has neither auth_id nor auth_index".to_owned());
        };
        let result = host::request_json("host.auth.get_runtime", &json!({ "auth_index": index }))?;
        result
            .pointer("/auth/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "CPA did not return an auth ID for auth_index".to_owned())
    }
    /// 每 30 秒扫一次账号目录：只要池子存在，就给没有可用 state 的 Codex 账号
    /// 自动建立采集任务。这就是"后台自动采集"——不依赖真实请求。
    fn maybe_auto_harvest(&self) {
        if !self.injection_enabled.load(Ordering::Acquire) {
            return;
        }
        let now = now_seconds();
        if now.saturating_sub(self.last_auto_scan.load(Ordering::Acquire) as i64)
            < AUTO_HARVEST_SCAN_SECONDS
        {
            return;
        }
        self.last_auto_scan.store(now as u64, Ordering::Release);

        // 每轮重新读一次池子：脚本改了池子不用重启插件。
        self.apply_egress_pool(load_egress_pool());
        if self
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty()
        {
            return;
        }

        for file in self.codex_auth_files() {
            if file.cooling_all {
                continue;
            }
            for model in self.harvest_models_with_priority(&file.auth_id) {
                // CPA 正在冷这条凭据的这个模型：等它恢复再采，别硬撞。
                if file.cooling_models.iter().any(|cooling| cooling == &model) {
                    continue;
                }
                let _ = self.ensure_job(
                    StateKey {
                        auth_id: file.auth_id.clone(),
                        model: model.clone(),
                    },
                    file.auth_id.clone(),
                    file.auth_index.clone(),
                    model,
                    AccountKind::Personal,
                );
            }
        }
    }

    /// 采集目标：这个账号已经出现过的模型；一个都没有时用默认模型。
    fn harvest_models(&self, auth_id: &str) -> Vec<String> {
        let mut models: Vec<String> = {
            let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
            jobs.values()
                .filter(|job| job.auth_id == auth_id)
                .map(|job| job.model.clone())
                .collect()
        };
        if models.is_empty() {
            models.push(default_harvest_model());
        }
        models.sort();
        models.dedup();
        models
    }

    /// 这一轮这个账号要保证有哪些采集任务：已经出现过的模型 + 默认模型。
    ///
    /// 重启后如果先来的请求是别的模型，`harvest_models` 里就不会有默认模型，
    /// 于是 astra 会一直没有人采 —— 所以默认模型始终补一个任务。
    fn harvest_models_with_priority(&self, auth_id: &str) -> Vec<String> {
        let mut models = self.harvest_models(auth_id);
        let priority = default_harvest_model();
        if !models.contains(&priority) {
            models.push(priority);
        }
        models.sort();
        models.dedup();
        models
    }

    /// 账号目录，含 CPA 侧对该账号/模型的冷却状态。
    fn codex_auth_files(&self) -> Vec<CodexAuthFile> {
        let mut out = Vec::new();
        if let Ok(result) = host::request_json("host.auth.list", &json!({}))
            && let Some(files) = result.get("files").and_then(Value::as_array)
        {
            for file in files {
                let disabled = file
                    .get("disabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let provider = file
                    .get("provider")
                    .or_else(|| file.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if disabled || !provider.eq_ignore_ascii_case("codex") {
                    continue;
                }
                let auth_id = file
                    .get("id")
                    .or_else(|| file.get("auth_index"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if auth_id.is_empty() {
                    continue;
                }
                let label = file
                    .get("email")
                    .or_else(|| file.get("label"))
                    .and_then(Value::as_str)
                    .unwrap_or(&auth_id)
                    .to_owned();
                let auth_index = file
                    .get("auth_index")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                // CPA 会按模型/账号给冷却（例如上游 502 之后）。正在冷却的目标
                // 先别采集：撞上去只会拿到 auth_unavailable，白白浪费一轮。
                let mut cooling_models = Vec::new();
                let mut cooling_all = false;
                if let Some(items) = file.get("cooldowns").and_then(Value::as_array) {
                    for item in items {
                        let remaining = item
                            .get("remaining_seconds")
                            .and_then(Value::as_i64)
                            .unwrap_or_default();
                        if remaining <= 0 {
                            continue;
                        }
                        match item.get("scope").and_then(Value::as_str) {
                            Some("model") => {
                                if let Some(model) = item.get("model_key").and_then(Value::as_str) {
                                    cooling_models.push(model.to_owned());
                                }
                            }
                            // provider / 账号级冷却：整条凭据先放着。
                            _ => cooling_all = true,
                        }
                    }
                }
                out.push(CodexAuthFile {
                    auth_id,
                    auth_index,
                    label,
                    cooling_models,
                    cooling_all,
                });
            }
        }
        out
    }

    /// 上游过载：所有采集一起停一会儿，别把账号自己打进限流。
    fn pause_harvest(&self, reason: &str, seconds: i64) {
        // 账号级/上游级的问题：下次恢复时先单发一次探探路。
        self.gentle_harvest.store(true, Ordering::Release);
        let until = now_seconds().saturating_add(seconds);
        if self.harvest_pause_until.load(Ordering::Acquire) as i64 >= until {
            return;
        }
        self.harvest_pause_until
            .store(until as u64, Ordering::Release);
        *self
            .harvest_pause_reason
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(reason.to_owned());
    }

    /// 现在是不是处于"上游过载"的暂停期。
    fn harvest_paused(&self) -> bool {
        now_seconds() < self.harvest_pause_until.load(Ordering::Acquire) as i64
    }

    /// 暂停状态（剩余秒数 + 原因），没有暂停时返回 None。
    fn harvest_pause_state(&self) -> Option<(i64, String)> {
        let until = self.harvest_pause_until.load(Ordering::Acquire) as i64;
        let now = now_seconds();
        if now >= until {
            return None;
        }
        let reason = self
            .harvest_pause_reason
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .unwrap_or_else(|| "上游过载".to_owned());
        Some((until - now, reason))
    }

    /// 换用一份新的出口池；内容变了就清掉旧的失败记录。
    ///
    /// 订阅刷新后端口号不变、背后的节点却换了，旧记录会让新节点被误跳。
    fn apply_egress_pool(&self, pool: Vec<EgressNode>) -> bool {
        let mut current = self
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *current == pool {
            return false;
        }
        *current = pool;
        drop(current);
        self.egress_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.egress_good
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        true
    }

    /// 这一轮最多试几个出口。
    ///
    /// 手上还没有可用 state 时，从上一次的位置起连着换出口试——这就是"预筛"：
    /// 一轮的代价就能看出哪些出口还能拿到 state，失败的在冷却期内会被跳过。
    /// 出口池再大也只走 `HARVEST_ATTEMPTS` 个，免得一轮把账号扫成异常流量。
    fn round_attempts(&self, job: &ProbeJob) -> usize {
        if job.store.acquire(now_seconds()).is_some() {
            return HARVEST_ATTEMPTS;
        }
        if self.gentle_harvest.load(Ordering::Acquire) {
            return 1;
        }
        let total = self
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        total.clamp(1, HARVEST_ATTEMPTS)
    }

    /// 轮换取下一个可用出口；池子为空时返回 None（等于不指定出口）。
    fn next_egress(&self, now: i64) -> Option<EgressNode> {
        let pool = self
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if pool.is_empty() {
            return None;
        }
        let start = self.egress_cursor.fetch_add(1, Ordering::Relaxed) as usize;
        let failures = self
            .egress_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let available =
            |node: &EgressNode| !failures.get(&node.url).is_some_and(|until| *until > now);
        // 优先用"确实采到过合格 state"的出口（新鲜度 30 分钟内算数）。
        {
            let good = self
                .egress_good
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let fresh: Vec<&EgressNode> = pool
                .iter()
                .filter(|node| {
                    good.get(&node.url)
                        .is_some_and(|at| now.saturating_sub(*at) < EGRESS_GOOD_TTL_SECONDS)
                        && available(node)
                })
                .collect();
            if !fresh.is_empty() {
                return Some(fresh[start % fresh.len()].clone());
            }
        }
        for offset in 0..pool.len() {
            let node = &pool[(start + offset) % pool.len()];
            if available(node) {
                return Some(node.clone());
            }
        }
        // 全在冷却里：仍然轮一个，别让采集彻底停住。
        Some(pool[start % pool.len()].clone())
    }

    /// 记一个出口真的采到了合格 state（复验通过的那种）。
    fn note_egress_good(&self, url: &str, now: i64) {
        let mut good = self
            .egress_good
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        good.insert(url.to_owned(), now);
        if good.len() > 512 {
            good.retain(|_, at| now.saturating_sub(*at) < EGRESS_GOOD_TTL_SECONDS);
        }
    }

    /// 记一次出口的成败：失败先进冷却，成功立刻恢复。
    fn note_egress(&self, url: &str, ok: bool, now: i64) {
        let mut failures = self
            .egress_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if ok {
            failures.remove(url);
        } else {
            failures.insert(
                url.to_owned(),
                now.saturating_add(EGRESS_FAIL_COOLDOWN_SECONDS),
            );
        }
        if failures.len() > 512 {
            failures.retain(|_, until| *until > now);
        }
    }

    /// 记一次"这个出口当前被降级"：正常作答却没有 state，或直接收到 312。
    ///
    /// 降级是跟着出口 IP 走的，换个出口往往立刻就能拿到 292，
    /// 所以只停一小会儿，别把整条采集链路一起停了。
    fn note_egress_degraded(&self, url: &str, now: i64) {
        let until = now.saturating_add(EGRESS_DEGRADED_COOLDOWN_SECONDS);
        let mut failures = self
            .egress_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = failures.entry(url.to_owned()).or_insert(until);
        if *entry < until {
            *entry = until;
        }
        if failures.len() > 512 {
            failures.retain(|_, until| *until > now);
        }
    }

    /// 上游是否已经拒绝过这条凭据（拒绝后换出口也没用）。
    fn credential_rejected(&self, key: &StateKey, now: i64) -> bool {
        self.jobs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(key)
            .is_some_and(|job| job.limit.rejection(now).is_some())
    }

    fn next_due_job(&self) -> Option<ProbeJob> {
        if self.harvest_paused() {
            return None;
        }
        let now = now_seconds();
        let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        let mut selected = None;
        if !self.injection_enabled.load(Ordering::Acquire) {
            return None;
        }
        // 默认模型还没有 state 时只采它：一个账号同时补多个模型既费额度，
        // 也更容易被上游当成异常流量。
        let priority = default_harvest_model();
        let prefer_priority = jobs
            .values()
            .any(|job| job.model == priority && job.store.acquire(now).is_none());
        if prefer_priority {
            selected = due_job(&mut jobs, now, Some(&priority)).map(|(_, job)| job);
        }
        if selected.is_none() {
            selected = due_job(&mut jobs, now, None).map(|(_, job)| job);
        }
        selected
    }

    /// 一轮采集：一次只发一个探测，命中即停。
    ///
    /// 宿主在一次模型调用进行中不处理其它请求，所以剩下的尝试留到下一轮，
    /// 中间由 worker 的 sleep 让宿主有机会处理普通请求。
    fn run_probe_round(&self) {
        let Some(job) = self.next_due_job() else {
            return;
        };
        let satisfied = self
            .jobs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&job.key)
            .is_some_and(|entry| entry.store.acquire(now_seconds()).is_some());
        if satisfied {
            return;
        }
        self.probe_job(job.clone());
    }

    /// 最近一次采集的外部观测：上游实际返回的模型与 state 长度。
    ///
    /// 这是排查降智最关键的一行——能直接看出上游给的是通行证还是降智信号。
    /// 上游过载暂停期间，卡片上直接说明白，避免误以为插件不工作。
    fn pause_note(&self) -> Option<String> {
        self.harvest_pause_state()
            .map(|(left, reason)| format!("{reason}，采集暂停中（还剩 {}）", human_seconds(left)))
    }

    fn probe_summary(&self, auth_id: &str, model: &str) -> String {
        if let Some(note) = self.pause_note() {
            return note;
        }
        let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        let Some(job) = jobs
            .values()
            .find(|job| job.auth_id == auth_id && job.model == model)
        else {
            return "还没有采集记录".to_owned();
        };
        let Some(observation) = &job.probe_observation else {
            return "还没有采集记录".to_owned();
        };
        if let Some(error) = observation.get("error").and_then(Value::as_str) {
            let egress = observation
                .get("egress")
                .and_then(Value::as_str)
                .map(|label| format!(" · 出口 {label}"))
                .unwrap_or_default();
            return format!("采集失败：{error}{egress}");
        }
        let Some(len) = observation.get("state_len").and_then(Value::as_i64) else {
            return "还没有采集记录".to_owned();
        };
        let egress = observation
            .get("egress")
            .and_then(Value::as_str)
            .map(|label| format!(" · 出口 {label}"))
            .unwrap_or_default();
        if observation
            .get("degraded_signal")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return format!("{len} 字节 · 降智信号（312）{egress}");
        }
        if observation.get("model_matches").and_then(Value::as_bool) == Some(true) {
            let served = observation
                .get("served_model")
                .and_then(Value::as_str)
                .unwrap_or(model);
            return format!("{len} 字节 · {served} · 模型一致{egress}");
        }
        let served = observation
            .get("served_model")
            .and_then(Value::as_str)
            .unwrap_or("未知");
        format!("{len} 字节 · 实际返回 {served}{egress}")
    }

    /// 给账号卡片用的状态摘要：(样式类, 文案)。
    fn state_summary(&self, auth_id: &str, model: &str) -> (&'static str, String) {
        let now = now_seconds();
        {
            let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(job) = jobs
                .values()
                .find(|job| job.auth_id == auth_id && job.model == model)
            {
                if job.limit.rejection(now).is_some() {
                    return ("bad", "state 被上游拒绝".to_owned());
                }
                let state = job.store.status(now);
                if state.usable {
                    return (
                        "ok",
                        format!("正常 · {}", human_seconds(state.remaining_seconds)),
                    );
                }
                if let Some(observation) = &job.probe_observation {
                    if observation
                        .get("degraded_signal")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        return ("warn", "state 已失效 · 收到 312".to_owned());
                    }
                    if observation.get("state_len").is_some()
                        && observation.get("model_matches").and_then(Value::as_bool) == Some(false)
                    {
                        return ("warn", "state 无效 · 模型不符".to_owned());
                    }
                }
                return ("warn", "state 采集中".to_owned());
            }
        }
        match self.verified_state_for(auth_id, model) {
            Some(_) => ("ok", "state 可用".to_owned()),
            None => ("warn", "尚无 state".to_owned()),
        }
    }

    /// 按业务请求的结果计数。
    ///
    /// 只数"上游返回了 state"是错的口径：注入生效时上游不会再下发 state，
    /// 那种情况恰恰是正常的。真正该回答的问题是"这次请求有没有被降智"。
    ///
    /// - `ok`       ：注入了 state，且上游没有下发降智信号 → 正常
    /// - `degraded` ：上游下发了 312 降智信号
    /// - `no_state` ：没有可用 state（兜底转发），结果未知
    fn note_request_outcome(&self, injected: bool, returned_len: Option<usize>) {
        let degraded = returned_len == Some(DEGRADED_STATE_LEN);
        let bucket = if degraded {
            "degraded"
        } else if injected {
            "ok"
        } else {
            "no_state"
        };
        if let Ok(mut stats) = self.state_stats.try_lock() {
            *stats.entry(bucket.to_owned()).or_insert(0) += 1;
            save_state_stats(&stats);
        }
    }

    /// 取出该账号 + 模型当前可用且已复验的 state，供检测复用。
    fn verified_state_for(&self, auth_id: &str, model: &str) -> Option<String> {
        // 任务在启动时就从磁盘重建了，所以这里只看任务即可。
        let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        jobs.values()
            .find(|job| job.auth_id == auth_id && job.model == model)
            .and_then(|job| job.store.acquire(now_seconds()))
            .map(|snapshot| snapshot.token.value)
    }

    /// 记录一次生成请求的处理方式，并累计各方式出现次数。
    ///
    /// 只做非阻塞尝试：调用点在请求路径上，等待锁会拖住整个宿主。
    fn note_mode(&self, key: &StateKey, mode: InjectionMode) {
        if let Ok(mut jobs) = self.jobs.try_lock()
            && let Some(job) = jobs.get_mut(key)
        {
            job.last_mode = Some(mode);
        }
        if let Ok(mut stats) = self.mode_stats.try_lock() {
            *stats.entry(mode.as_str().to_owned()).or_insert(0) += 1;
        }
    }

    /// 采集诊断：给页面与排查用。
    ///
    /// `run` 为真时顺手把这个（账号，模型）的采集跑一轮——这是"立即采集"，
    /// 平时只回报采集器状态，方便判断"为什么没在采"。
    fn harvest_diagnostics(&self, auth_id: Option<&str>, model: Option<&str>, run: bool) -> Value {
        let targets: Vec<(StateKey, ProbeJob)> = {
            let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
            jobs.iter()
                .filter(|(_, job)| {
                    auth_id.is_none_or(|id| job.auth_id == id)
                        && model.is_none_or(|name| job.model == name)
                })
                .map(|(key, job)| {
                    (
                        key.clone(),
                        ProbeJob {
                            key: key.clone(),
                            auth_id: job.auth_id.clone(),
                            auth_index: job.auth_index.clone(),
                            model: job.model.clone(),
                            store: Arc::clone(&job.store),
                        },
                    )
                })
                .collect()
        };

        let mut entries = Vec::with_capacity(targets.len());
        for (key, probe) in targets {
            if run {
                self.probe_job(probe);
            }
            let now = now_seconds();
            let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
            let entry = jobs.get(&key);
            entries.push(json!({
                "auth_id": key.auth_id,
                "model": key.model,
                "next_probe_in": entry
                    .map(|job| job.next_probe.saturating_sub(now))
                    .unwrap_or(0),
                "usable": entry
                    .map(|job| job.store.status(now).usable)
                    .unwrap_or(false),
                "rejected": entry
                    .and_then(|job| job.limit.rejection(now))
                    .map(|(status, _)| status),
                "last_result": entry.and_then(|job| job.last_result.clone()),
            }));
        }

        json!({
            "worker_running": self.running.load(Ordering::Acquire),
            "injection_enabled": self.injection_enabled.load(Ordering::Acquire),
            "paused": self.harvest_paused(),
            "ran": run,
            "jobs": entries,
        })
    }

    /// 最近一次采集观测是不是"上游降级"（312 / 模型被换）。
    fn last_probe_degraded(&self, key: &StateKey) -> bool {
        self.jobs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(key)
            .and_then(|job| job.probe_observation.as_ref())
            .and_then(|observation| observation.get("degraded"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn probe_job(&self, job: ProbeJob) {
        let now = now_seconds();
        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
            let Some(entry) = jobs.get_mut(&job.key) else {
                return;
            };
            // 探测开始前再确认一次：调度与执行之间上游可能刚给出拒绝。
            if entry.limit.rejection(now).is_some() {
                entry.next_probe = now.saturating_add(REJECT_COOLDOWN_SECONDS);
                return;
            }
            entry.next_probe = now.saturating_add(PROBE_COOLDOWN_SECONDS);
        }

        // 每轮从池子里的随机位置开始。池子顺序是固定的，每次都从头开始的话，
        // 前几个节点一旦降级/过载，整轮就废了，后面的节点永远轮不到。
        let pool_len = self
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        if pool_len > 1 {
            let offset = rand::random::<u32>() as usize % pool_len;
            self.egress_cursor
                .fetch_add(offset as u64, Ordering::Relaxed);
        }

        // 一轮里换着出口试：拿到合格 state 就停；上游拒绝凭据（401/403/429）立刻停。
        let mut last: Result<(bool, usize), String> = Err("没有可用的采集出口".to_owned());
        let mut settled = false;
        // 这一轮是不是"每个出口都只给降级响应"：决定失败后停 10 分钟还是 30 分钟。
        let mut degraded_round = false;
        let mut attempts = 0_usize;
        let budget = self.round_attempts(&job);
        for attempt in 1..=budget {
            attempts = attempt;
            if !self.running.load(Ordering::Acquire) {
                break;
            }
            if attempt > 1 {
                interruptible_sleep(&self.running, HARVEST_ATTEMPT_INTERVAL);
                if !self.running.load(Ordering::Acquire) {
                    break;
                }
            }
            let result = self.probe_once(&job);
            // 拿到一份 state（不管最后有没有被接受）就算本轮结束；Err 才换出口重试。
            settled = result.is_ok();
            degraded_round = if settled {
                false
            } else {
                self.last_probe_degraded(&job.key)
            };
            // 宿主说没有可用凭据（凭据被冷掉了）：换多少个出口都没用，整轮停。
            let unavailable = match &result {
                Err(error) => credential_unavailable(error),
                Ok(_) => false,
            };
            last = result;
            if settled || unavailable || self.credential_rejected(&job.key, now_seconds()) {
                break;
            }
        }

        let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = jobs.get_mut(&job.key) {
            match last {
                Ok((accepted, blocks)) => {
                    entry.last_result = Some(if accepted {
                        format!("accepted:blocks={blocks}")
                    } else {
                        format!("state_not_accepted:blocks={blocks}")
                    });
                }
                Err(error) => {
                    entry.last_result = Some(format!(
                        "采集失败（尝试 {attempts} 次）：{}",
                        compact_error(&error)
                    ));
                }
            }
            let cooldown = harvest_cooldown(settled, degraded_round);
            entry.next_probe = now.saturating_add(cooldown);
        }
    }

    fn probe_once(&self, job: &ProbeJob) -> Result<(bool, usize), String> {
        let auth_id = self.resolve_auth_id(job)?;
        let body = probe_body(&job.model);
        // 采集走池子里的下一个出口；复验和业务请求都不带 proxy_url，落到业务出口。
        let egress = self.next_egress(now_seconds());
        let egress_label = egress
            .as_ref()
            .map(|node| node.label.clone())
            .unwrap_or_else(|| "全局出口".to_owned());
        let mut payload = json!({
            "entry_protocol": "openai-response",
            "exit_protocol": "codex",
            "model": job.model,
            // 宿主只接受 stream=false；上游是不是流式由宿主自己决定。
            "stream": false,
            "body": STANDARD.encode(serde_json::to_vec(&body).map_err(|error| error.to_string())?),
            "headers": {
                "Accept": ["text/event-stream"],
                "Content-Type": ["application/json"],
                "OpenAI-Beta": ["responses=experimental"],
                "session_id": [uuid_like()],
                // 采集会被上游当成一次真实会话：身份头缺失更容易只拿到降级 state。
                "version": [CODEX_CLIENT_VERSION],
                "originator": ["codex_cli_rs"],
                // 原项目采集显式不复用连接；连接复用可能影响 292 的签发。
                "Connection": ["close"],
                INTERNAL_HEADER: ["1"]
            },
            "query": {},
            "alt": "",
            "forced_provider": "codex",
            "auth_id": auth_id
        });
        if let Some(node) = &egress {
            // 每次尝试都换一个会话 id：同一个地址、不同的出口 IP。
            payload["proxy_url"] = json!(expand_egress_url(&node.url));
        }
        let result = match host::request_json("host.model.execute", &payload) {
            Ok(result) => result,
            Err(error) => {
                // 这次调用本身失败。注意区分两类原因：
                // - 出口/网络问题 → 把这个出口冷却掉，下一次换别的
                // - 宿主没有可用凭据（CPA 把凭据冷掉了）→ 与出口无关，别污染池子
                if !credential_unavailable(&error)
                    && let Some(node) = &egress
                {
                    self.note_egress(&node.url, false, now_seconds());
                }
                self.record_failure(job, &egress_label, &error);
                return Err(error);
            }
        };
        let status = result
            .get("status_code")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let headers = result.get("headers").cloned().unwrap_or_else(|| json!({}));
        if let Some(rejected) = RejectedStatus::from_http(status) {
            let now = now_seconds();
            let retry_after = retry_after_seconds(&headers);
            if let Some(entry) = self
                .jobs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get_mut(&job.key)
            {
                entry
                    .limit
                    .reject(rejected, retry_after, REJECT_COOLDOWN_SECONDS, now);
                entry.last_result = Some(format!("upstream_{}", rejected.code()));
                entry.next_probe = now.saturating_add(REJECT_COOLDOWN_SECONDS.max(retry_after));
            }
            return Err(format!("probe rejected with HTTP {status}"));
        }
        if (500..600).contains(&status) {
            // 上游自己过载：换出口、换账号都没用，整条链路先歇一会儿。
            self.pause_harvest(&format!("上游 {status} 过载"), OVERLOAD_PAUSE_SECONDS);
            let error = format!(
                "probe returned HTTP {status}（上游过载，采集暂停 {OVERLOAD_PAUSE_SECONDS} 秒）"
            );
            self.record_failure(job, &egress_label, &error);
            return Err(error);
        }
        if !(200..300).contains(&status) {
            let error = format!("probe returned HTTP {status}");
            self.record_failure(job, &egress_label, &error);
            return Err(error);
        }
        // 出口本身是通的，清掉它的失败标记（state 好不好另算）。
        if let Some(node) = &egress {
            self.note_egress(&node.url, true, now_seconds());
        }
        let Some(value) = header_get_value(&headers, STATE_HEADER) else {
            let hint = response_hint(&result);
            let error = if status == 200 {
                // 正常作答却没有 state：经验上这是这个出口 IP 正在被降级，
                // 换出口（换 IP、换地区）就能重新拿到 292，所以只停这个出口。
                if let Some(node) = &egress {
                    self.note_egress_degraded(&node.url, now_seconds());
                }
                format!("probe returned no turn-state header{hint}")
            } else {
                if let Some(node) = &egress {
                    // 出口被拦（Cloudflare 会回 HTML 页）：换一个出口再来。
                    self.note_egress(&node.url, false, now_seconds());
                }
                format!("probe returned no turn-state header{hint}")
            };
            self.record_failure(job, &egress_label, &error);
            return Err(error);
        };
        let state_len = value.len();
        let state_value = value.clone();
        let token = TurnState::parse(&state_value).map_err(|error| error.to_string())?;

        // 第一重：312 字节是服务端下发的降智信号。
        if state_len == DEGRADED_STATE_LEN {
            // 这个出口现在只能拿到降级 state：停它一会儿，换下一个出口继续试。
            if let Some(node) = &egress {
                self.note_egress_degraded(&node.url, now_seconds());
            }
            self.record_observation(
                job,
                json!({
                    "state_len": state_len,
                    "egress": egress_label.clone(),
                    "blocks": token.blocks,
                    "requested_model": job.model,
                    "served_model": Value::Null,
                    "model_matches": false,
                    "degraded_signal": true,
                    "degraded": true,
                    "verified": false,
                    "accepted": false,
                }),
            );
            return Err(format!(
                "收到降智信号：state 为 {state_len} 字节（{DEGRADED_STATE_LEN} 即降级）"
            ));
        }

        // 第二重：采集请求必须由请求的模型作答。
        let served = served_model(&result.get("body").cloned().unwrap_or(Value::Null));
        let model_matches = served.as_deref().is_some_and(|served| served == job.model);
        if !model_matches {
            // 出口拿到的是别的（降级）模型：同样按出口级失败处理。
            if let Some(node) = &egress {
                self.note_egress_degraded(&node.url, now_seconds());
            }
            self.record_observation(
                job,
                json!({
                    "state_len": state_len,
                    "egress": egress_label.clone(),
                    "blocks": token.blocks,
                    "requested_model": job.model,
                    "served_model": served,
                    "model_matches": false,
                    "degraded_signal": false,
                    "degraded": true,
                    "verified": false,
                    "accepted": false,
                }),
            );
            return Err(format!(
                "上游返回的模型与请求不符（请求 {}，实际 {}）",
                job.model,
                served.as_deref().unwrap_or("未知")
            ));
        }

        // 第三重：拿这份 state 再打一次，
        // 证明注入它之后仍然由请求的模型作答。
        let (replay_len, replay_model) = self.replay_with_state(job, &state_value)?;
        let replay_ok =
            replay_model.as_deref() == Some(job.model.as_str()) && replay_len != DEGRADED_STATE_LEN;
        let accepted = replay_ok && job.store.offer(token.clone(), now_seconds());
        if accepted {
            // 拿到可用 state 了：回到正常节奏。
            self.gentle_harvest.store(false, Ordering::Release);
        }
        if replay_ok && let Some(node) = &egress {
            self.note_egress_good(&node.url, now_seconds());
        }
        self.record_observation(
            job,
            json!({
                "state_len": state_len,
                "egress": egress_label.clone(),
                "blocks": token.blocks,
                "requested_model": job.model,
                "served_model": served,
                "model_matches": true,
                "degraded_signal": false,
                "replay_state_len": replay_len,
                "replay_model": replay_model,
                "verified": replay_ok,
                "accepted": accepted,
            }),
        );
        if !replay_ok {
            let error = format!(
                "复验未通过：注入后返回 {}（{} 字节）",
                replay_model.as_deref().unwrap_or("未知"),
                replay_len
            );
            self.record_failure(job, &egress_label, &error);
            return Err(error);
        }
        Ok((accepted, token.blocks))
    }

    /// 拿候选 state 再打一次，确认注入它之后仍然由请求的模型作答。
    fn replay_with_state(
        &self,
        job: &ProbeJob,
        state: &str,
    ) -> Result<(usize, Option<String>), String> {
        let auth_id = self.resolve_auth_id(job)?;
        let body = probe_body(&job.model);
        let payload = json!({
            "entry_protocol": "openai-response",
            "exit_protocol": "codex",
            "model": job.model,
            "stream": false,
            "body": STANDARD.encode(serde_json::to_vec(&body).map_err(|error| error.to_string())?),
            "headers": {
                "Accept": ["application/json"],
                "Content-Type": ["application/json"],
                "OpenAI-Beta": ["responses=experimental"],
                "session_id": [uuid_like()],
                "version": [CODEX_CLIENT_VERSION],
                "originator": ["codex_cli_rs"],
                "Connection": ["close"],
                STATE_HEADER: [state],
                INTERNAL_HEADER: ["1"]
            },
            "query": {},
            "alt": "",
            "forced_provider": "codex",
            "auth_id": auth_id
        });
        let result = host::request_json("host.model.execute", &payload)?;
        let status = result
            .get("status_code")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(format!("复验请求返回 HTTP {status}"));
        }
        let headers = result.get("headers").cloned().unwrap_or_else(|| json!({}));
        let returned = header_get_value(&headers, STATE_HEADER).unwrap_or_default();
        let served = served_model(&result.get("body").cloned().unwrap_or(Value::Null));
        Ok((returned.len(), served))
    }

    /// 记一次失败的采集：只留下出口和原因，页面据此显示"为什么没采到"。
    fn record_failure(&self, job: &ProbeJob, egress: &str, error: &str) {
        self.record_observation(
            job,
            json!({
                "egress": egress,
                "error": compact_error(error),
                "model_matches": false,
                "verified": false,
                "accepted": false,
            }),
        );
    }

    /// 记录最近一次采集的外部观测，供状态页与排查使用。
    fn record_observation(&self, job: &ProbeJob, observation: Value) {
        let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = jobs.get_mut(&job.key) {
            entry.probe_observation = Some(observation);
        }
        save_states(&jobs);
    }
    fn resolve_auth_id(&self, job: &ProbeJob) -> Result<String, String> {
        self.resolve_auth_id_values(&job.auth_id, job.auth_index.as_deref())
    }
}

/// CPA 账号目录里的一条 Codex 凭据。
#[derive(Clone, Debug)]
struct CodexAuthFile {
    auth_id: String,
    auth_index: Option<String>,
    label: String,
    /// CPA 正在冷却的模型（scope=model）。
    cooling_models: Vec<String>,
    /// provider / 账号级冷却：整条凭据都要先放着。
    cooling_all: bool,
}

#[derive(Clone)]
struct ModelTraceAccount {
    auth_id: String,
    label: String,
}

struct ModeltraceTask {
    id: String,
    auth_id: String,
    model: String,
    status: String,
    progress: modeltrace::ProbeProgress,
    report: Option<Value>,
    error: Option<String>,
    updated_at: i64,
}

impl ModeltraceTask {
    fn json(&self) -> Value {
        json!({
            "id": self.id,
            "auth_id": self.auth_id,
            "model": self.model,
            "status": self.status,
            "progress": self.progress,
            "report": self.report,
            "error": self.error,
            "updated_at": self.updated_at
        })
    }
}

fn modeltrace_result_key(auth_id: &str, model: &str) -> String {
    format!("{auth_id}\0{model}")
}

#[derive(Clone)]
struct ProbeJob {
    key: StateKey,
    auth_id: String,
    auth_index: Option<String>,
    model: String,
    store: Arc<StateStore>,
}
pub fn intercept_after_auth(payload: &[u8]) -> Result<Value, String> {
    let request: InterceptRequest =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    let mut headers = request.headers.clone();
    let body = request.body_base64.clone();
    if header_get(&headers, INTERNAL_HEADER).is_some() {
        return Ok(json!({ "Headers": headers, "Body": body }));
    }
    if !is_codex_gpt_model(&request.model) {
        return Ok(json!({ "Headers": headers, "Body": body }));
    }
    let runtime = runtime()?;
    if !runtime.injection_enabled.load(Ordering::Acquire) {
        return Ok(json!({ "Headers": headers, "Body": body }));
    }
    let key = request_key(&request.metadata, &request.request_id, &request.model);
    let account = account_kind(&headers, &request.metadata);
    let (store, limit) = runtime.ensure_job(
        key.clone(),
        request.auth_id(),
        request.auth_index(),
        request.model.clone(),
        account,
    );

    let auth_id = request.auth_id();
    let mut mode = InjectionMode::FallbackPassthrough;

    // 上游已经拒绝这条凭据时不再注入：有效的 turn-state 不该绕过认证或配额结论。
    if limit.rejection(now_seconds()).is_some() {
        mode = InjectionMode::UpstreamRejected;
    } else if let Some(snapshot) = store.acquire(now_seconds()) {
        header_set(&mut headers, STATE_HEADER, snapshot.token.value.clone());
        runtime
            .inflight
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                request.request_id.clone(),
                Inflight {
                    key: key.clone(),
                    snapshot,
                },
            );
        mode = InjectionMode::Injected;
    }

    runtime
        .modes
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(request.request_id.clone(), RequestMode { mode, auth_id });
    runtime.note_mode(&key, mode);

    Ok(json!({ "Headers": headers, "Body": body }))
}

/// 严格模式要在请求发出前终止，所以判断必须放在 `request.intercept_before`。
///
/// 与原项目一致：只有生成请求参与严格判定；注入关闭或上游已拒绝时照常放行。
pub fn intercept_before(payload: &[u8]) -> Result<Value, String> {
    let request: InterceptRequest =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    let headers = request.headers.clone();
    let body = request.body_base64.clone();

    if header_get(&headers, INTERNAL_HEADER).is_some() || !is_codex_gpt_model(&request.model) {
        return Ok(json!({ "Headers": headers, "Body": body }));
    }

    let runtime = runtime()?;
    if !runtime.injection_enabled.load(Ordering::Acquire) {
        return Ok(json!({ "Headers": headers, "Body": body }));
    }
    let strict = *runtime
        .fallback
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        == StateFallback::Strict;
    if !strict || !is_generation_request(&request.body_base64) {
        return Ok(json!({ "Headers": headers, "Body": body }));
    }

    let key = request_key(&request.metadata, &request.request_id, &request.model);
    // 关键：这里绝不等待锁。宿主在插件回调里是串行的，一旦等待就会把整个宿主拖住。
    let Ok(jobs) = runtime.jobs.try_lock() else {
        return Ok(json!({ "Headers": headers, "Body": body }));
    };
    let Some(job) = jobs.get(&key) else {
        drop(jobs);
        runtime.note_mode(&key, InjectionMode::Rejected);
        return Ok(terminate_state_unavailable());
    };
    let now = now_seconds();
    // 被上游拒绝时交给后续流程按原状态码处理，不在这里伪装成"state 不可用"。
    if job.limit.rejection(now).is_some() || job.store.acquire(now).is_some() {
        return Ok(json!({ "Headers": headers, "Body": body }));
    }
    drop(jobs);
    runtime.note_mode(&key, InjectionMode::Rejected);
    Ok(terminate_state_unavailable())
}

/// 严格模式下没有可用 state 时的下游响应。
fn terminate_state_unavailable() -> Value {
    let body = json!({
        "error": {
            "type": "state_unavailable",
            "message": "没有可用的 turn-state，严格模式下拒绝转发。请稍后重试，或把策略改为 passthrough。",
        }
    });
    json!({
        "Terminate": true,
        "StatusCode": 503,
        "ResponseHeaders": {
            "Content-Type": ["application/json"],
            "Retry-After": ["30"],
        },
        "ResponseBody": STANDARD.encode(serde_json::to_vec(&body).unwrap_or_default()),
    })
}

/// 判断是不是生成请求：原项目按路径判定，这里按请求体特征判定。
///
/// 生成请求会带 `include: ["reasoning.encrypted_content"]`；压缩与元数据请求不带。
fn is_generation_request(body_base64: &Value) -> bool {
    let Some(encoded) = body_base64.as_str() else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .or_else(|_| STANDARD.decode(encoded))
    else {
        return false;
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return false;
    };
    text.contains("reasoning.encrypted_content")
}

pub fn intercept_response(payload: &[u8]) -> Result<Value, String> {
    let response: ResponseEnvelope =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    Ok(response_intercept_result(&response))
}

pub fn intercept_stream_chunk(payload: &[u8]) -> Result<Value, String> {
    let response: ResponseEnvelope =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    Ok(response_intercept_result(&response))
}

fn response_intercept_result(response: &ResponseEnvelope) -> Value {
    observe_response(response);
    let Ok(runtime) = runtime() else {
        return json!({});
    };

    // 本次请求最终怎么处理的：注入 / 兜底 / 关闭 / 上游拒绝。让调用方一眼能看出是否真的注入。
    let mode = runtime
        .modes
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&response.request_id);
    let mut headers = serde_json::Map::new();
    if let Some(mode) = &mode {
        headers.insert(
            "X-FixGPT-State-Mode".to_owned(),
            json!([mode.mode.as_str()]),
        );
        headers.insert("X-FixGPT-State-Auth".to_owned(), json!([mode.auth_id]));
    }
    if let Some(version) = runtime.injected_state_version(&response.request_id) {
        headers.insert(
            "X-FixGPT-State-Version".to_owned(),
            json!([version.to_string()]),
        );
    }
    // 把本次注入的 state 回显给调用方，用于验证注入是否真的生效。
    if let Ok(inflight) = runtime.inflight.lock()
        && let Some(entry) = inflight.get(&response.request_id)
    {
        headers.insert(
            "X-FixGPT-Injected-State".to_owned(),
            json!([entry.snapshot.token.value]),
        );
    }
    if headers.is_empty() {
        json!({})
    } else {
        json!({ "Headers": Value::Object(headers) })
    }
}

pub fn complete_request(payload: &[u8]) -> Result<Value, String> {
    let completion: CompletionEnvelope =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    let runtime = runtime()?;
    runtime
        .inflight
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&completion.request_id);
    runtime
        .observed
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&completion.request_id);
    Ok(json!({}))
}

pub fn handle_management(payload: &[u8]) -> Result<Value, String> {
    let request: ManagementRequest =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;

    if request.path.ends_with("/modeltrace/start") {
        let auth_id =
            query_value(&request, "auth_id").ok_or_else(|| "auth_id is required".to_owned())?;
        let model = query_value(&request, "model").ok_or_else(|| "model is required".to_owned())?;
        let task_id = runtime()?.start_modeltrace_task(auth_id.to_owned(), model.to_owned())?;
        return json_management_response(json!({ "task_id": task_id }));
    }

    // 采集诊断；带 run=1 时立即跑一轮采集。
    if request.path.ends_with("/harvest") {
        let runtime = runtime()?;
        let auth_id = query_value(&request, "auth_id");
        let model = query_value(&request, "model");
        let run = query_value(&request, "run")
            .is_some_and(|value| !matches!(value, "0" | "false" | "off" | "no"));
        return json_management_response(runtime.harvest_diagnostics(auth_id, model, run));
    }

    // 供页面轮询的 JSON 状态：只在页面可见时被前端拉取。
    if request.path.ends_with("/state") {
        let runtime = runtime()?;
        let mut status = runtime.status_json();
        let mut models = modeltrace::supported_models();
        if let Some(index) = models.iter().position(|model| model == "gpt-6-astra") {
            models.rotate_left(index);
        }
        // 每个 账号 × 模型 一条：卡片上的下拉框可以切换模型，状态必须跟着模型走，
        // 不能只报默认模型的状态。
        let mut accounts: Vec<Value> = Vec::new();
        for account in runtime.modeltrace_accounts() {
            for model in &models {
                let (tone, state_text) = runtime.state_summary(&account.auth_id, model);
                accounts.push(json!({
                    "auth_id": account.auth_id,
                    "label": account.label,
                    "model": model,
                    "tone": tone,
                    "state": state_text,
                    "probe": runtime.probe_summary(&account.auth_id, model),
                }));
            }
        }
        // 页面只用 accounts / state_stats，其余字段是排查用的原始快照。
        if let Some(object) = status.as_object_mut() {
            object.insert("accounts".to_owned(), Value::Array(accounts));
        }
        return json_management_response(status);
    }

    if request.path.ends_with("/injection") {
        let runtime = runtime()?;
        // 资源路由只走 GET，所以切换也走 GET：带参数时改，不带时只读。
        if let Some(value) = query_value(&request, "enabled") {
            let enabled = !matches!(value, "0" | "false" | "off" | "no");
            runtime.set_injection(enabled);
        }
        if let Some(fallback) = query_value(&request, "fallback").and_then(StateFallback::parse) {
            runtime.set_fallback(fallback);
        }
        return json_management_response(json!({
            "injection_enabled": runtime.injection_enabled.load(Ordering::Acquire),
            "state_fallback": runtime
                .fallback
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_str(),
        }));
    }

    if request.path.ends_with("/modeltrace/tasks") {
        let tasks = runtime()?.modeltrace_tasks_json();
        return json_management_response(tasks);
    }

    if request.path.ends_with("/modeltrace/status") {
        let task_id =
            query_value(&request, "task_id").ok_or_else(|| "task_id is required".to_owned())?;
        // 任务只存在内存里，插件重启后就没了。这里回一条能看懂的 JSON，
        // 而不是让宿主把它变成页面看不懂的 502。
        let Some(task) = runtime()?.modeltrace_task_json(task_id) else {
            return json_management_response(json!({
                "error": "检测任务已不存在（插件重启过），请重新检测"
            }));
        };
        return json_management_response(task);
    }

    // 只有一个界面：/status 既是菜单入口，也是页面本体
    let html = if request.path.ends_with("/status") {
        render_modeltrace_page(&request)
    } else {
        return Err("unknown FixGPT resource".to_owned());
    };
    Ok(json!({
        "StatusCode": 200,
        "Headers": { "content-type": ["text/html; charset=utf-8"] },
        "Body": STANDARD.encode(html.into_bytes())
    }))
}

fn json_management_response(value: Value) -> Result<Value, String> {
    let body = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(json!({
        "StatusCode": 200,
        "Headers": { "content-type": ["application/json; charset=utf-8"] },
        "Body": STANDARD.encode(body)
    }))
}

fn query_value<'a>(request: &'a ManagementRequest, key: &str) -> Option<&'a str> {
    request
        .query
        .as_ref()
        .and_then(|query| query.get(key))
        .and_then(|values| values.first())
        .map(String::as_str)
}
const PAGE_CSS: &str = r#"
:root{--bg:#f5f6f8;--surface:#fff;--surface-soft:#f8fafc;--text:#18212f;--muted:#667085;--line:#dfe3e8;--line-strong:#cfd5dc;--primary:#2563eb;--primary-dark:#1d4ed8;--primary-soft:#eff6ff;--success:#16794b;--success-soft:#eaf7f0;--warning:#946200;--warning-soft:#fff6dc;--danger:#b42318;--danger-soft:#fff0ee}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--text);font-family:"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;font-size:14px}button,input,select{font:inherit}button{cursor:pointer}button:disabled{cursor:wait;opacity:.6}
.topbar{position:sticky;top:0;z-index:20;height:58px;display:flex;align-items:center;justify-content:space-between;padding:0 22px;background:var(--surface);border-bottom:1px solid var(--line)}.product-name{display:flex;align-items:center;gap:10px}.product-mark{display:grid;place-items:center;width:29px;height:29px;border-radius:6px;color:#fff;background:var(--primary);font-size:11px;font-weight:800}.product-name strong{font-size:14px}.status-dot{width:7px;height:7px;border-radius:50%;background:#22a06b}.divider{width:1px;height:14px;background:var(--line)}

.main-content{max-width:1080px;margin:0 auto;padding:26px 30px 60px}.page-header{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;margin-bottom:22px}.page-header h1{margin:0 0 7px;font-size:24px;line-height:1.25}.page-header p{margin:0;color:var(--muted);line-height:1.55}.privacy-badge{color:var(--success);background:var(--success-soft);border:1px solid #c8ead7;border-radius:999px;padding:7px 10px;font-size:11px;white-space:nowrap}
.account-grid{display:grid;grid-template-columns:1fr;gap:12px}.account-card{padding:17px;background:var(--surface);border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 2px rgba(16,24,40,.03)}.account-head{display:flex;align-items:center;gap:11px;min-width:0}.avatar{display:grid;place-items:center;width:34px;height:34px;flex:0 0 auto;border-radius:8px;color:#fff;background:linear-gradient(135deg,#2563eb,#7c4dff);font-size:13px;font-weight:800}.account-title{min-width:0}.account-title strong{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:14px}.account-title span{color:var(--muted);font-size:11px}.codex-pill{margin-left:auto;color:var(--primary-dark);background:var(--primary-soft);border:1px solid #c7d8ff;border-radius:999px;padding:4px 8px;font-size:10px;font-weight:650}
.account-controls{display:grid;grid-template-columns:minmax(0,1fr) 96px;gap:10px;margin-top:15px}.account-controls select{width:100%;height:36px;padding:0 30px 0 10px;color:var(--text);background:#fff;border:1px solid var(--line-strong);border-radius:7px;outline:none}.account-controls select:focus{border-color:var(--primary);box-shadow:0 0 0 3px #2563eb18}.button{min-height:36px;padding:8px 13px;border-radius:7px;border:1px solid transparent;font-size:12px;font-weight:650}.button.primary{color:#fff;background:var(--primary);border-color:var(--primary)}.button.primary:hover{background:var(--primary-dark)}
.account-result{display:flex;align-items:center;flex-wrap:wrap;gap:7px;min-height:22px;margin-top:13px;padding-top:12px;border-top:1px solid #edf0f3;color:var(--muted);font-size:12px}.account-result strong{color:var(--text)}.status-pill{border-radius:999px;padding:4px 8px;font-size:10px;font-weight:700}.status-pill.success{color:var(--success);background:var(--success-soft)}.status-pill.warning{color:var(--warning);background:var(--warning-soft)}.status-pill.danger{color:var(--danger);background:var(--danger-soft)}.probability{margin-left:auto;color:var(--text);font-weight:700}
.progress-panel,.result-panel{margin-top:14px;background:var(--surface);border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 2px rgba(16,24,40,.03)}.progress-panel{padding:15px}.progress-heading{display:flex;align-items:center;justify-content:space-between;gap:16px;font-size:12px}.progress-heading strong{font-size:12.5px}.progress-heading span{color:var(--muted);white-space:nowrap}.progress-track{height:7px;margin-top:12px;overflow:hidden;background:#e9edf2;border-radius:999px}.progress-track i{display:block;height:100%;width:0;background:var(--primary);border-radius:999px;transition:width .25s ease}.progress-steps{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px;margin-top:12px}.progress-step{display:flex;align-items:center;gap:7px;min-height:34px;padding:7px 9px;color:var(--muted);background:#fff;border:1px solid var(--line);border-radius:7px;font-size:11px;white-space:nowrap}.progress-step .step-index{display:grid;place-items:center;width:18px;height:18px;border-radius:50%;background:#eef1f5;font-size:10px;font-weight:700}.progress-step.running{color:var(--primary-dark);border-color:#bfd0ff;background:#f7f9ff}.progress-step.running .step-index{color:#fff;background:var(--primary)}.progress-step.valid{color:var(--success);border-color:#c8ead7;background:var(--success-soft)}.progress-step.valid .step-index{color:#fff;background:var(--success)}.progress-step.invalid,.progress-step.error{color:var(--danger);border-color:#f3c7c3;background:var(--danger-soft)}.progress-step.invalid .step-index,.progress-step.error .step-index{color:#fff;background:var(--danger)}.progress-detail{margin-top:10px;color:var(--danger);font-size:11px;line-height:1.5}
.result-summary{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid var(--line)}.result-summary div{padding:14px 16px;border-right:1px solid var(--line)}.result-summary div:last-child{border-right:0}.result-summary span{display:block;margin-bottom:6px;color:var(--muted);font-size:11px}.result-summary strong{font-size:18px}.diagnostics{display:flex;flex-wrap:wrap;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line)}.diagnostic{border-radius:6px;padding:5px 8px;font-size:11px}.diagnostic.accepted{color:var(--success);background:var(--success-soft)}.diagnostic.rejected{color:var(--danger);background:var(--danger-soft)}
.table-wrap{overflow:auto}.result-table{width:100%;border-collapse:collapse}.result-table th,.result-table td{padding:11px 16px;border-bottom:1px solid #edf0f3;text-align:left;font-size:12px}.result-table th{color:var(--muted);font-weight:600;background:#fafbfc}.result-table tr.winner{background:#eef4ff}.probability-cell{display:flex;align-items:center;gap:10px}.probability-bar{width:150px;height:7px;overflow:hidden;background:#e9edf2;border-radius:999px}.probability-bar i{display:block;height:100%;background:var(--primary);border-radius:999px}.result-note{padding:12px 16px;color:var(--muted);font-size:11px}.empty{padding:44px 18px;text-align:center;color:var(--muted);background:var(--surface);border:1px dashed var(--line-strong);border-radius:10px}
@media(max-width:760px){.topbar{padding:0 14px}.main-content{padding:18px 13px 40px}.page-header{flex-direction:column}.account-controls{grid-template-columns:1fr}.progress-steps{grid-template-columns:repeat(3,1fr)}.result-summary{grid-template-columns:repeat(2,1fr)}.result-summary div:nth-child(2){border-right:0}.result-summary div:nth-child(-n+2){border-bottom:1px solid var(--line)}}
.status-bar{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 18px}
.toolbar{display:flex;gap:8px;margin:0 0 18px}.toolbar .button{min-height:32px;padding:6px 14px;border-radius:7px;border:1px solid var(--line);background:#fff;color:var(--text);font-size:12px;font-weight:650}.toolbar .button.primary{color:#fff;background:var(--primary);border-color:var(--primary)}
.badge{padding:5px 11px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px;line-height:1.4}
.badge.ok{color:var(--success);background:var(--success-soft);border-color:#c8ead7}
.badge.warn{color:var(--warning);background:var(--warning-soft);border-color:#f0e0b0}
"#;

const MODELTRACE_TASK_PANEL: &str = r#"<div class="task-area" hidden><section class="progress-panel" hidden><div class="progress-heading"><strong class="progress-status">正在进行第 1 次尝试，等待模型完整输出……</strong><span class="progress-count">有效 0/3 · 已尝试 0/6</span></div><div class="progress-track"><i class="progress-fill"></i></div><div class="progress-steps"></div><div class="progress-detail" hidden></div></section><section class="result-panel" hidden></section></div>"#;

const MODELTRACE_PAGE: &str = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ModelTrace</title>
<style>__PAGE_CSS__</style></head><body>
<header class="topbar"><div class="product-name"><span class="product-mark">FG</span><strong>FixGPT</strong></div></header>
<main class="main-content"><div class="page-header"><div></div><div class="privacy-badge">GPT-only</div></div>
__STATUS_BAR__
<div class="toolbar"><button class="button primary" id="run-all" type="button">一键检测</button><button class="button" id="refresh-now" type="button">刷新状态</button></div>
<div class="account-grid">__ACCOUNT_CARDS__<script>
const byId=(id)=>document.getElementById(id);
const esc=(value)=>String(value??'').replace(/[&<>"']/g,(character)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const pct=(value)=>(Number(value||0)*100).toFixed(1)+'%';
function stepMarkup(progress,completed){const steps=Array.from({length:progress.total_attempts||6},(_,index)=>{const step=(progress.steps||[]).find((item)=>Number(item.index)===index+1);const state=step?.state||'waiting';const label=state==='running'?'请求中':state==='valid'?'有效':state==='invalid'?'无效':state==='error'?'失败':(completed?'无需调用':'等待');return '<div class="progress-step '+esc(state)+'" title="'+esc(step?.error||'')+'"><span class="step-index">'+(index+1)+'</span>挑战 '+(index+1)+' · '+label+'</div>';});return steps.join('');}
function renderProgress(card,task){const progress=task.progress||{};const attempted=progress.attempted||0,valid=progress.valid||0,total=progress.total_attempts||6,current=progress.current||0;const panel=card.querySelector('.progress-panel');panel.hidden=false;const status=card.querySelector('.progress-status');const label=task.status==='completed'?`测试完成：${valid}/3 份有效回答进入归因`:task.status==='failed'?(attempted===0?'未开始测试':'测试失败'):current>0?`正在进行第 ${current} 次尝试，等待模型完整输出……`:`已尝试 ${attempted}/${total} 次，准备下一次挑战……`;status.textContent=label;card.querySelector('.progress-count').textContent=`有效 ${valid}/3 · 已尝试 ${attempted}/${total}`;card.querySelector('.progress-fill').style.width=Math.min(100,attempted/total*100)+'%';card.querySelector('.progress-steps').innerHTML=stepMarkup(progress,task.status==='completed');const errors=(progress.steps||[]).filter((step)=>step.error).map((step)=>'挑战 '+step.index+'：'+step.error).join('；');const detail=card.querySelector('.progress-detail');detail.textContent=errors;detail.hidden=!errors;}
function renderResult(card,task){const result=card.querySelector('.result-panel');if(task.status==='failed'){result.innerHTML='<div class="result-note" style="color:var(--danger)">'+esc(task.error||'测试失败')+'</div>';result.hidden=false;return;}const report=task.report;if(!report)return;const candidates=report.candidates||[];const rows=candidates.map((item,index)=>'<tr class="'+(index===0?'winner':'')+'"><td>'+(index+1)+'</td><td><strong>'+esc(item.display_name)+'</strong></td><td>GPT</td><td><div class="probability-cell"><div class="probability-bar"><i style="width:'+Math.max(0,Math.min(100,item.probability*100))+'%"></i></div><strong>'+pct(item.probability)+'</strong></div></td><td>'+pct(item.profile_similarity)+'</td></tr>').join('');const injected=report.state_injected?'<span class="status-pill success">已注入 292 state</span>':'<span class="status-pill warning">未注入（无可用 state）</span>';result.innerHTML='<div class="result-note">本次检测：'+injected+'</div><div class="result-summary"><div><span>最可能模型</span><strong>'+esc(report.prediction)+'</strong></div><div><span>归因概率</span><strong>'+pct(report.probability)+'</strong></div><div><span>模型家族</span><strong>GPT · 100.0%</strong></div><div><span>有效查询</span><strong>'+report.used_outputs+'/3</strong></div></div><div class="table-wrap"><table class="result-table"><thead><tr><th>排序</th><th>候选模型</th><th>家族</th><th>归因概率</th><th>分布相似度</th></tr></thead><tbody>'+rows+'</tbody></table></div><div class="result-note">仅对 GPT 指纹库内模型进行归因。</div>';result.hidden=false;}
async function startTask(button,resumeTaskId){const self=button;const card=button.closest('.account-card');const taskArea=card.querySelector('.task-area');taskArea.hidden=false;const resultPanel=card.querySelector('.result-panel');resultPanel.hidden=true;const authId=card.dataset.authId;const model=card.querySelector('select').value;const cardResult=card.querySelector('.account-result');button.disabled=true;button.textContent='检测中';renderProgress(card,{status:'running',progress:{attempt:0,total_attempts:6,valid:0,attempted:0,steps:[]}});try{let taskId=resumeTaskId;if(!taskId){const start=await fetch('/v0/resource/plugins/fixgpt/modeltrace/start?auth_id='+encodeURIComponent(authId)+'&model='+encodeURIComponent(model)).then((response)=>response.json());if(start.error)throw new Error(start.error);taskId=start.task_id;}while(true){await new Promise((resolve)=>setTimeout(resolve,800));const task=await fetch('/v0/resource/plugins/fixgpt/modeltrace/status?task_id='+encodeURIComponent(taskId)).then((response)=>response.json());if(task.error&&!task.status)throw new Error(task.error);renderProgress(card,task);if(task.status==='completed'){renderResult(card,task);const report=task.report||{};const compatible=report.outcome==='compatible';cardResult.innerHTML='<span class="status-pill '+(compatible?'success':'warning')+'">'+(compatible?'正常':'异常')+'</span><span>判定 <strong>'+esc(report.prediction)+'</strong></span><span class="probability">'+pct(report.probability)+'</span>';break;}if(task.status==='failed')throw new Error(task.error||'测试失败');}}catch(error){const offline=error instanceof TypeError||/failed to fetch|networkerror|load failed/i.test(String(error.message||''));const status=card.querySelector('.progress-status');if(offline){status.textContent='已失去连接';resultFallback(card,'与后端连接中断（后端可能正在重启）。这不代表检测结果异常，请刷新页面后重试。');}else{status.textContent='测试失败';resultFallback(card,error.message);}}finally{self.disabled=false;self.textContent='检测';}}
function resultFallback(card,message){const result=card.querySelector('.result-panel');result.innerHTML='<div class="result-note" style="color:var(--danger)">'+esc(message)+'</div>';result.hidden=false;}
const resumeTask=(card)=>{const authId=card.dataset.authId;const model=card.querySelector('select').value;fetch('/v0/resource/plugins/fixgpt/modeltrace/tasks').then((response)=>response.json()).then((payload)=>{const task=(payload.tasks||[]).find((item)=>item.auth_id===authId&&item.model===model&&item.status==='running');if(task)startTask(card.querySelector('[data-run]'),task.id);}).catch(()=>{});};document.querySelectorAll('[data-run]').forEach((button)=>button.addEventListener('click',()=>startTask(button)));document.querySelectorAll('.account-card').forEach((card)=>resumeTask(card));

// ---- 状态轮询：只在页面可见时进行，切走/关闭就停 ----
const statusBar=document.getElementById('status-bar');
let probeTimer=null,counterTimer=null;
async function pullState(){
  if(document.hidden)return null;
  try{
    const r=await fetch('/v0/resource/plugins/fixgpt/state',{cache:'no-store'});
    if(!r.ok)return null;
    return await r.json();
  }catch(_){return null;}
}
// 每 5 秒：最近采集 + state 状态
async function refreshProbe(){
  const d=await pullState();if(!d)return;
  for(const card of document.querySelectorAll('.account-card')){
    const sel=card.querySelector('select');
    const authId=card.dataset.authId;
    const model=sel?sel.value:'';
    const a=(d.accounts||[]).find(x=>x.auth_id===authId&&x.model===model);
    if(!a)continue;
    const pill=card.querySelector('.status-pill');
    if(pill){pill.className='status-pill '+a.tone;pill.textContent=a.state;}
    const detail=card.querySelector('.detail');
    if(detail)detail.textContent='最近采集：'+a.probe;
  }
}
// 每 30 秒：计数条
async function refreshCounters(){
  const d=await pullState();if(!d||!statusBar)return;
  const s=d.state_stats||{};
  statusBar.innerHTML='<span class="badge ok">正常 '+(s.ok||0)+'</span><span class="badge warn">降智 '+(s.degraded||0)+'</span><span class="badge">无 state '+(s.no_state||0)+'</span>';
}
function startPolling(){
  stopPolling();
  if(document.hidden)return;
  refreshProbe();refreshCounters();
  probeTimer=setInterval(refreshProbe,5000);
  counterTimer=setInterval(refreshCounters,30000);
}
function stopPolling(){
  if(probeTimer){clearInterval(probeTimer);probeTimer=null;}
  if(counterTimer){clearInterval(counterTimer);counterTimer=null;}
}
document.addEventListener('visibilitychange',()=>{document.hidden?stopPolling():startPolling();});
window.addEventListener('pagehide',stopPolling);
startPolling();

// ---- 一键检测：所有账号一起跑 ----
const runAll=document.getElementById('run-all');
const refreshNow=document.getElementById('refresh-now');
if(runAll)runAll.addEventListener('click',()=>{
  document.querySelectorAll('.account-card').forEach((card)=>{
    const b=card.querySelector('[data-run]');
    if(b&&!b.disabled)startTask(b);
  });
});
if(refreshNow)refreshNow.addEventListener('click',()=>{refreshProbe();refreshCounters();});
document.querySelectorAll('.account-card select').forEach((sel)=>sel.addEventListener('change',refreshProbe));
</script></body></html>"#;

/// 剩余的秒数说成人话。
fn human_seconds(seconds: i64) -> String {
    if seconds <= 0 {
        return "已过期".to_owned();
    }
    let minutes = seconds / 60;
    if minutes >= 60 {
        format!("{} 小时 {} 分", minutes / 60, minutes % 60)
    } else if minutes > 0 {
        format!("{minutes} 分钟")
    } else {
        format!("{seconds} 秒")
    }
}

/// 页头下方的状态条：注入开关、无 state 时的策略、292/312 计数。
///
/// 放在页头下方而不是右上角——右上角会被客户端（Codex 应用）的浮层遮住。
fn render_status_bar(status: &Value) -> String {
    let stats = status
        .get("state_stats")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let count_of = |key: &str| stats.get(key).and_then(Value::as_u64).unwrap_or_default();
    format!(
        "<div class=\"status-bar\" id=\"status-bar\"><span class=\"badge ok\">正常 {}</span><span class=\"badge warn\">降智 {}</span><span class=\"badge\">无 state {}</span></div>",
        count_of("ok"),
        count_of("degraded"),
        count_of("no_state"),
    )
}

fn render_modeltrace_page(_request: &ManagementRequest) -> String {
    let Ok(runtime) = runtime() else {
        return MODELTRACE_PAGE
            .replace("__PAGE_CSS__", PAGE_CSS)
            .replace("__STATUS_BAR__", &render_status_bar(&json!({})))
            .replace(
                "__ACCOUNT_CARDS__",
                "<div class=\"empty\">插件尚未初始化</div>",
            );
    };
    let mut accounts = runtime.modeltrace_accounts();
    let mut models = modeltrace::supported_models();
    if let Some(index) = models.iter().position(|model| model == "gpt-6-astra") {
        models.rotate_left(index);
    }
    let mut cards = String::new();
    for account in accounts.drain(..) {
        let selected = models.first().map(String::as_str).unwrap_or("gpt-6-astra");
        let options = models
            .iter()
            .map(|model| {
                format!(
                    "<option value=\"{}\"{}>{}</option>",
                    html(model),
                    if model == selected { " selected" } else { "" },
                    html(model)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let avatar = account
            .label
            .chars()
            .next()
            .map(|value| value.to_uppercase().to_string())
            .unwrap_or_else(|| "?".to_owned());
        let rendered = runtime.modeltrace_result(&account.auth_id, selected);
        let (tone, state_text) = runtime.state_summary(&account.auth_id, selected);
        let probe_text = runtime.probe_summary(&account.auth_id, selected);
        cards.push_str(&format!(
            "<article class=\"account-card\" data-auth-id=\"{}\"><div class=\"account-head\"><div class=\"avatar\">{}</div><div class=\"account-title\"><strong>{}</strong><span>Codex account</span></div><span class=\"status-pill {}\">{}</span></div><p class=\"detail\">最近采集：{}</p><div class=\"account-controls\"><select>{}</select><button class=\"button primary\" data-run type=\"button\">检测</button></div>{}{}</article>",
            html(&account.auth_id),
            html(&avatar),
            html(&account.label),
            tone,
            html(&state_text),
            html(&probe_text),
            options,
            modeltrace_result_markup(rendered),
            MODELTRACE_TASK_PANEL,
        ));
    }
    if cards.is_empty() {
        cards = "<div class=\"empty\">没有启用的 Codex 账号</div>".to_owned();
    }
    let status_bar = render_status_bar(&runtime.status_json());

    MODELTRACE_PAGE
        .replace("__PAGE_CSS__", PAGE_CSS)
        .replace("__STATUS_BAR__", &status_bar)
        .replace("__ACCOUNT_CARDS__", &cards)
}

fn modeltrace_result_markup(result: Option<Value>) -> String {
    let Some(result) = result else {
        return "<div class=\"account-result\">尚未检测</div>".to_owned();
    };
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        return format!(
            "<div class=\"account-result\"><span class=\"status-pill danger\">失败</span>{}</div>",
            html(error)
        );
    }
    let outcome = result
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("inconclusive");
    let prediction = result
        .get("prediction")
        .and_then(Value::as_str)
        .unwrap_or("-");
    let probability = result
        .get("probability")
        .and_then(Value::as_f64)
        .unwrap_or_default();
    let (class, label) = match outcome {
        "compatible" => ("success", "正常"),
        "difference_signal" | "repeated_difference" => ("warning", "异常"),
        _ => ("danger", "不确定"),
    };
    format!(
        "<div class=\"account-result\"><span class=\"status-pill {class}\">{label}</span><span>判定 <strong>{}</strong></span><span class=\"probability\">{:.1}%</span></div>",
        html(prediction),
        probability * 100.0
    )
}
fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
impl Runtime {
    fn injected_state_version(&self, request_id: &str) -> Option<u64> {
        self.inflight
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(request_id)
            .map(|inflight| inflight.snapshot.version)
    }

    fn ensure_job(
        &self,
        key: StateKey,
        auth_id: String,
        auth_index: Option<String>,
        model: String,
        account: AccountKind,
    ) -> (Arc<StateStore>, CredentialLimit) {
        let account = self.resolve_account_kind(auth_index.as_deref(), account);
        let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        let entry = jobs.entry(key.clone()).or_insert_with(|| {
            Job::new(
                auth_id.clone(),
                auth_index.clone(),
                model.clone(),
                account.clone(),
            )
        });
        entry.auth_id = auth_id.clone();
        entry.auth_index = auth_index;
        entry.model = model.clone();
        entry.account = account.clone();
        (Arc::clone(&entry.store), entry.limit)
    }

    fn resolve_account_kind(&self, auth_index: Option<&str>, fallback: AccountKind) -> AccountKind {
        if matches!(fallback, AccountKind::Team) {
            return fallback;
        }
        let Some(index) = auth_index else {
            return fallback;
        };
        let Ok(result) =
            host::request_json("host.auth.get_runtime", &json!({ "auth_index": index }))
        else {
            return fallback;
        };
        let kind = result
            .pointer("/auth/account_type")
            .or_else(|| result.pointer("/auth/account"))
            .or_else(|| result.pointer("/auth/plan_type"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if kind.contains("team") || kind.contains("business") {
            AccountKind::Team
        } else {
            fallback
        }
    }
    fn start_modeltrace_task(
        self: &Arc<Self>,
        auth_id: String,
        model: String,
    ) -> Result<String, String> {
        if !modeltrace::supports_model(&model) {
            return Err(format!(
                "ModelTrace GPT bank does not contain model {model}"
            ));
        }
        let id = format!(
            "mt-{}-{}",
            now_seconds(),
            self.modeltrace_seq.fetch_add(1, Ordering::Relaxed)
        );
        let task = ModeltraceTask {
            id: id.clone(),
            auth_id: auth_id.clone(),
            model: model.clone(),
            status: "running".to_owned(),
            progress: modeltrace::ProbeProgress::initial(),
            report: None,
            error: None,
            updated_at: now_seconds(),
        };
        {
            let mut tasks = self
                .modeltrace_tasks
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            // 结束的任务只服务页面轮询，长期留在内存里会一直累积。
            let now = now_seconds();
            tasks.retain(|_, task| task.status == "running" || now - task.updated_at < 600);
            tasks.insert(id.clone(), task);
        }

        let task_id = id.clone();
        let mut handles = self
            .detect_threads
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        handles.retain(|handle| !handle.is_finished());
        let stopping = Arc::clone(self);
        handles.push(thread::spawn(move || {
            let resolved = stopping.resolve_auth_id_values(&auth_id, None);
            match resolved {
                Ok(resolved_auth) => {
                    let abort = Arc::clone(&stopping);
                    // 检测必须带上采集并复验过的 state：不带 state 的请求更容易被
                    // 上游降级，会把健康账号误判成降智。
                    let state = stopping.verified_state_for(&resolved_auth, &model);
                    let result = modeltrace::probe_with_progress(
                        &resolved_auth,
                        &model,
                        state.as_deref(),
                        |progress| stopping.update_modeltrace_task(&task_id, progress),
                        || !abort.running.load(Ordering::Acquire),
                    );
                    stopping.finish_modeltrace_task(&task_id, result);
                }
                Err(error) => stopping.fail_modeltrace_task(&task_id, error),
            }
        }));
        drop(handles);
        Ok(id)
    }

    fn update_modeltrace_task(&self, id: &str, progress: &modeltrace::ProbeProgress) {
        let mut tasks = self
            .modeltrace_tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(task) = tasks.get_mut(id) {
            task.progress = progress.clone();
            task.updated_at = now_seconds();
        }
    }

    fn finish_modeltrace_task(
        &self,
        id: &str,
        result: Result<modeltrace::ModelTraceReport, String>,
    ) {
        let mut tasks = self
            .modeltrace_tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(task) = tasks.get_mut(id) {
            match result {
                Ok(report) => {
                    let report = serde_json::to_value(report).ok();
                    if let Some(report) = &report {
                        let mut results = self
                            .modeltrace_results
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        results.insert(
                            modeltrace_result_key(&task.auth_id, &task.model),
                            report.clone(),
                        );
                        // 落盘：刷新页面或重启插件后结果仍然在。
                        save_modeltrace_results(&results);
                    }
                    task.status = "completed".to_owned();
                    task.report = report;
                }
                Err(error) => {
                    task.status = "failed".to_owned();
                    task.error = Some(error);
                }
            }
            task.updated_at = now_seconds();
        }
    }

    fn fail_modeltrace_task(&self, id: &str, error: String) {
        let mut tasks = self
            .modeltrace_tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(task) = tasks.get_mut(id) {
            task.status = "failed".to_owned();
            task.error = Some(error);
            task.updated_at = now_seconds();
        }
    }

    /// 页面刷新后用来找回仍在跑的检测任务。
    fn modeltrace_tasks_json(&self) -> Value {
        let tasks = self
            .modeltrace_tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut running: Vec<Value> = tasks
            .values()
            .filter(|task| task.status == "running")
            .map(|task| {
                json!({
                    "id": task.id,
                    "auth_id": task.auth_id,
                    "model": task.model,
                    "status": task.status,
                })
            })
            .collect();
        running.sort_by(|left, right| {
            left.get("id")
                .and_then(Value::as_str)
                .cmp(&right.get("id").and_then(Value::as_str))
        });
        json!({ "tasks": running })
    }

    fn modeltrace_task_json(&self, id: &str) -> Option<Value> {
        self.modeltrace_tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(id)
            .map(ModeltraceTask::json)
    }

    fn modeltrace_accounts(&self) -> Vec<ModelTraceAccount> {
        let mut accounts: Vec<ModelTraceAccount> = self
            .codex_auth_files()
            .into_iter()
            .map(|file| ModelTraceAccount {
                auth_id: file.auth_id,
                label: file.label,
            })
            .collect();
        if accounts.is_empty() {
            let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
            accounts = jobs
                .values()
                .filter(|job| modeltrace::supports_model(&job.model))
                .map(|job| ModelTraceAccount {
                    auth_id: job.auth_id.clone(),
                    label: job.auth_id.clone(),
                })
                .collect();
        }
        accounts.sort_by(|left, right| left.label.cmp(&right.label));
        accounts.dedup_by(|left, right| left.auth_id == right.auth_id);
        accounts
    }

    fn status_json(&self) -> Value {
        let now = now_seconds();
        let jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        let items: Vec<Value> = jobs
            .values()
            .map(|job| {
                let account = match job.account {
                    AccountKind::Personal => "personal",
                    AccountKind::Team => "team",
                };
                let status = job.store.status(now);
                let (rejected_status, retry_after) = job.limit.rejection(now).unwrap_or((0, 0));
                json!({
                    "auth_id": job.auth_id,
                    "model": job.model,
                    "account": account,
                    "state": {
                        "usable": status.usable,
                        "ready": status.ready,
                        "remaining": status.remaining_seconds,
                        "strikes": status.strikes,
                        "version": status.version,
                        "observations": status.observations,
                        "rejected_status": rejected_status,
                        "retry_after_seconds": retry_after,
                    },
                    "last_result": job.last_result,
                    "last_mode": job.last_mode.map(InjectionMode::as_str),
                    "probe_observation": job.probe_observation,
                })
            })
            .collect();
        json!({
            "jobs": items,
            "injection_enabled": self.injection_enabled.load(Ordering::Acquire),
            "state_fallback": self
                .fallback
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_str(),
            "mode_stats": self
                .mode_stats
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
            "state_stats": self
                .state_stats
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
            "egress": self.egress_summary(),
            "harvest_pause": self
                .harvest_pause_state()
                .map(|(left, reason)| json!({ "seconds_left": left, "reason": reason })),
        })
    }

    /// 出口池概况：一共几个、当前被冷却几个。
    fn egress_summary(&self) -> Value {
        let now = now_seconds();
        let total = self
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        let parked = self
            .egress_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .filter(|until| **until > now)
            .count();
        json!({ "total": total, "parked": parked })
    }

    fn set_injection(&self, enabled: bool) {
        self.injection_enabled.store(enabled, Ordering::Release);
    }

    fn set_fallback(&self, fallback: StateFallback) {
        let mut current = self
            .fallback
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *current = fallback;
    }

    fn modeltrace_result(&self, auth_id: &str, model: &str) -> Option<Value> {
        self.modeltrace_results
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&modeltrace_result_key(auth_id, model))
            .cloned()
    }
}

#[derive(Debug, Deserialize)]
struct InterceptRequest {
    #[serde(rename = "RequestID", default)]
    request_id: String,
    #[serde(rename = "Model", default)]
    model: String,
    #[serde(rename = "Headers", default)]
    headers: HashMap<String, Vec<String>>,
    #[serde(rename = "Body", default)]
    body_base64: Value,
    #[serde(rename = "Metadata", default)]
    metadata: Value,
}

impl InterceptRequest {
    fn auth_id(&self) -> String {
        self.metadata
            .get("selected_auth_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    fn auth_index(&self) -> Option<String> {
        self.metadata
            .get("selected_auth_index")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }
}

#[derive(Debug, Deserialize)]
struct ResponseEnvelope {
    #[serde(rename = "RequestID", default)]
    request_id: String,
    #[serde(rename = "Model", default)]
    model: String,
    #[serde(rename = "ResponseHeaders", default)]
    response_headers: Value,
    #[serde(rename = "Metadata", default)]
    metadata: Value,
    #[serde(rename = "StatusCode", default)]
    status_code: i64,
}

#[derive(Debug, Deserialize)]
struct CompletionEnvelope {
    #[serde(rename = "RequestID", default)]
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct ManagementRequest {
    #[serde(rename = "Path", default)]
    path: String,
    #[serde(rename = "Query", default)]
    query: Option<HashMap<String, Vec<String>>>,
}

fn observe_response(response: &ResponseEnvelope) {
    let Ok(runtime) = runtime() else {
        return;
    };
    observe_response_with(runtime, response);
}

/// 业务响应记账的本体；拆出来是为了能在测试里直接喂一个 Runtime。
fn observe_response_with(runtime: &Runtime, response: &ResponseEnvelope) {
    // CPA 里还有别的 provider（Claude / Kimi …），它们的响应同样会走到这里。
    // 只有 Codex 的 GPT 生成请求参与降智判定和计数，否则「无 state」会被别的流量灌爆。
    if !is_codex_gpt_model(&response.model) {
        return;
    }

    // 同一个请求只观测一次：流式响应会按 chunk 重复回调。
    {
        let mut observed = runtime
            .observed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if observed.len() > 4096 {
            observed.clear();
        }
        if !observed.insert(response.request_id.clone()) {
            return;
        }
    }

    record_rejection(response);
    let inflight = runtime
        .inflight
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&response.request_id)
        .cloned();
    let key = inflight
        .as_ref()
        .map(|value| value.key.clone())
        .unwrap_or_else(|| request_key(&response.metadata, &response.request_id, &response.model));

    // 上游可以随时撤销 state：响应里的 312 字节就是撤销信号。
    //
    // 这条必须在业务请求上处理：抱着已作废的 state 继续注入，等于持续降智。
    // 处置方式是立刻丢弃 active 并马上重采，而不是等下一条冷却到期。
    let returned = header_get_value(&response.response_headers, STATE_HEADER);
    // 按业务结果计数：注入了没被降智 / 收到 312 / 没有 state
    runtime.note_request_outcome(inflight.is_some(), returned.as_deref().map(str::len));
    if returned
        .as_deref()
        .is_some_and(|value| value.len() == DEGRADED_STATE_LEN)
    {
        let mut jobs = runtime
            .jobs
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(job) = jobs.get_mut(&key) {
            let now = now_seconds();
            // 只作废这次真正用到的那一份。排队中的续期是另一次独立签发、刚复验过的，
            // 让它顶上来继续用；连它一起扔掉只会多出一段没有 state 的空窗期。
            match inflight.as_ref() {
                Some(used) => {
                    job.store.reject_and_promote(&used.snapshot, now);
                }
                None => {
                    job.store = Arc::new(StateStore::new(job.store.policy()));
                }
            }
            job.next_probe = now;
            job.probe_observation = Some(json!({
                "state_len": DEGRADED_STATE_LEN,
                "degraded_signal": true,
                "source": "business_response",
                "accepted": false,
            }));
            job.last_result = Some("上游下发降智信号，已作废被撤销的 state".to_owned());
        }
        return;
    }

    let Some(value) = returned else {
        return;
    };
    let jobs = runtime
        .jobs
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(job) = jobs.get(&key) else {
        return;
    };

    if let Some(inflight) = inflight {
        let _ = job.store.observe(value, &inflight.snapshot, now_seconds());
    } else if let Ok(token) = TurnState::parse(value) {
        let _ = job.store.offer(token, now_seconds());
    }
}

fn is_codex_gpt_model(model: &str) -> bool {
    let model = model.trim().to_ascii_lowercase();
    (model.starts_with("gpt-") || model.starts_with("o1") || model.starts_with("o3"))
        && !model.contains("image")
        && !model.contains("audio")
        && !model.contains("tts")
        && !model.contains("whisper")
        && !model.contains("embedding")
        && !model.contains("moderation")
        && !model.contains("realtime")
}

/// 上游 401/403/429 是对整条凭据的结论，不能被有效的 turn-state 绕过。
/// 记录后，后续请求与探测在该凭据上都停下来。
///
/// 注意：现在 CPA 只在响应拦截里传 200，上游错误走的是 error 通道，所以这条
/// 属于纵深防御；真正会命中状态码的是采集路径。CPA 哪天把错误响应也送进来，
/// 这里就能立刻生效。
fn record_rejection(response: &ResponseEnvelope) {
    let Some(status) = RejectedStatus::from_http(response.status_code) else {
        return;
    };
    let Ok(runtime) = runtime() else {
        return;
    };
    let key = request_key(&response.metadata, &response.request_id, &response.model);
    let retry_after = retry_after_seconds(&response.response_headers);
    let now = now_seconds();
    let mut jobs = runtime
        .jobs
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(job) = jobs.get_mut(&key) else {
        return;
    };
    job.limit
        .reject(status, retry_after, REJECT_COOLDOWN_SECONDS, now);
    job.last_result = Some(format!("upstream_{}", status.code()));
    // 被拒绝时不再继续采集，直到冷却结束。
    job.next_probe = now.saturating_add(REJECT_COOLDOWN_SECONDS.max(retry_after));
}

/// 解析上游 Retry-After（秒）。HTTP 日期格式这里不支持，退回本地冷却。
fn retry_after_seconds(headers: &Value) -> i64 {
    header_get_value(headers, "Retry-After")
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or_default()
}

/// 从采集响应里取出上游实际使用的模型名。
///
/// 上游对 `X-Codex-Turn-State` 的返回不区分会话状态：降级会话同样会带回 state。
/// 因此必须核对这里返回的模型，才能判断这份 state 值不值得存。
fn served_model(body: &Value) -> Option<String> {
    let encoded = body.as_str()?;
    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')))
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;

    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        for pointer in ["/response/model", "/model"] {
            if let Some(model) = value.pointer(pointer).and_then(Value::as_str) {
                return Some(model.to_owned());
            }
        }
    }

    // SSE：只认完成事件
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(data.trim()) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("response.completed") {
            continue;
        }
        if let Some(model) = value.pointer("/response/model").and_then(Value::as_str) {
            return Some(model.to_owned());
        }
    }
    None
}

/// 采集用的 Codex 客户端版本：Astra 需要 0.153.4 及以上才会被视为现代客户端。
const CODEX_CLIENT_VERSION: &str = "0.153.4";

/// 采集请求需要一个随机会话 id，复用会让上游把多次采集当成同一会话。
fn uuid_like() -> String {
    let hex: String = rand::random::<u128>()
        .to_be_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn probe_body(model: &str) -> Value {
    // 宿主只接受 stream=false；上游实际使用的模型名从响应体里核对。
    json!({
        "model": model,
        "instructions": "Reply with exactly: pong",
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{ "type": "input_text", "text": "ping" }]
        }],
        "stream": false,
        "store": false
    })
}

fn request_key(metadata: &Value, request_id: &str, model: &str) -> StateKey {
    let auth_id = metadata
        .get("selected_auth_id")
        .and_then(Value::as_str)
        .or_else(|| metadata.get("selected_auth_index").and_then(Value::as_str))
        .filter(|value| !value.is_empty())
        .unwrap_or(request_id);
    StateKey {
        auth_id: auth_id.to_owned(),
        model: model.to_owned(),
    }
}

fn account_kind(headers: &HashMap<String, Vec<String>>, metadata: &Value) -> AccountKind {
    let hint = metadata
        .get("account_type")
        .and_then(Value::as_str)
        .or_else(|| metadata.get("plan_type").and_then(Value::as_str))
        .map(str::to_owned)
        .or_else(|| {
            header_get(headers, "Authorization").and_then(|value| {
                let token = value.strip_prefix("Bearer ")?;
                let payload = token.split('.').nth(1)?;
                let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
                let value: Value = serde_json::from_slice(&bytes).ok()?;
                value
                    .get("https://api.openai.com/auth")
                    .and_then(|value| value.get("chatgpt_plan_type"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
        });
    match hint.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("team" | "business") => AccountKind::Team,
        _ => AccountKind::Personal,
    }
}

fn header_get(headers: &HashMap<String, Vec<String>>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first().cloned())
}

fn header_get_value(headers: &Value, name: &str) -> Option<String> {
    headers
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.as_array())
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn header_set(headers: &mut HashMap<String, Vec<String>>, name: &str, value: String) {
    headers.retain(|key, _| !key.eq_ignore_ascii_case(name));
    headers.insert(name.to_owned(), vec![value]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_codex_gpt_models_enter_state_jobs() {
        assert!(is_codex_gpt_model("gpt-6-astra"));
        assert!(is_codex_gpt_model("gpt-5.6-sol"));
        assert!(!is_codex_gpt_model("claude-sonnet-5"));
        assert!(!is_codex_gpt_model("gpt-image-2"));
    }

    /// 卸载时线程要尽快退出：停止位置位后，分片睡眠不能等满一整轮。
    #[test]
    fn interruptible_sleep_returns_when_stopped() {
        let running = Arc::new(AtomicBool::new(true));
        let stopper = Arc::clone(&running);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            stopper.store(false, Ordering::Release);
        });
        let started = Instant::now();
        interruptible_sleep(&running, PROBE_YIELD);
        let elapsed = started.elapsed();
        let _ = handle.join();
        assert!(elapsed < PROBE_YIELD, "停止后不该睡满 {PROBE_YIELD:?}");
    }

    /// 出口池文件解析：坏条目丢掉，坏文件当"没有池子"。
    #[test]
    fn egress_pool_parses_only_well_formed_entries() {
        let dir = std::env::temp_dir().join(format!(
            "fixgpt-pool-{}-{}",
            std::process::id(),
            now_seconds()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("pool.json");
        std::fs::write(
            &path,
            r#"{"proxies":[{"url":"http://172.18.0.1:7901","label":"HK-01"},{"url":"   "},{"label":"no url"}]}"#,
        )
        .expect("write pool");

        let pool = load_egress_pool_at(&path);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].url, "http://172.18.0.1:7901");
        assert_eq!(pool[0].label, "HK-01");

        std::fs::write(&path, b"{not json").expect("write broken");
        assert!(load_egress_pool_at(&path).is_empty());
        assert!(load_egress_pool_at(&dir.join("missing.json")).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 出口轮换：按顺序轮、跳过冷却中的、全在冷却里也不至于停住。
    #[test]
    fn egress_rotation_skips_failed_nodes() {
        let runtime = Runtime::new();
        *runtime
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = vec![
            EgressNode {
                url: "http://a".to_owned(),
                label: "A".to_owned(),
            },
            EgressNode {
                url: "http://b".to_owned(),
                label: "B".to_owned(),
            },
            EgressNode {
                url: "http://c".to_owned(),
                label: "C".to_owned(),
            },
        ];

        let order: Vec<String> = (0..3)
            .map(|_| runtime.next_egress(100).expect("node").label)
            .collect();
        assert_eq!(order, vec!["A", "B", "C"], "一轮里按顺序轮换");

        runtime.note_egress("http://a", false, 100);
        assert!(
            (0..3)
                .map(|_| runtime.next_egress(100).expect("node").label)
                .all(|label| label != "A"),
            "冷却中的出口要被跳过"
        );

        runtime.note_egress("http://b", false, 100);
        runtime.note_egress("http://c", false, 100);
        assert!(
            runtime.next_egress(100).is_some(),
            "全部冷却时仍然给一个出口"
        );

        runtime.note_egress("http://a", true, 100);
        assert!(
            (0..3)
                .map(|_| runtime.next_egress(100).expect("node").label)
                .any(|label| label == "A"),
            "恢复后的出口重新参与轮换"
        );
    }

    /// 没有历史请求时，用默认模型作为采集目标。
    #[test]
    fn harvest_models_falls_back_to_default_model() {
        let runtime = Runtime::new();
        assert_eq!(
            runtime.harvest_models("nobody@example.com"),
            vec![default_harvest_model()]
        );
    }

    /// 造一个形状合法的 state（57 字节固定头 + 16 字节/块，头部带签发时间）。
    fn test_state(blocks: usize, issued_at: u64) -> String {
        use base64::engine::general_purpose::URL_SAFE;
        let mut raw = vec![0_u8; 57 + 16 * blocks];
        raw[0] = 0x80;
        raw[1..9].copy_from_slice(&issued_at.to_be_bytes());
        URL_SAFE.encode(raw)
    }

    /// 默认模型（astra）永远要有一个采集任务，不能被别的模型挤掉。
    #[test]
    fn priority_model_always_gets_a_job() {
        let runtime = Runtime::new();
        let auth = "auth-priority".to_owned();
        runtime.ensure_job(
            StateKey {
                auth_id: auth.clone(),
                model: "gpt-5.6-luna".to_owned(),
            },
            auth.clone(),
            None,
            "gpt-5.6-luna".to_owned(),
            AccountKind::Personal,
        );
        // 只按「已经出现过的模型」算的话，这里不会有 astra
        let plain = runtime.harvest_models(&auth);
        assert!(
            !plain.contains(&default_harvest_model()),
            "前置条件：默认模型不在里面"
        );
        // 带优先级的那份必须补上默认模型
        let models = runtime.harvest_models_with_priority(&auth);
        assert!(
            models.contains(&default_harvest_model()),
            "默认模型必须被补上"
        );
        assert!(models.iter().any(|m| m == "gpt-5.6-luna"), "原有模型不能丢");
    }

    /// 全是降级响应时停 30 分钟，其它失败停 10 分钟，采到就回到常规节奏。
    #[test]
    fn degraded_rounds_back_off_longer() {
        assert_eq!(harvest_cooldown(true, false), PROBE_COOLDOWN_SECONDS);
        assert_eq!(
            harvest_cooldown(false, true),
            DEGRADED_HARVEST_COOLDOWN_SECONDS
        );
        assert_eq!(
            harvest_cooldown(false, false),
            HARVEST_FAIL_COOLDOWN_SECONDS
        );
        const { assert!(DEGRADED_HARVEST_COOLDOWN_SECONDS > HARVEST_FAIL_COOLDOWN_SECONDS) };
    }

    /// 上游给的长度就是身份的一部分：个人 292、Team 332、降智信号 312。
    #[test]
    fn state_lengths_match_the_wire_shapes() {
        assert_eq!(test_state(10, 0).len(), 292);
        assert_eq!(test_state(12, 0).len(), 332);
        assert_eq!(test_state(11, 0).len(), DEGRADED_STATE_LEN);
    }

    /// 别的 provider 的响应不能进 Codex 的统计：CPA 里 Claude / Kimi 的流量走同一条钩子。
    #[test]
    fn non_codex_traffic_is_not_counted() {
        let runtime = Runtime::new();
        let read = || {
            runtime
                .state_stats
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get("no_state")
                .copied()
                .unwrap_or_default()
        };
        let before = read();
        observe_response_with(
            &runtime,
            &ResponseEnvelope {
                request_id: "req-claude".to_owned(),
                model: "claude-opus-4-6-thinking".to_owned(),
                response_headers: json!({}),
                metadata: json!({}),
                status_code: 200,
            },
        );
        assert_eq!(before, read(), "非 Codex 流量不该计入降智统计");
    }

    /// 业务响应收到 312 时，只作废被撤销的那一份；排队中的续期要顶上来。
    #[test]
    fn business_312_revokes_only_the_used_state() {
        let runtime = Runtime::new();
        let key = StateKey {
            auth_id: "auth-312".to_owned(),
            model: "gpt-6-astra".to_owned(),
        };
        let now = now_seconds();
        let (store, _limit) = runtime.ensure_job(
            key.clone(),
            key.auth_id.clone(),
            None,
            key.model.clone(),
            AccountKind::Personal,
        );
        // active = 半小时前签发的旧 state；ready = 刚采到、复验通过的续期
        assert!(store.offer(
            TurnState::parse(test_state(10, (now - 1800).max(1) as u64)).expect("state"),
            now
        ));
        assert!(store.offer(
            TurnState::parse(test_state(10, now as u64)).expect("state"),
            now
        ));
        let used = store.acquire(now).expect("active state");
        runtime
            .inflight
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                "req-312".to_owned(),
                Inflight {
                    key: key.clone(),
                    snapshot: used,
                },
            );

        let revoked = test_state(11, now as u64);
        assert_eq!(revoked.len(), DEGRADED_STATE_LEN);
        let mut headers = serde_json::Map::new();
        headers.insert(STATE_HEADER.to_owned(), json!([revoked]));

        observe_response_with(
            &runtime,
            &ResponseEnvelope {
                request_id: "req-312".to_owned(),
                model: key.model.clone(),
                response_headers: Value::Object(headers),
                metadata: json!({}),
                status_code: 200,
            },
        );

        let jobs = runtime
            .jobs
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let job = jobs.get(&key).expect("job");
        assert!(
            job.store.acquire(now_seconds()).is_some(),
            "排队中的续期应该顶上来，而不是整份作废"
        );
    }

    /// 重启后直接按磁盘记录重建任务：任务在 = 会继续续采，不必等真实请求。
    #[test]
    fn restore_jobs_rebuilds_tasks_from_disk_records() {
        let dir = std::env::temp_dir().join(format!(
            "fixgpt-restore-{}-{}",
            std::process::id(),
            now_seconds()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("turn-state.json");
        let now = now_seconds() as u64;
        let records = json!([
            {"auth_id": "acc-a", "auth_index": "idx-a", "model": "gpt-6-astra", "account": "personal", "value": test_state(10, now)},
            {"auth_id": "acc-b", "model": "gpt-6-astra", "account": "team", "value": test_state(12, now)},
            {"auth_id": "acc-c", "model": "gpt-6-astra", "account": "personal", "value": test_state(10, now - 7200)},
            {"auth_id": "acc-d", "model": "gpt-6-astra", "account": "personal", "value": "not-a-state"},
            {"model": "gpt-6-astra", "account": "personal", "value": test_state(10, now)}
        ]);
        std::fs::write(&path, serde_json::to_vec(&records).expect("encode")).expect("write");

        let jobs = restore_jobs_at(&path);
        assert_eq!(jobs.len(), 2, "只重建仍然可用的记录");

        let active = StateKey {
            auth_id: "acc-a".to_owned(),
            model: "gpt-6-astra".to_owned(),
        };
        let job_a = jobs.get(&active).expect("personal job");
        assert_eq!(
            job_a.auth_index.as_deref(),
            Some("idx-a"),
            "auth_index 一起恢复"
        );
        assert!(
            job_a.store.acquire(now_seconds()).is_some(),
            "重建后 state 可直接注入"
        );

        let team = StateKey {
            auth_id: "acc-b".to_owned(),
            model: "gpt-6-astra".to_owned(),
        };
        assert_eq!(
            jobs.get(&team).expect("team job").account,
            AccountKind::Team,
            "账号类型跟着恢复（决定块数规则）"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cloudflare 拦截页要压成人话：标签、style、script 全丢掉。
    #[test]
    fn html_response_is_reduced_to_readable_text() {
        let html = "<html><head><meta name=\"viewport\"><style>body{font-family:Arial}</style></head>\
<body><div class=\"container\"><h1>Sorry, you have been blocked</h1><p>Cloudflare Ray ID: 8f2</p></div>\
<script>var a=1;</script></body></html>";
        let snippet = plain_text_snippet(html, 80);
        assert!(
            snippet.contains("Sorry, you have been blocked"),
            "关键信息要留下: {snippet}"
        );
        assert!(!snippet.contains('<'), "不该残留标签: {snippet}");
        assert!(
            !snippet.contains("font-family"),
            "style 内容要丢掉: {snippet}"
        );
        assert!(!snippet.contains("var a"), "script 内容要丢掉: {snippet}");

        // 正常 JSON 也要能读出开头
        assert!(plain_text_snippet("{\"type\":\"response.completed\"}", 40).starts_with('{'));

        // 宿主的报错里夹着整页 HTML 时，也要能读
        let host_error = "auth_unavailable: no auth available (last upstream error: <html><head><style>body{font-family:Arial}</style></head><body><h1>Sorry, you have been blocked</h1></body></html>)";
        let compact = compact_error(host_error);
        assert!(
            compact.starts_with("auth_unavailable: no auth available"),
            "{compact}"
        );
        assert!(
            compact.contains("Sorry, you have been blocked"),
            "{compact}"
        );
        assert!(
            !compact.contains("font-family") && !compact.contains('<'),
            "{compact}"
        );
    }

    /// 凭据级错误要能被识别出来，否则会白轮 8 个出口还污染池子。
    #[test]
    fn credential_level_errors_are_recognised() {
        assert!(credential_unavailable(
            "auth_unavailable: no auth available"
        ));
        assert!(credential_unavailable(
            "plugin call host.model.execute returned 1: auth_not_found"
        ));
        // host.rs 保留宿主错误码之后，前缀就是稳定的错误码本身
        assert!(credential_unavailable(
            "auth_not_found: no auth available for model gpt-6-astra"
        ));
        assert!(credential_unavailable("AUTH_UNAVAILABLE: whatever"));
        // 会话被上游吊销：换出口/换模型都没用，等用户重新登录
        assert!(credential_unavailable(
            "token_revoked: invalidated oauth token"
        ));
        assert!(credential_unavailable(
            "host_call_failed: {\"error\":{\"code\":\"refresh_token_invalidated\"}}"
        ));
        assert!(credential_unavailable(
            "Encountered invalidated oauth token for user, failing request"
        ));
        assert!(!credential_unavailable("probe returned HTTP 502"));
        assert!(!credential_unavailable(
            "probe returned no turn-state header"
        ));
        assert!(!credential_unavailable(
            "upstream served gpt-5.6-luna for requested gpt-6-astra"
        ));
    }

    /// 没有 state 时一轮连着换出口试（预筛），但最多只走 HARVEST_ATTEMPTS 个。
    #[test]
    fn round_attempts_sweeps_the_pool_only_without_state() {
        let runtime = Runtime::new();
        *runtime
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = (0..12)
            .map(|index| EgressNode {
                url: format!("http://node-{index}"),
                label: format!("N{index}"),
            })
            .collect();
        let job = ProbeJob {
            key: StateKey {
                auth_id: "a".to_owned(),
                model: "gpt-6-astra".to_owned(),
            },
            auth_id: "a".to_owned(),
            auth_index: None,
            model: "gpt-6-astra".to_owned(),
            store: Arc::new(StateStore::new(StatePolicy::personal())),
        };
        assert_eq!(
            runtime.round_attempts(&job),
            HARVEST_ATTEMPTS,
            "一轮最多 8 个出口"
        );

        *runtime
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = vec![EgressNode {
            url: "http://only".to_owned(),
            label: "only".to_owned(),
        }];
        assert_eq!(runtime.round_attempts(&job), 1, "池子小就只试池子里那几个");

        *runtime
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Vec::new();
        assert_eq!(runtime.round_attempts(&job), 1, "没配出口池时只发一次");

        let token = TurnState::parse(test_state(10, now_seconds() as u64)).expect("state");
        assert!(job.store.offer(token, now_seconds()), "先塞一份可用 state");
        assert_eq!(
            runtime.round_attempts(&job),
            HARVEST_ATTEMPTS,
            "有 state 时按常规次数"
        );
    }

    /// 动态 IP 出口：{sid} 占位符每次都要换成新的会话号。
    #[test]
    fn egress_placeholder_rotates_per_use() {
        let raw = "socks5h://acct-region-Rand-sid-{sid}-t-5:secret@proxy.example.com:1080";
        let first = expand_egress_url(raw);
        let second = expand_egress_url(raw);
        assert!(!first.contains("{sid}"), "占位符要被替换: {first}");
        assert_ne!(first, second, "每次都要换一个会话号");
        for url in [&first, &second] {
            assert!(url.starts_with("socks5h://acct-region-Rand-sid-"), "{url}");
            assert!(url.ends_with("-t-5:secret@proxy.example.com:1080"), "{url}");
        }
        assert!(expand_egress_url("http://plain.example.com:8080").ends_with(":8080"));
    }

    /// 1024proxy：用户名里的粘性会话段要被轮换。
    #[test]
    fn sticky_session_segment_is_rotated_for_1024proxy() {
        let raw = "socks5h://ryvs744504-region-Rand-sid-abc123-t-5:fyfwqqrz@us.1024proxy.io:3000";
        let rotated = expand_egress_url(raw);
        assert!(!rotated.contains("abc123"), "旧的会话号要换掉: {rotated}");
        assert!(rotated.contains("-sid-"), "{rotated}");
        assert!(
            rotated.contains("-t-5:fyfwqqrz@us.1024proxy.io:3000"),
            "{rotated}"
        );

        // 用户名里没有 -sid- 段时补一个
        let without = expand_egress_url("socks5h://user:pass@us.1024proxy.io:3000");
        assert!(without.contains("-sid-"), "{without}");
        assert!(without.contains(":pass@us.1024proxy.io:3000"), "{without}");

        // 非 1024proxy 不动用户名
        let other = expand_egress_url("socks5h://user:pass@other.example.com:1080");
        assert_eq!(other, "socks5h://user:pass@other.example.com:1080");
    }

    /// 退避之后只轻试一次（不是 8 次），避免又把账号打回限流。
    #[test]
    fn gentle_mode_probes_once_after_backoff() {
        let runtime = Runtime::new();
        *runtime
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = (0..8)
            .map(|index| EgressNode {
                url: format!("http://node-{index}"),
                label: format!("N{index}"),
            })
            .collect();
        let job = ProbeJob {
            key: StateKey {
                auth_id: "a".to_owned(),
                model: "gpt-6-astra".to_owned(),
            },
            auth_id: "a".to_owned(),
            auth_index: None,
            model: "gpt-6-astra".to_owned(),
            store: Arc::new(StateStore::new(StatePolicy::personal())),
        };
        assert_eq!(
            runtime.round_attempts(&job),
            HARVEST_ATTEMPTS,
            "正常情况 8 次"
        );
        runtime.pause_harvest("上游 502 过载", OVERLOAD_PAUSE_SECONDS);
        assert_eq!(runtime.round_attempts(&job), 1, "退避后只轻试一次");
    }

    /// 上游过载要能熔断：暂停期间不调度采集，恢复后自动继续。
    #[test]
    fn overload_pauses_harvesting() {
        let runtime = Runtime::new();
        assert!(!runtime.harvest_paused(), "默认不暂停");

        runtime.pause_harvest("上游 502 过载", OVERLOAD_PAUSE_SECONDS);
        assert!(runtime.harvest_paused(), "过载后应暂停");
        let (left, reason) = runtime.harvest_pause_state().expect("pause state");
        assert!(left > OVERLOAD_PAUSE_SECONDS - 5 && left <= OVERLOAD_PAUSE_SECONDS);
        assert_eq!(reason, "上游 502 过载");
        assert!(runtime.next_due_job().is_none(), "暂停期间不发探测");

        // 更短的暂停不能把已有的暂停时间改短
        runtime.pause_harvest("别的理由", 30);
        assert!(runtime.harvest_pause_state().expect("still paused").0 > 30);

        // 过期的暂停不算暂停
        runtime
            .harvest_pause_until
            .store((now_seconds() - 1) as u64, Ordering::Release);
        assert!(!runtime.harvest_paused());
        assert!(runtime.harvest_pause_state().is_none());
    }

    /// 采到过合格 state 的出口，下一轮优先再选它。
    #[test]
    fn known_good_egress_is_preferred() {
        let runtime = Runtime::new();
        *runtime
            .egress_pool
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = vec![
            EgressNode {
                url: "http://bad".to_owned(),
                label: "BAD".to_owned(),
            },
            EgressNode {
                url: "http://good".to_owned(),
                label: "GOOD".to_owned(),
            },
        ];
        runtime.note_egress_good("http://good", now_seconds());
        for _ in 0..4 {
            assert_eq!(
                runtime.next_egress(now_seconds()).expect("node").label,
                "GOOD",
                "有成功记录时只用成功过的出口"
            );
        }
        runtime.note_egress_good("http://good", now_seconds() - EGRESS_GOOD_TTL_SECONDS - 1);
        let labels: Vec<String> = (0..2)
            .map(|_| runtime.next_egress(now_seconds()).expect("node").label)
            .collect();
        assert!(
            labels.contains(&"BAD".to_owned()),
            "过期后不再独占: {labels:?}"
        );
    }

    /// 池子换新（订阅刷新）时，旧的失败记录要清掉。
    #[test]
    fn applying_a_new_pool_clears_stale_failures() {
        let runtime = Runtime::new();
        let pool = vec![EgressNode {
            url: "http://node-a".to_owned(),
            label: "A".to_owned(),
        }];
        assert!(runtime.apply_egress_pool(pool.clone()), "首次应用算变化");
        runtime.note_egress("http://node-a", false, now_seconds());
        assert!(!runtime.apply_egress_pool(pool), "同样的池子不算变化");
        assert_eq!(
            runtime
                .egress_failures
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1,
            "池子没变就保留失败记录"
        );

        let changed = vec![EgressNode {
            url: "http://node-b".to_owned(),
            label: "B".to_owned(),
        }];
        assert!(runtime.apply_egress_pool(changed), "换了池子算变化");
        assert!(
            runtime
                .egress_failures
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "换池子后清空失败记录"
        );
    }

    #[test]
    fn request_key_prefers_selected_auth_id() {
        let metadata = json!({ "selected_auth_id": "auth-a", "selected_auth_index": "index-a" });
        let key = request_key(&metadata, "request-1", "gpt-6-astra");
        assert_eq!(key.auth_id, "auth-a");
        assert_eq!(key.model, "gpt-6-astra");
    }

    #[test]
    fn headers_are_replaced_case_insensitively() {
        let mut headers = HashMap::from([
            ("x-codex-turn-state".to_owned(), vec!["old".to_owned()]),
            ("X-Other".to_owned(), vec!["keep".to_owned()]),
        ]);
        header_set(&mut headers, STATE_HEADER, "new".to_owned());
        assert_eq!(header_get(&headers, STATE_HEADER).as_deref(), Some("new"));
        assert_eq!(header_get(&headers, "X-Other").as_deref(), Some("keep"));
        assert!(!headers.contains_key("x-codex-turn-state"));
    }

    #[test]
    fn jwt_team_hint_selects_team_policy() {
        let token = "eyJhbGciOiJub25lIn0.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJ0ZWFtIn19.";
        let headers =
            HashMap::from([("Authorization".to_owned(), vec![format!("Bearer {token}")])]);
        assert_eq!(account_kind(&headers, &json!({})), AccountKind::Team);
    }
}

#[cfg(test)]
mod menu_render_tests {
    use super::*;

    /// 空状态提示只能出现在"一个账号都没有"的情况下。
    /// 之前它被误并入 task panel，导致每张卡片都多出两个空框。
    #[test]
    fn task_panel_has_no_empty_state_placeholder() {
        assert!(
            !MODELTRACE_TASK_PANEL.contains("没有启用的 Codex 账号"),
            "task panel 不该包含空状态提示：{}",
            MODELTRACE_TASK_PANEL
        );
        assert!(
            !MODELTRACE_TASK_PANEL.contains("class=\"empty\""),
            "task panel 不该包含 .empty 元素"
        );
        // 面板结构保持完整
        assert!(MODELTRACE_TASK_PANEL.starts_with("<div class=\"task-area\""));
        assert!(MODELTRACE_TASK_PANEL.ends_with("</div>"));
        assert!(MODELTRACE_TASK_PANEL.contains("progress-panel"));
        assert!(MODELTRACE_TASK_PANEL.contains("result-panel"));
    }

    #[test]
    fn modeltrace_page_has_no_cross_page_menu() {
        let request = ManagementRequest {
            path: "/modeltrace".to_owned(),
            query: None,
        };
        let html = render_modeltrace_page(&request);
        // FixGPT 状态页已移除，页面不再有跨页菜单。
        assert!(!html.contains("topnav"));
        assert!(!html.contains("/v0/resource/plugins/fixgpt/status"));
        assert!(html.contains("account-card") || html.contains("没有启用的 Codex 账号"));
        assert!(html.contains("/modeltrace/start"));
        assert!(html.contains("/modeltrace/status"));
    }

    #[test]
    fn modeltrace_page_is_gpt_only() {
        let request = ManagementRequest {
            path: "/modeltrace".to_owned(),
            query: None,
        };
        let html = render_modeltrace_page(&request);
        assert!(html.contains("GPT-only"));
        assert!(!html.contains("Claude"));
    }

    #[test]
    fn modeltrace_results_survive_a_reload() {
        let directory = std::env::temp_dir().join(format!(
            "fixgpt-persist-{}-{}",
            std::process::id(),
            now_seconds()
        ));
        std::fs::create_dir_all(&directory).expect("temp dir");
        let path = directory.join("results.json");

        let mut results = HashMap::new();
        results.insert(
            modeltrace_result_key("auth-a", "gpt-6-astra"),
            json!({ "prediction": "gpt-5.6-luna", "probability": 0.99 }),
        );
        save_modeltrace_results_at(&path, &results);

        let reloaded = load_modeltrace_results_at(&path);
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded
                .get(&modeltrace_result_key("auth-a", "gpt-6-astra"))
                .and_then(|value| value.get("prediction"))
                .and_then(Value::as_str),
            Some("gpt-5.6-luna")
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// 之前用 HashMap 直存时，key 里的 NUL 会写出非法 JSON，读取被静默丢弃。
    /// 现在格式换成记录数组，同时保证遇到坏文件也只是"没有历史结果"。
    #[test]
    fn corrupt_results_file_is_ignored() {
        let directory = std::env::temp_dir().join(format!(
            "fixgpt-corrupt-{}-{}",
            std::process::id(),
            now_seconds()
        ));
        std::fs::create_dir_all(&directory).expect("temp dir");
        let path = directory.join("results.json");

        // 裸 NUL 在 JSON 字符串里非法
        let mut broken: Vec<u8> = b"[{\"key\":\"a".to_vec();
        broken.push(0);
        broken.extend_from_slice(b"b\",\"report\":{}}");
        std::fs::write(&path, broken).expect("write broken file");
        assert!(load_modeltrace_results_at(&path).is_empty());

        // 记录数组格式可以正常往返
        let mut results = HashMap::new();
        results.insert(
            modeltrace_result_key("auth", "gpt-6-astra"),
            json!({ "prediction": "gpt-5.6-luna" }),
        );
        save_modeltrace_results_at(&path, &results);
        let text = std::fs::read_to_string(&path).expect("read back");
        assert!(text.contains("\\u0000"), "NUL 必须被转义: {text}");
        assert_eq!(load_modeltrace_results_at(&path).len(), 1);

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// 端到端：内存里有结果时，页面必须把它渲染出来（刷新不丢）。
    #[test]
    fn modeltrace_page_shows_stored_result() {
        let key = modeltrace_result_key("auth-a", "gpt-6-astra");
        let report = json!({
            "expected": "gpt-6-astra",
            "outcome": "difference_signal",
            "prediction": "gpt-5.6-luna",
            "probability": 0.99,
            "used_outputs": 3,
        });
        let markup = modeltrace_result_markup(Some(report.clone()));
        assert!(markup.contains("gpt-5.6-luna"), "markup: {markup}");
        assert!(!markup.contains("尚未检测"));

        // 模拟页面查表
        let mut results: HashMap<String, Value> = HashMap::new();
        results.insert(key.clone(), report);
        let found = results.get(&modeltrace_result_key("auth-a", "gpt-6-astra"));
        assert!(found.is_some(), "查表命中");
        let rendered = modeltrace_result_markup(found.cloned());
        assert!(rendered.contains("gpt-5.6-luna"), "rendered: {rendered}");
    }

    #[test]
    fn missing_results_file_is_not_an_error() {
        let path = std::env::temp_dir().join("fixgpt-does-not-exist.json");
        assert!(load_modeltrace_results_at(&path).is_empty());
    }

    #[test]
    fn injection_is_enabled_by_default() {
        let runtime = Runtime::new();
        assert!(runtime.injection_enabled.load(Ordering::Acquire));
        runtime.set_injection(false);
        assert!(!runtime.injection_enabled.load(Ordering::Acquire));
        runtime.set_injection(true);
        assert!(runtime.injection_enabled.load(Ordering::Acquire));
    }

    /// 生成请求的判定：只有带 reasoning.encrypted_content 的才算，
    /// 压缩与元数据请求不参与严格判定。
    #[test]
    fn generation_detection_matches_project_semantics() {
        let generation = json!({
            "model": "gpt-6-astra",
            "include": ["reasoning.encrypted_content"],
            "stream": true,
        });
        let encoded = STANDARD.encode(serde_json::to_vec(&generation).expect("encode"));
        assert!(is_generation_request(&json!(encoded)), "生成请求应被识别");

        let metadata = json!({ "model": "gpt-6-astra", "stream": false });
        let encoded = STANDARD.encode(serde_json::to_vec(&metadata).expect("encode"));
        assert!(
            !is_generation_request(&json!(encoded)),
            "元数据请求不参与严格判定"
        );

        // 非法 / 缺失的 body 不能当成生成请求
        assert!(!is_generation_request(&json!("not-base64!!")));
        assert!(!is_generation_request(&Value::Null));
    }

    /// 严格模式下没有可用 state 时，必须明确拒绝而不是静默转发。
    #[test]
    fn strict_mode_terminates_with_503() {
        let response = terminate_state_unavailable();
        assert_eq!(
            response.get("Terminate").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            response.get("StatusCode").and_then(Value::as_i64),
            Some(503)
        );
        let body = response
            .get("ResponseBody")
            .and_then(Value::as_str)
            .expect("body");
        let decoded = STANDARD.decode(body).expect("base64");
        let text = String::from_utf8(decoded).expect("utf8");
        assert!(text.contains("state_unavailable"), "body: {text}");
    }

    /// 策略可切换，默认是兜底（与原项目首次 setup 的行为一致）。
    #[test]
    fn state_fallback_defaults_to_passthrough_and_switches() {
        let runtime = Runtime::new();
        assert_eq!(
            *runtime
                .fallback
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            StateFallback::Passthrough
        );
        runtime.set_fallback(StateFallback::Strict);
        assert_eq!(
            *runtime
                .fallback
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            StateFallback::Strict
        );
    }

    #[test]
    fn injection_mode_labels_match_the_wire_values() {
        assert_eq!(InjectionMode::Injected.as_str(), "injected");
        assert_eq!(
            InjectionMode::FallbackPassthrough.as_str(),
            "fallback-passthrough"
        );
        assert_eq!(
            InjectionMode::UpstreamRejected.as_str(),
            "upstream-rejected"
        );
        assert_eq!(InjectionMode::Rejected.as_str(), "state-unavailable");
    }

    #[test]
    fn status_bar_counts_request_outcomes() {
        let bar = render_status_bar(&json!({
            "state_stats": { "ok": 12, "degraded": 3, "no_state": 1 },
        }));
        assert!(bar.contains("正常 12"), "{bar}");
        assert!(bar.contains("降智 3"), "{bar}");
        assert!(bar.contains("无 state 1"), "{bar}");
        // 不该再显示只是"上游给了 state"的口径
        assert!(!bar.contains("通行证"), "旧口径已废弃: {bar}");
    }

    /// 页面 HTML 用到的 class 必须在 CSS 里有定义。
    ///
    /// 之前 `.badge` / `.status-bar` 只加进了 HTML 没加进 CSS，页面上显示成
    /// 一坨没有样式的纯文本——只查 HTML 的测试发现不了这个。
    #[test]
    fn every_rendered_class_has_css() {
        let page = render_modeltrace_page(&ManagementRequest {
            path: "/status".to_owned(),
            query: None,
        });
        let css = {
            let start = page.find("<style>").expect("style") + "<style>".len();
            let end = page.find("</style>").expect("style end");
            &page[start..end]
        };
        // 页面（含账号卡片）可能用到的全部 class
        for class in [
            "status-bar",
            "badge",
            "account-card",
            "account-head",
            "avatar",
            "account-title",
            "status-pill",
            "account-controls",
            "account-result",
            "progress-panel",
            "result-panel",
            "page-header",
            "privacy-badge",
        ] {
            assert!(
                css.contains(&format!(".{class}{{")),
                "CSS 里缺少 .{class} 的定义"
            );
        }
        // 基础模板渲染后不该残留占位符
        assert!(!page.contains("__STATUS_BAR__"));
        assert!(page.contains("class=\"status-bar\""));
    }

    /// 合并后只应有一个页面：/status 和 /modeltrace 渲染同一份模板。
    #[test]
    fn status_path_renders_the_merged_page() {
        let page = render_modeltrace_page(&ManagementRequest {
            path: "/status".to_owned(),
            query: None,
        });
        assert!(!page.contains("__STATUS_BAR__"), "占位符未替换");
        assert!(!page.contains("__ACCOUNT_CARDS__"), "占位符未替换");
        assert!(page.contains("class=\"status-bar\""), "缺状态条");
    }

    /// 账号卡片上的状态用人话描述，不堆内部术语。
    #[test]
    fn account_card_describes_state_in_plain_words() {
        let page = render_modeltrace_page(&ManagementRequest {
            path: "/modeltrace".to_owned(),
            query: None,
        });
        // 卡片上有 status-pill（正常/降智/采集中的状态位）
        assert!(page.contains("status-pill"), "卡片应有状态位");
        // 不该出现内部术语
        assert!(!page.contains("STRIKES"));
        assert!(!page.contains("observations"));
    }

    #[test]
    fn human_seconds_reads_naturally() {
        assert_eq!(human_seconds(45), "45 秒");
        assert_eq!(human_seconds(600), "10 分钟");
        assert_eq!(human_seconds(5400), "1 小时 30 分");
        assert_eq!(human_seconds(0), "已过期");
    }

    #[test]
    fn html_escape_blocks_markup() {
        assert_eq!(
            html("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    }
}
