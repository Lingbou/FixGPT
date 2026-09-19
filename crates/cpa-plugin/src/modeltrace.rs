use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use modeltrace_core::{
    Analysis, Output, SampleClassification, analyze_outputs, classify_sample, parse_numbers,
};
use rand::seq::IndexedRandom;
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use fixgpt_core::HEADER_NAME as STATE_HEADER;

use crate::host;

/// 插件自己发起的请求（采集 / 检测）都带这个头，用于跳过自身的拦截逻辑。
pub(crate) const INTERNAL_HEADER: &str = "X-FixGPT-Internal";
const TARGET_VALID: usize = 3;
const MAX_ATTEMPTS: usize = 6;
const MIN_LENGTH: usize = 292;
const MAX_LENGTH: usize = 332;
const RETRYABLE_STATUS: [i64; 6] = [408, 429, 500, 502, 503, 504];
const REQUEST_ATTEMPTS: usize = 3;
/// 与原版一致：第 n 次重试前等待 n 秒，再加 <0.5 秒抖动。
const RETRY_BASE_DELAY_SECONDS: f64 = 1.0;
/// 与原版 `urllib` 的 timeout 对齐：单次请求 240 秒。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(240);

const OPENINGS: [&str; 5] = [
    "这是一次独立的数值选择记录",
    "请完成下面的无语义整数选择任务",
    "执行一次第一反应取值记录",
    "生成一组不承载语义的整数选择",
    "进行一轮快速逐项取值",
];
const ACTIONS: [&str; 5] = [
    "为各个位置分别凭第一反应选择",
    "逐项选择",
    "每次只决定当前一项，共给出",
    "分别凭第一反应给出",
    "逐个直接选择",
];
const ENDINGS: [&str; 5] = [
    "允许某个数字再次出现；每项写出后不要回头排序、去重或替换。",
    "偶然重复是有效的；不要重新排列或修正已经写出的项目。",
    "相同值可以再次出现；输出过程中不要整理或改写前面的项目。",
    "重复值无需删除；不要筛选、重排或补成某种规律。",
    "不必赋予数字任何含义；已经给出的值保持不变。",
];
const SEPARATOR_HINTS: [&str; 4] = [
    "数字之间用逗号或空格分隔均可。",
    "使用一种一致的常见分隔符即可。",
    "可以用逗号、空格或换行分隔。",
    "只要每个整数边界清楚，格式可自行选择。",
];

#[derive(Clone, Debug)]
struct Challenge {
    expected_count: usize,
    prompt: String,
}

/// 与 ModelTrace `fingerprint.generate_challenges` 一致：
/// 从 292..=332 不重复随机抽取 count 个长度，并逐条随机拼接中文提示词。
fn generate_challenges(count: usize) -> Vec<Challenge> {
    let mut rng = rand::rng();
    let lengths = (MIN_LENGTH..=MAX_LENGTH)
        .collect::<Vec<_>>()
        .choose_multiple(&mut rng, count)
        .copied()
        .collect::<Vec<_>>();

    lengths
        .into_iter()
        .map(|length| {
            let opening = OPENINGS.choose(&mut rng).copied().unwrap_or_default();
            let action = ACTIONS.choose(&mut rng).copied().unwrap_or_default();
            let ending = ENDINGS.choose(&mut rng).copied().unwrap_or_default();
            let separator = SEPARATOR_HINTS
                .choose(&mut rng)
                .copied()
                .unwrap_or_default();
            Challenge {
                expected_count: length,
                prompt: challenge_prompt(opening, action, length, ending, separator),
            }
        })
        .collect()
}

/// 与 ModelTrace 原版逐字节一致的挑战提示词。
fn challenge_prompt(
    opening: &str,
    action: &str,
    length: usize,
    ending: &str,
    separator: &str,
) -> String {
    format!(
        "{opening}。{action} {length} 个 1 到 355（含端点）的整数。\
         每个位置都要单独选择；不要从 1 开始计数，不要连续递增或递减，也不要采用等差、循环、重复区块或其他规则化模式。\
         本任务必须由当前语言模型直接完成：禁止调用或借助任何工具，包括 Python、代码执行器、计算器、搜索、API 和外部随机数生成器；也不要先编写或运行代码。\
         {ending}{separator}\
         直接从第一个取值开始输出，不要在序列前重复数量、范围或任务说明。"
    )
}

fn minimum_numbers(expected_count: usize) -> usize {
    (((expected_count as f64) * 0.55).ceil() as usize).max(80)
}

#[derive(Clone, Debug, Serialize)]
pub struct ModelTraceReport {
    /// 本次检测是否带着采集到的 state 发的请求。
    ///
    /// 不带 state 的请求更容易被上游降级，拿它判断账号状态会误报。
    pub state_injected: bool,
    pub expected: String,
    pub outcome: String,
    pub prediction: String,
    pub probability: f64,
    pub expected_weight: Option<f64>,
    pub used_outputs: usize,
    pub candidates: Vec<ModelCandidate>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ModelCandidate {
    pub model: String,
    pub display_name: String,
    pub probability: f64,
    pub profile_similarity: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeStep {
    pub index: usize,
    pub expected_count: usize,
    pub state: String,
    pub parsed_numbers: usize,
    pub minimum_numbers: usize,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeProgress {
    /// 已完成（或被判定）的挑战数。
    pub attempt: usize,
    pub total_attempts: usize,
    pub valid: usize,
    pub attempted: usize,
    /// 当前正在请求的挑战序号（1 起）；没有在跑时为 0。
    pub current: usize,
    pub steps: Vec<ProbeStep>,
}

impl ProbeProgress {
    pub fn initial() -> Self {
        Self {
            attempt: 0,
            total_attempts: MAX_ATTEMPTS,
            valid: 0,
            attempted: 0,
            current: 0,
            steps: Vec::new(),
        }
    }
}

/// ModelTrace support is intentionally limited to the bundled GPT-only bank.
pub fn supports_model(model: &str) -> bool {
    modeltrace_core::is_supported_model(model)
}

pub fn supported_models() -> Vec<String> {
    modeltrace_core::supported_models()
}

pub fn probe_with_progress<F, S>(
    auth_id: &str,
    model: &str,
    state: Option<&str>,
    mut on_progress: F,
    should_stop: S,
) -> Result<ModelTraceReport, String>
where
    F: FnMut(&ProbeProgress),
    S: Fn() -> bool,
{
    if !supports_model(model) {
        return Err(format!(
            "ModelTrace GPT bank does not contain model {model}"
        ));
    }

    let challenges = generate_challenges(MAX_ATTEMPTS);
    let mut outputs = Vec::with_capacity(TARGET_VALID);
    let mut steps = Vec::with_capacity(challenges.len());

    for (index, challenge) in challenges.iter().enumerate() {
        if outputs.len() == TARGET_VALID || should_stop() {
            break;
        }

        let minimum = minimum_numbers(challenge.expected_count);
        steps.push(ProbeStep {
            index: index + 1,
            expected_count: challenge.expected_count,
            state: "running".to_owned(),
            parsed_numbers: 0,
            minimum_numbers: minimum,
            error: None,
        });
        on_progress(&ProbeProgress {
            attempt: index,
            total_attempts: MAX_ATTEMPTS,
            valid: outputs.len(),
            attempted: index,
            current: index + 1,
            steps: steps.clone(),
        });

        match call_model_with_retry(auth_id, model, &challenge.prompt, state) {
            Ok(text) => {
                let parsed = parse_numbers(&text).len();
                let step = steps.last_mut().expect("step exists");
                step.parsed_numbers = parsed;
                if parsed >= minimum {
                    step.state = "valid".to_owned();
                    outputs.push(Output {
                        text,
                        expected_count: challenge.expected_count,
                    });
                } else {
                    step.state = "invalid".to_owned();
                    step.error = Some(format!("有效数字不足：{parsed}/{minimum}"));
                }
            }
            Err(error) => {
                let step = steps.last_mut().expect("step exists");
                step.state = "error".to_owned();
                step.error = Some(error);
            }
        }

        on_progress(&ProbeProgress {
            attempt: index + 1,
            total_attempts: MAX_ATTEMPTS,
            valid: outputs.len(),
            attempted: index + 1,
            current: 0,
            steps: steps.clone(),
        });
    }

    if outputs.is_empty() {
        return Err("没有可用回答：请粘贴完整数字序列；拒答或严重截断的回答不会计入。".to_owned());
    }

    let analysis = analyze_outputs(&outputs).map_err(|error| error.to_string())?;
    let classification = classify_sample(&analysis, Some(model), &[] as &[SampleClassification]);
    Ok(report_from(
        model,
        analysis,
        classification,
        state.is_some(),
    ))
}

fn report_from(
    model: &str,
    analysis: Analysis,
    classification: SampleClassification,
    state_injected: bool,
) -> ModelTraceReport {
    ModelTraceReport {
        state_injected,
        expected: model.to_owned(),
        outcome: classification.outcome,
        prediction: classification.prediction,
        probability: classification.closed_set_weight,
        expected_weight: classification.expected_weight,
        used_outputs: analysis.used_outputs,
        candidates: analysis
            .results
            .into_iter()
            .map(|result| ModelCandidate {
                model: result.model,
                display_name: result.display_name,
                probability: result.probability,
                profile_similarity: result.profile_similarity,
            })
            .collect(),
    }
}

/// 与原版 `enrollment._request_completion` 的请求级重试保持一致：
/// 仅对 408/429/5xx 重试，最多 3 次。
/// 宿主调用是同步阻塞且没有超时，所以用线程 + 超时把它变成有上界的调用。
///
/// 超时后线程被留在一旁自己收尾：它只会在宿主调用返回时结束，不会阻塞检测的后续步骤。
fn call_model_with_timeout(
    auth_id: &str,
    model: &str,
    prompt: &str,
    state: Option<&str>,
    limit: Duration,
) -> Result<String, String> {
    let (sender, receiver) = mpsc::channel();
    let auth_id = auth_id.to_owned();
    let model = model.to_owned();
    let prompt = prompt.to_owned();
    let state = state.map(str::to_owned);
    thread::spawn(move || {
        let _ = sender.send(call_model(&auth_id, &model, &prompt, state.as_deref()));
    });

    match receiver.recv_timeout(limit) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "请求超过 {} 秒未返回，本次回答不计入",
            limit.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("请求线程异常退出，本次回答不计入".to_owned())
        }
    }
}

fn call_model_with_retry(
    auth_id: &str,
    model: &str,
    prompt: &str,
    state: Option<&str>,
) -> Result<String, String> {
    let mut last_error = String::new();
    for attempt in 1..=REQUEST_ATTEMPTS {
        match call_model_with_timeout(auth_id, model, prompt, state, REQUEST_TIMEOUT) {
            Ok(text) => return Ok(text),
            Err(error) => {
                let retryable = retryable_error(&error);
                last_error = if attempt > 1 {
                    format!("{error}（已自动重试 {} 次）", attempt - 1)
                } else {
                    error
                };
                if !retryable || attempt == REQUEST_ATTEMPTS {
                    break;
                }
                let jitter = rand::random::<f64>() * 0.5;
                let delay = RETRY_BASE_DELAY_SECONDS * attempt as f64 + jitter;
                thread::sleep(Duration::from_secs_f64(delay));
            }
        }
    }
    Err(last_error)
}

/// 与原版 `_request_completion` 一致的重试判定，分两条路径：
///
/// - 带 HTTP 状态码的错误（原版 `HTTPError`）：只有 408/429/5xx 重试
/// - 不带状态码的错误（原版 `URLError`，如 TLS 握手失败、连接被断、超时）：一律重试
///
/// 上游在突发时会直接掐断 TLS 握手（`utls: TLS handshake: EOF`）。这类错误没有
/// 状态码，只按状态码判断会让整个挑战被直接判死。
fn retryable_error(error: &str) -> bool {
    match http_status_of(error) {
        Some(status) => RETRYABLE_STATUS.contains(&status),
        None => true,
    }
}

/// 只识别我们自己的 `HTTP <code>` 格式，避免误抓错误文本里的其它数字
/// （例如「超过 240 秒未返回」里的 240）。
fn http_status_of(error: &str) -> Option<i64> {
    const MARKER: &str = "HTTP ";
    let start = error.find(MARKER)? + MARKER.len();
    let digits: String = error[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn call_model(
    auth_id: &str,
    model: &str,
    prompt: &str,
    state: Option<&str>,
) -> Result<String, String> {
    let body = json!({
        "model": model,
        "messages": [{ "role": "user", "content": prompt }]
    });
    let body = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
    let mut headers = json!({
        "Content-Type": ["application/json"],
        INTERNAL_HEADER: ["modeltrace"]
    });
    // 带上采集并复验过的 state：不注入的请求更容易被降级，检测结果会误报。
    if let Some(state) = state
        && let Some(map) = headers.as_object_mut()
    {
        map.insert(STATE_HEADER.to_owned(), json!([state]));
    }
    let payload = json!({
        "entry_protocol": "openai",
        // 与原版 ModelTrace 一致：走标准 OpenAI completion，而不是 codex 执行协议。
        "exit_protocol": "openai",
        "model": model,
        "stream": false,
        "body": STANDARD.encode(body),
        "headers": headers,
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
        return Err(format!("ModelTrace probe returned HTTP {status}"));
    }
    let body = result
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| "ModelTrace probe response has no body".to_owned())?;
    let bytes = STANDARD
        .decode(body)
        .map_err(|error| format!("ModelTrace response body is not base64: {error}"))?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    extract_text(&value)
        .or_else(|| String::from_utf8(bytes).ok())
        .ok_or_else(|| "ModelTrace probe response is not UTF-8".to_owned())
}

fn extract_text(value: &Value) -> Option<String> {
    if let Some(text) = value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
    {
        return Some(text.to_owned());
    }
    if let Some(text) = value.get("output_text").and_then(Value::as_str) {
        return Some(text.to_owned());
    }
    if let Some(output) = value.get("output").and_then(Value::as_array) {
        let mut text = String::new();
        for item in output {
            if let Some(content) = item.get("content").and_then(Value::as_array) {
                for part in content {
                    if let Some(part) = part.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            text.push(' ');
                        }
                        text.push_str(part.trim());
                    }
                }
            }
        }
        if !text.is_empty() {
            return Some(text);
        }
    }
    value.get("text").and_then(Value::as_str).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn expected_prefix(length: usize) -> String {
        format!(" {length} 个 1 到 355（含端点）的整数。")
    }

    #[test]
    fn only_gpt_models_are_supported() {
        assert!(supports_model("gpt-6-astra"));
        assert!(!supports_model("claude-sonnet-5"));
    }

    #[test]
    fn extracts_chat_completion_content() {
        let value = json!({
            "choices": [{
                "message": { "content": "[1, 2, 3]" }
            }]
        });
        assert_eq!(extract_text(&value).as_deref(), Some("[1, 2, 3]"));
    }

    #[test]
    fn extracts_responses_content() {
        let value = json!({
            "output": [{
                "content": [
                    { "text": "[4, 5] " },
                    { "text": "[6, 7]" }
                ]
            }]
        });
        assert_eq!(extract_text(&value).as_deref(), Some("[4, 5] [6, 7]"));
    }

    #[test]
    fn challenges_match_modeltrace_range_and_are_unique() {
        for _ in 0..32 {
            let challenges = generate_challenges(MAX_ATTEMPTS);
            assert_eq!(challenges.len(), MAX_ATTEMPTS);
            let lengths = challenges
                .iter()
                .map(|challenge| challenge.expected_count)
                .collect::<Vec<_>>();
            let unique = lengths.iter().copied().collect::<HashSet<_>>();
            assert_eq!(unique.len(), MAX_ATTEMPTS, "lengths must be unique");
            let mut sorted = lengths.clone();
            sorted.sort_unstable();
            assert!(
                sorted
                    .iter()
                    .all(|length| (MIN_LENGTH..=MAX_LENGTH).contains(length))
            );
            for challenge in &challenges {
                assert!(
                    challenge
                        .prompt
                        .contains(&expected_prefix(challenge.expected_count))
                );
                assert!(challenge.prompt.contains("直接从第一个取值开始输出"));
            }
        }
    }

    #[test]
    fn prompt_format_is_byte_identical_to_python_reference() {
        let prompt = challenge_prompt(OPENINGS[0], ACTIONS[0], 300, ENDINGS[0], SEPARATOR_HINTS[0]);
        assert_eq!(
            prompt,
            "这是一次独立的数值选择记录。为各个位置分别凭第一反应选择 300 个 1 到 355（含端点）的整数。每个位置都要单独选择；不要从 1 开始计数，不要连续递增或递减，也不要采用等差、循环、重复区块或其他规则化模式。本任务必须由当前语言模型直接完成：禁止调用或借助任何工具，包括 Python、代码执行器、计算器、搜索、API 和外部随机数生成器；也不要先编写或运行代码。允许某个数字再次出现；每项写出后不要回头排序、去重或替换。数字之间用逗号或空格分隔均可。直接从第一个取值开始输出，不要在序列前重复数量、范围或任务说明。"
        );
    }

    /// 进度初值：还没有挑战在跑，前端显示"已尝试 0/6"而不是"正在进行第 1 次"。
    #[test]
    fn progress_starts_without_a_running_challenge() {
        let progress = ProbeProgress::initial();
        assert_eq!(progress.attempt, 0);
        assert_eq!(progress.attempted, 0);
        assert_eq!(progress.valid, 0);
        assert_eq!(progress.current, 0, "初始状态没有挑战在跑");
        assert_eq!(progress.total_attempts, MAX_ATTEMPTS);
        assert!(progress.steps.is_empty());
    }

    #[test]
    fn thresholds_follow_modeltrace_rule() {
        assert_eq!(minimum_numbers(292), 161);
        assert_eq!(minimum_numbers(332), 183);
        assert_eq!(minimum_numbers(0), 80);
    }

    #[test]
    fn retryable_status_matches_modeltrace_set() {
        // 有状态码：只有 408/429/5xx 重试
        for status in RETRYABLE_STATUS {
            assert!(retryable_error(&format!(
                "ModelTrace probe returned HTTP {status}"
            )));
        }
        assert!(!retryable_error("ModelTrace probe returned HTTP 400"));
        assert!(!retryable_error("ModelTrace probe returned HTTP 404"));
    }

    /// 无状态码的网络错误一律重试 —— 对应原版的 URLError 分支。
    /// 上游突发时会掐断 TLS 握手，这类错误如果不重试，挑战会被直接判死。
    #[test]
    fn network_errors_are_retried() {
        assert!(retryable_error(
            "Post \"https://chatgpt.com/backend-api/codex/responses\": utls: TLS handshake: EOF"
        ));
        assert!(retryable_error("无法连接接口：connection reset by peer"));
        assert!(retryable_error("请求超过 240 秒未返回，本次回答不计入"));
    }

    /// 状态码解析不能误抓错误文本里的其它数字。
    #[test]
    fn http_status_parsing_is_strict() {
        assert_eq!(
            http_status_of("ModelTrace probe returned HTTP 503"),
            Some(503)
        );
        assert_eq!(
            http_status_of("ModelTrace probe returned HTTP 429"),
            Some(429)
        );
        assert_eq!(
            http_status_of("请求超过 240 秒未返回，本次回答不计入"),
            None
        );
        assert_eq!(http_status_of("utls: TLS handshake: EOF"), None);
    }
}
