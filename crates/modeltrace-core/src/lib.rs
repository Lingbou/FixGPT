//! Rust port of the ModelTrace numeric fingerprint scoring core.
//!
//! The implementation follows the scoring contract in ModelTrace's
//! `fingerprint-core.mjs` and uses the bundled `gpt_bank.json`. ModelTrace is
//! MIT-licensed; see `THIRD_PARTY_NOTICES.md` at the workspace root.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const VALUE_MIN: i64 = 1;
const VALUE_MAX: i64 = 355;
const DIMENSION: usize = (VALUE_MAX - VALUE_MIN + 1) as usize;
const ALPHA: f64 = 0.5;
const ORDERED_BLOCK_WEIGHT: f64 = 0.25;

#[derive(Debug, Error)]
pub enum ModelTraceError {
    #[error("fingerprint bank is unavailable: {0}")]
    Bank(String),
    #[error("no usable output: provide a complete numeric sequence")]
    NoUsableOutput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub text: String,
    pub expected_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub index: usize,
    pub parsed_numbers: usize,
    pub minimum_numbers: usize,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelResult {
    pub model: String,
    pub display_name: String,
    pub probability: f64,
    pub profile_similarity: f64,
    pub score: f64,
    pub family: String,
    pub family_name: String,
    pub conditional_probability: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis {
    pub prediction: String,
    pub prediction_name: String,
    pub probability: f64,
    pub used_outputs: usize,
    pub results: Vec<ModelResult>,
    pub diagnostics: Vec<Diagnostic>,
    pub calibration_queries: String,
    pub beta: f64,
    pub cv_accuracy: f64,
    pub family_prediction: String,
    pub family_prediction_name: String,
    pub family_probability: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SampleClassification {
    pub outcome: String,
    pub prediction: String,
    pub closed_set_weight: f64,
    pub expected_weight: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct BankFile {
    models: Vec<Model>,
    robust: Robust,
    calibration: HashMap<String, Calibration>,
}

#[derive(Debug, Deserialize)]
struct Model {
    id: String,
    display_name: String,
    family: Option<String>,
    family_name: Option<String>,
    counts: Vec<f64>,
}

#[derive(Debug, Deserialize)]
struct Robust {
    model_order: Vec<String>,
    hellinger: Artifact,
    ordered_blocks: OrderedArtifact,
}

#[derive(Debug, Deserialize)]
struct Calibration {
    beta: f64,
    cv_accuracy: f64,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    feature_mean: Vec<f64>,
    feature_scale: Vec<f64>,
    nuisance_basis: Vec<Vec<f64>>,
    centroids: Vec<Vec<f64>>,
}

#[derive(Debug, Deserialize)]
struct OrderedArtifact {
    weight: f64,
    feature_mean: Vec<f64>,
    feature_scale: Vec<f64>,
    nuisance_basis: Vec<Vec<f64>>,
    centroids: Vec<Vec<f64>>,
    environment_centroids: Vec<Vec<Vec<f64>>>,
}

static BANK: OnceLock<Result<BankFile, String>> = OnceLock::new();

fn bank() -> Result<&'static BankFile, ModelTraceError> {
    BANK.get_or_init(|| {
        serde_json::from_str(include_str!("../data/gpt_bank.json"))
            .map_err(|error| error.to_string())
    })
    .as_ref()
    .map_err(|error| ModelTraceError::Bank(error.clone()))
}

/// Return the GPT-only model identifiers embedded in the fingerprint bank.
pub fn supported_models() -> Vec<String> {
    bank()
        .map(|bank| bank.robust.model_order.clone())
        .unwrap_or_default()
}

/// Return whether the embedded fingerprint bank contains this model.
pub fn is_supported_model(model: &str) -> bool {
    bank().is_ok_and(|bank| {
        bank.robust
            .model_order
            .iter()
            .any(|candidate| candidate == model)
    })
}

/// Extract the longest digit run from a model response.
pub fn parse_numbers(text: &str) -> Vec<i64> {
    let bytes = text.as_bytes();
    let mut runs: Vec<Vec<i64>> = Vec::new();
    let mut current = Vec::new();
    let mut previous_end = 0_usize;
    let mut index = 0_usize;

    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }

        let separator = &text[previous_end..start];
        if !current.is_empty() && separator.chars().any(char::is_alphabetic) {
            runs.push(std::mem::take(&mut current));
        }

        if let Ok(value) = text[start..index].parse::<i64>()
            && (VALUE_MIN..=VALUE_MAX).contains(&value)
        {
            current.push(value);
        }
        previous_end = index;
    }

    if !current.is_empty() {
        runs.push(current);
    }

    runs.into_iter().max_by_key(Vec::len).unwrap_or_default()
}

pub fn analyze_outputs(outputs: &[Output]) -> Result<Analysis, ModelTraceError> {
    let bank = bank()?;
    let model_by_id: HashMap<&str, &Model> = bank
        .models
        .iter()
        .map(|model| (model.id.as_str(), model))
        .collect();

    let mut ordered_models = Vec::with_capacity(bank.robust.model_order.len());
    for id in &bank.robust.model_order {
        let model = model_by_id
            .get(id.as_str())
            .ok_or_else(|| ModelTraceError::Bank(format!("model {id} missing from bank")))?;
        ordered_models.push(*model);
    }

    let mut valid: Vec<(Vec<f64>, Vec<f64>)> = Vec::new();
    let mut diagnostics = Vec::with_capacity(outputs.len());

    for (index, output) in outputs.iter().enumerate() {
        let numbers = parse_numbers(&output.text);
        let minimum = if output.expected_count == 0 {
            80
        } else {
            ((output.expected_count as f64 * 0.55).ceil() as usize).max(80)
        };
        let accepted = numbers.len() >= minimum;
        diagnostics.push(Diagnostic {
            index,
            parsed_numbers: numbers.len(),
            minimum_numbers: minimum,
            accepted,
        });
        if !accepted {
            continue;
        }

        let counts = count_numbers(&numbers);
        let scores = robust_score_numbers(&numbers, counts.clone(), bank);
        valid.push((counts, scores));
    }

    if valid.is_empty() {
        return Err(ModelTraceError::NoUsableOutput);
    }

    let combined_scores: Vec<f64> = (0..ordered_models.len())
        .map(|model_index| {
            valid
                .iter()
                .map(|(_, scores)| scores[model_index])
                .sum::<f64>()
                / valid.len() as f64
        })
        .collect();

    let calibration_key = valid.len().min(3).to_string();
    let calibration = bank
        .calibration
        .get(&calibration_key)
        .ok_or_else(|| ModelTraceError::Bank(format!("calibration {calibration_key} missing")))?;
    let probabilities = softmax(
        combined_scores
            .iter()
            .map(|score| calibration.beta * score)
            .collect(),
    );

    let mut pooled_counts = vec![0.0; DIMENSION];
    for (counts, _) in &valid {
        for (target, value) in pooled_counts.iter_mut().zip(counts) {
            *target += value;
        }
    }

    let mut results: Vec<ModelResult> = ordered_models
        .iter()
        .enumerate()
        .map(|(index, model)| {
            let family = model.family.clone().unwrap_or_else(|| "models".to_owned());
            let family_name = model.family_name.clone().unwrap_or_else(|| family.clone());
            ModelResult {
                model: model.id.clone(),
                display_name: model.display_name.clone(),
                probability: probabilities[index],
                profile_similarity: js_similarity(&pooled_counts, &model.counts),
                score: combined_scores[index],
                family,
                family_name,
                conditional_probability: 0.0,
            }
        })
        .collect();
    results.sort_by(|left, right| {
        right
            .probability
            .partial_cmp(&left.probability)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut family_probabilities: HashMap<String, f64> = HashMap::new();
    for result in &results {
        *family_probabilities
            .entry(result.family.clone())
            .or_default() += result.probability;
    }
    for result in &mut results {
        if let Some(total) = family_probabilities.get(&result.family)
            && *total > 0.0
        {
            result.conditional_probability = result.probability / *total;
        }
    }

    if results.is_empty() {
        return Err(ModelTraceError::NoUsableOutput);
    }

    let winner = results[0].clone();
    let family_winner = family_probabilities
        .iter()
        .max_by(|left, right| {
            left.1
                .partial_cmp(right.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(family, probability)| (family.clone(), *probability))
        .unwrap_or_else(|| (winner.family.clone(), winner.probability));
    let family_name = results
        .iter()
        .find(|result| result.family == family_winner.0)
        .map(|result| result.family_name.clone())
        .unwrap_or_else(|| family_winner.0.clone());

    Ok(Analysis {
        prediction: winner.model.clone(),
        prediction_name: winner.display_name.clone(),
        probability: winner.probability,
        used_outputs: valid.len(),
        results,
        diagnostics,
        calibration_queries: calibration_key,
        beta: calibration.beta,
        cv_accuracy: calibration.cv_accuracy,
        family_prediction: family_winner.0,
        family_prediction_name: family_name,
        family_probability: family_winner.1,
    })
}

pub fn classify_sample(
    analysis: &Analysis,
    expected: Option<&str>,
    previous: &[SampleClassification],
) -> SampleClassification {
    let Some(expected) = expected.filter(|value| !value.is_empty()) else {
        return SampleClassification {
            outcome: "missing_expected_model".to_owned(),
            prediction: analysis.prediction.clone(),
            closed_set_weight: analysis.probability,
            expected_weight: None,
        };
    };

    let Some(candidate) = analysis
        .results
        .iter()
        .find(|result| result.model == expected)
    else {
        return SampleClassification {
            outcome: "unknown_expected_model".to_owned(),
            prediction: analysis.prediction.clone(),
            closed_set_weight: analysis.probability,
            expected_weight: None,
        };
    };
    let top = &analysis.results[0];
    let mut outcome = "inconclusive";
    if top.model == expected && top.probability >= 0.5 {
        outcome = "compatible";
    } else if top.model != expected
        && top.probability >= 0.8
        && candidate.probability <= 0.15
        && top.probability - candidate.probability >= 0.65
    {
        outcome = "difference_signal";
    }

    let matching_recent = previous
        .iter()
        .rev()
        .take(2)
        .filter(|sample| {
            sample.prediction == top.model
                && matches!(
                    sample.outcome.as_str(),
                    "difference_signal" | "repeated_difference"
                )
        })
        .count();
    if outcome == "difference_signal" && matching_recent >= 1 {
        outcome = "repeated_difference";
    }

    SampleClassification {
        outcome: outcome.to_owned(),
        prediction: top.model.clone(),
        closed_set_weight: top.probability,
        expected_weight: Some(candidate.probability),
    }
}

fn count_numbers(numbers: &[i64]) -> Vec<f64> {
    let mut counts = vec![0.0; DIMENSION];
    for value in numbers {
        if (VALUE_MIN..=VALUE_MAX).contains(value) {
            counts[(*value - VALUE_MIN) as usize] += 1.0;
        }
    }
    counts
}

fn robust_score_numbers(numbers: &[i64], counts: Vec<f64>, bank: &BankFile) -> Vec<f64> {
    let marginal = robust_score_counts(&counts, &bank.robust.hellinger);
    let ordered = ordered_block_scores(numbers, &bank.robust.ordered_blocks);
    let weight = if bank.robust.ordered_blocks.weight == 0.0 {
        ORDERED_BLOCK_WEIGHT
    } else {
        bank.robust.ordered_blocks.weight
    };
    marginal
        .iter()
        .zip(ordered)
        .map(|(left, right)| (1.0 - weight) * left + weight * right)
        .collect()
}

fn robust_score_counts(counts: &[f64], artifact: &Artifact) -> Vec<f64> {
    let feature = hellinger_feature(counts);
    let mut projected = feature
        .iter()
        .zip(artifact.feature_mean.iter().zip(&artifact.feature_scale))
        .map(|(value, (mean, scale))| (value - mean) / safe_scale(*scale))
        .collect::<Vec<_>>();
    subtract_basis(&mut projected, &artifact.nuisance_basis);
    let projected = normalized(&projected);
    let scores: Vec<f64> = artifact
        .centroids
        .iter()
        .map(|centroid| dot(&projected, centroid))
        .collect();
    standardize(&scores)
}

fn ordered_block_scores(numbers: &[i64], artifact: &OrderedArtifact) -> Vec<f64> {
    let feature = ordered_block_feature(numbers);
    let standardized = feature
        .iter()
        .zip(artifact.feature_mean.iter().zip(&artifact.feature_scale))
        .map(|(value, (mean, scale))| (value - mean) / safe_scale(*scale))
        .collect::<Vec<_>>();
    let unit = normalized(&standardized);
    let environment_scores: Vec<Vec<f64>> = artifact
        .environment_centroids
        .iter()
        .map(|centroids| {
            centroids
                .iter()
                .map(|centroid| dot(&unit, centroid))
                .collect()
        })
        .collect();
    let template = standardize(
        &(0..artifact.centroids.len())
            .map(|model_index| {
                environment_scores
                    .iter()
                    .map(|scores| scores.get(model_index).copied().unwrap_or_default())
                    .fold(f64::NEG_INFINITY, f64::max)
            })
            .collect::<Vec<_>>(),
    );
    let mut projected = standardized.clone();
    subtract_basis(&mut projected, &artifact.nuisance_basis);
    let projected = normalized(&projected);
    let nuisance = standardize(
        &artifact
            .centroids
            .iter()
            .map(|centroid| dot(&projected, centroid))
            .collect::<Vec<_>>(),
    );
    standardize(
        &template
            .iter()
            .zip(nuisance)
            .map(|(left, right)| 0.5 * left + 0.5 * right)
            .collect::<Vec<_>>(),
    )
}

fn hellinger_feature(counts: &[f64]) -> Vec<f64> {
    let total = counts.iter().sum::<f64>() + ALPHA * DIMENSION as f64;
    counts
        .iter()
        .map(|value| ((value + ALPHA) / total).sqrt())
        .collect()
}

fn ordered_block_feature(numbers: &[i64]) -> Vec<f64> {
    let mut pieces = Vec::with_capacity(74);
    let base = numbers.len() / 4;
    let remainder = numbers.len() % 4;
    let mut start = 0;
    for chunk_index in 0..4 {
        let size = base + usize::from(chunk_index < remainder);
        let chunk = &numbers[start..start + size];
        start += size;
        let mut bins = [0.5_f64; 16];
        for value in chunk {
            let index = (((value - VALUE_MIN) as f64 / VALUE_MAX as f64) * 16.0)
                .floor()
                .clamp(0.0, 15.0) as usize;
            bins[index] += 1.0;
        }
        let total = bins.iter().sum::<f64>();
        pieces.extend(bins.iter().map(|value| (value / total).sqrt()));
    }

    let mut digits = [0.5_f64; 10];
    for value in numbers {
        digits[(value % 10) as usize] += 1.0;
    }
    let total = digits.iter().sum::<f64>();
    pieces.extend(digits.iter().map(|value| (value / total).sqrt()));
    pieces
}

fn js_similarity(left: &[f64], right: &[f64]) -> f64 {
    let left_total = left.iter().sum::<f64>();
    if left_total <= 0.0 {
        return 0.0;
    }
    let right_total = right.iter().sum::<f64>() + ALPHA * DIMENSION as f64;
    let p: Vec<f64> = left.iter().map(|value| value / left_total).collect();
    let q: Vec<f64> = right
        .iter()
        .map(|value| (value + ALPHA) / right_total)
        .collect();
    let midpoint: Vec<f64> = p
        .iter()
        .zip(&q)
        .map(|(left, right)| (left + right) / 2.0)
        .collect();
    let divergence = |values: &[f64]| {
        values
            .iter()
            .zip(&midpoint)
            .filter(|(value, _)| **value > 0.0)
            .map(|(value, middle)| value * (value / middle).ln())
            .sum::<f64>()
    };
    let js = (divergence(&p) + divergence(&q)) / 2.0;
    1.0 - (js / 2.0_f64.ln()).max(0.0).sqrt()
}

fn softmax(values: Vec<f64>) -> Vec<f64> {
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let weights: Vec<f64> = values.iter().map(|value| (value - max).exp()).collect();
    let total = weights.iter().sum::<f64>();
    weights.into_iter().map(|value| value / total).collect()
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn standardize(values: &[f64]) -> Vec<f64> {
    if values.is_empty() {
        return Vec::new();
    }
    let center = mean(values);
    let variance = values
        .iter()
        .map(|value| (value - center).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    let scale = variance.sqrt().max(1e-12);
    values
        .iter()
        .map(|value| (value - center) / scale)
        .collect()
}

fn normalized(values: &[f64]) -> Vec<f64> {
    let scale = dot(values, values).sqrt().max(1e-12);
    values.iter().map(|value| value / scale).collect()
}

fn subtract_basis(values: &mut [f64], basis: &[Vec<f64>]) {
    for vector in basis {
        let projection = dot(values, vector);
        for (value, basis_value) in values.iter_mut().zip(vector) {
            *value -= projection * basis_value;
        }
    }
}

fn dot(left: &[f64], right: &[f64]) -> f64 {
    left.iter()
        .zip(right)
        .map(|(left, right)| left * right)
        .sum()
}

fn safe_scale(value: f64) -> f64 {
    if value.abs() < 1e-12 { 1e-12 } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_uses_longest_digit_run() {
        assert_eq!(
            parse_numbers("101, 102 and 103 104 105"),
            vec![103, 104, 105]
        );
        assert_eq!(parse_numbers("1 2 3 x 9 10 11 12"), vec![9, 10, 11, 12]);
    }

    #[test]
    fn analysis_returns_probability_distribution() {
        let output = Output {
            text: (1..=355)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            expected_count: 355,
        };
        let analysis = analyze_outputs(&[output]).expect("analysis");
        let total = analysis
            .results
            .iter()
            .map(|result| result.probability)
            .sum::<f64>();
        assert!((total - 1.0).abs() < 1e-9);
        assert!(analysis.results.len() >= 6);
    }

    #[test]
    fn embedded_bank_is_gpt_only() {
        let models = supported_models();
        assert!(!models.is_empty());
        assert!(models.iter().all(|model| model.starts_with("gpt-")));
        assert!(is_supported_model("gpt-6-astra"));
        assert!(!is_supported_model("claude-sonnet-5"));
    }

    #[test]
    fn short_output_is_rejected() {
        let output = Output {
            text: "1 2 3".to_owned(),
            expected_count: 100,
        };
        assert!(matches!(
            analyze_outputs(&[output]),
            Err(ModelTraceError::NoUsableOutput)
        ));
    }
}
