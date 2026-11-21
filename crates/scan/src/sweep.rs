//! The scanner sweep.
//!
//! A scanner is another process, often someone else's model, and it only ever answers
//! "these labels, with these confidences". This loop is the one place that turns those
//! answers into something that happened to a post: a review item, a sensitive flag, or a
//! deletion. It runs as its own service because the scanner registry lives in the database
//! it already talks to and a verdict is only useful once it is applied, so a slow model must
//! not be able to slow a request down.
//!
//! Two passes per tick. Discovery queues work that was never queued — content posted while
//! a scanner was unreachable, or before one was configured — so nothing is permanently
//! missed. Execution leases a batch and asks each scanner in turn.

use std::time::{Duration, Instant};

use crate::{Request, Severity, Signal, Transport};
use nodus_server_store::scanners::{self, RuleRow, ScanRow, ScannerRow};
use nodus_server_store::{statuses, Store};

/// How long the sweep sleeps between passes. Content scanning is not latency critical, and
/// a longer tick keeps a burst of media from turning into a burst of outbound requests.
const TICK: Duration = Duration::from_secs(5);

/// Scans in flight per tick, per sweep.
const BATCH: i64 = 8;

/// Subjects queued per kind per tick.
const DISCOVERY: i64 = 32;

/// How long a leased scan belongs to this sweep before another may take it. Generous: a
/// cold model load can take a while, and a duplicate scan costs more than a late one.
const LEASE_SECONDS: i64 = 120;

/// The most text sent to a text scanner. A post longer than this is a post whose tail is
/// not worth the round trip, and every scanner would truncate it anyway.
const MAX_TEXT: usize = 8 * 1024;

/// Starts the sweep on the current runtime. It never returns; a failed pass is logged and
/// retried on the next tick, because one unreachable scanner must not stop the others.
///
/// `wake` is the on-demand path: a caller that wants a pass now notifies it instead of
/// waiting out the tick.
pub fn spawn(store: Store, base_url: String, wake: std::sync::Arc<tokio::sync::Notify>) {
    tokio::spawn(async move {
        let transport = match Transport::new() {
            Ok(transport) => transport,
            Err(error) => {
                tracing::error!(%error, "scanner sweep cannot start");
                return;
            }
        };
        let mut ticker = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                () = wake.notified() => {}
            }
            if let Err(error) = once(&store, &base_url, &transport).await {
                tracing::error!(%error, "scanner sweep failed");
            }
        }
    });
}

async fn once(store: &Store, base_url: &str, transport: &Transport) -> Result<(), sqlx::Error> {
    discover(store, base_url).await?;
    for scan in scanners::claim(store.pool(), BATCH, LEASE_SECONDS).await? {
        examine(store, transport, &scan).await;
    }
    Ok(())
}

async fn discover(store: &Store, base_url: &str) -> Result<(), sqlx::Error> {
    let pool = store.pool();
    for (id, content, spoiler_text) in scanners::unqueued_statuses(pool, "text", DISCOVERY).await? {
        let text = plain(&content, &spoiler_text);
        if text.is_empty() {
            continue;
        }
        scanners::enqueue_for(pool, "text", "status", &id, None, Some(&text), None).await?;
    }
    for kind in ["image", "video"] {
        for (id, content_type) in scanners::unqueued_media(pool, kind, DISCOVERY).await? {
            let url = media_url(base_url, &id);
            scanners::enqueue_for(
                pool,
                kind,
                "media",
                &id,
                Some(&url),
                None,
                Some(&content_type),
            )
            .await?;
        }
    }
    Ok(())
}

async fn examine(store: &Store, transport: &Transport, scan: &ScanRow) {
    let pool = store.pool();
    let scanner = match scanners::scanner(pool, &scan.scanner_id).await {
        Ok(Some(scanner)) => scanner,
        Ok(None) => {
            report(store, &scan.id, "this scanner no longer exists").await;
            return;
        }
        Err(error) => {
            report(store, &scan.id, &error.to_string()).await;
            return;
        }
    };

    let started = Instant::now();
    let answer = transport
        .ask(
            &scanner.endpoint,
            scanner.secret.as_deref(),
            timeout(&scanner),
            &request(scan),
        )
        .await;
    let elapsed = started.elapsed();
    let response = match answer {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                scanner = %scanner.name,
                subject = %scan.subject_id,
                elapsed_ms = elapsed.as_millis(),
                %error,
                "scanner did not answer"
            );
            report(store, &scan.id, &error.to_string()).await;
            return;
        }
    };

    let rules = match scanners::rules(pool, &scanner.id).await {
        Ok(rules) => rules,
        Err(error) => {
            report(store, &scan.id, &error.to_string()).await;
            return;
        }
    };
    let verdict = verdict(&rules, &response.labels);
    tracing::debug!(
        scanner = %scanner.name,
        subject = %scan.subject_id,
        severity = verdict.severity.as_str(),
        labels = ?verdict.labels,
        elapsed_ms = elapsed.as_millis(),
        "scanner answered"
    );

    if let Err(error) = scanners::finish(
        pool,
        &scan.id,
        verdict.score,
        &verdict.labels,
        &response.detail,
    )
    .await
    {
        tracing::error!(scan = %scan.id, %error, "could not record a scan result");
        return;
    }
    if verdict.severity == Severity::Ignore {
        return;
    }
    if let Err(error) = act(store, scan, &verdict).await {
        tracing::error!(scan = %scan.id, %error, "could not apply a scan result");
    }
}

/// What the instance decided about one answer.
struct Verdict {
    severity: Severity,
    labels: Vec<String>,
    score: Option<f32>,
}

/// Rules are the instance's, not the scanner's: a label nobody wrote a rule for is a label
/// this instance does not care about, whatever the scanner thought of it.
fn verdict(rules: &[RuleRow], signals: &[Signal]) -> Verdict {
    let mut severity = Severity::Ignore;
    let mut labels = Vec::new();
    let mut score: Option<f32> = None;
    for signal in signals {
        let name = signal.name();
        let Some(rule) = rules
            .iter()
            .find(|rule| rule.label.eq_ignore_ascii_case(name))
        else {
            continue;
        };
        let confidence = signal.score();
        if f64::from(confidence) < rule.threshold {
            continue;
        }
        severity = severity.or(Severity::parse(&rule.severity));
        labels.push(format!("{name} ({confidence:.2})"));
        score = Some(score.map_or(confidence, |best: f32| best.max(confidence)));
    }
    Verdict {
        severity,
        labels,
        score,
    }
}

/// Applies the decided severity to the content, then queues the decision for a moderator.
///
/// Nothing is removed silently: every severity above `ignore` leaves a flag, so the author
/// of a deletion can always be shown what the scanner saw.
async fn act(store: &Store, scan: &ScanRow, verdict: &Verdict) -> Result<(), sqlx::Error> {
    let pool = store.pool();
    let Some(subject) = scanners::subject(pool, &scan.subject_type, &scan.subject_id).await? else {
        return Ok(());
    };
    let Some(status_id) = subject.status_id.as_deref() else {
        return Ok(());
    };
    let mut record = scan.clone();
    record.score = verdict.score;
    record.labels = verdict.labels.clone();
    match verdict.severity {
        Severity::Ignore => return Ok(()),
        Severity::Sensitive => {
            statuses::mark_sensitive(pool, status_id).await?;
        }
        Severity::Block => {
            if let Some(account_id) = subject.account_id.as_deref() {
                statuses::delete_owned(pool, status_id, account_id).await?;
            }
        }
        Severity::Flag => {}
    }
    let reason = if verdict.labels.is_empty() {
        "a scanner asked for a review".to_owned()
    } else {
        verdict.labels.join(", ")
    };
    scanners::raise_flag(
        pool,
        &record,
        Some(status_id),
        subject.account_id.as_deref(),
        &reason,
        verdict.severity.as_str(),
    )
    .await?;
    Ok(())
}

async fn report(store: &Store, scan_id: &str, error: &str) {
    if let Err(failure) = scanners::fail(store.pool(), scan_id, error).await {
        tracing::error!(scan = %scan_id, %failure, "could not record a scan failure");
    }
}

fn request(scan: &ScanRow) -> Request<'_> {
    let mut request = Request::new(&scan.id, &scan.kind);
    if let Some(url) = scan.url.as_deref() {
        request = request.url(url);
    }
    if let Some(text) = scan.text.as_deref() {
        request = request.text(text);
    }
    if let Some(mime) = scan.mime.as_deref() {
        request = request.mime(mime);
    }
    request
}

fn timeout(scanner: &ScannerRow) -> Duration {
    Duration::from_millis(
        u64::try_from(scanner.timeout_ms)
            .unwrap_or(5000)
            .clamp(100, 60_000),
    )
}

fn media_url(base_url: &str, id: &str) -> String {
    format!("{}/media/{id}", base_url.trim_end_matches('/'))
}

/// The text a text scanner should see: no markup, and the content warning, which is often
/// the only place the author named what the post is about.
fn plain(content: &str, spoiler_text: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in content.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    let body = out.split_whitespace().collect::<Vec<_>>().join(" ");
    let warning = spoiler_text.trim();
    let joined = match (warning.is_empty(), body.is_empty()) {
        (true, _) => body,
        (false, true) => warning.to_owned(),
        (false, false) => format!("{warning}\n{body}"),
    };
    joined.chars().take(MAX_TEXT).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(label: &str, threshold: f64, severity: &str) -> RuleRow {
        RuleRow {
            id: format!("rule-{label}"),
            scanner_id: "scanner".to_owned(),
            label: label.to_owned(),
            threshold,
            severity: severity.to_owned(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn a_label_without_a_rule_is_ignored() {
        let verdict = verdict(&[], &[Signal::Bare("nsfw".to_owned())]);
        assert_eq!(verdict.severity, Severity::Ignore);
        assert!(verdict.labels.is_empty(), "an unruled label names nothing");
    }

    #[test]
    fn a_label_below_its_threshold_is_ignored() {
        let rules = vec![rule("nsfw", 0.8, "sensitive")];
        let verdict = verdict(
            &rules,
            &[Signal::Scored {
                name: "nsfw".to_owned(),
                score: 0.5,
            }],
        );
        assert_eq!(verdict.severity, Severity::Ignore);
    }

    #[test]
    fn the_strictest_matching_rule_wins() {
        let rules = vec![rule("nsfw", 0.5, "sensitive"), rule("csam", 0.9, "block")];
        let verdict = verdict(
            &rules,
            &[
                Signal::Scored {
                    name: "nsfw".to_owned(),
                    score: 0.95,
                },
                Signal::Bare("csam".to_owned()),
            ],
        );
        assert_eq!(verdict.severity, Severity::Block);
        assert_eq!(verdict.labels.len(), 2);
        assert_eq!(verdict.score, Some(1.0));
    }

    #[test]
    fn labels_match_regardless_of_case() {
        let rules = vec![rule("NSFW", 0.2, "flag")];
        let verdict = verdict(&rules, &[Signal::Bare("nsfw".to_owned())]);
        assert_eq!(verdict.severity, Severity::Flag);
    }

    #[test]
    fn plain_text_keeps_the_warning_and_drops_markup() {
        let text = plain("<p>a <b>bold</b> \n claim</p>", "cw");
        assert_eq!(text, "cw\na bold claim");
    }

    #[test]
    fn plain_text_without_a_warning_is_just_the_body() {
        assert_eq!(plain("<p>hi</p>", ""), "hi");
    }
}
