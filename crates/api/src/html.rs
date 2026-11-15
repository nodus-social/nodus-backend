//! Inbound HTML sanitisation and plain-text escaping.
//!
//! Matches the allowlist in `docs/02-api-compat.md`:
//! allow `p`, `br`, `a[href,rel,class]`, `span[class]`, `strong`, `em`, `del`,
//! `code`, `pre`, `blockquote`; unwrap unknown tags so no text is lost (while
//! dropping `script`/`style` bodies); force `rel="nofollow noopener noreferrer"`
//! and `target="_blank"` on links.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use ammonia::Builder;

static SANITIZER: LazyLock<Builder<'static>> = LazyLock::new(|| {
    let tags = HashSet::from([
        "p",
        "br",
        "a",
        "span",
        "strong",
        "em",
        "del",
        "code",
        "pre",
        "blockquote",
    ]);
    let clean_content_tags = HashSet::from(["script", "style"]);
    let tag_attributes = HashMap::from([
        ("a", HashSet::from(["href", "class"])),
        ("span", HashSet::from(["class"])),
    ]);
    let url_schemes = HashSet::from(["http", "https", "mailto"]);

    let mut builder = Builder::empty();
    builder
        .tags(tags)
        .clean_content_tags(clean_content_tags)
        .generic_attributes(HashSet::new())
        .tag_attributes(tag_attributes)
        .url_schemes(url_schemes)
        .link_rel(Some("nofollow noopener noreferrer"))
        .set_tag_attribute_value("a", "target", "_blank");
    builder
});

/// Sanitises untrusted HTML on write using the strict Mastodon-compatible allowlist.
pub(crate) fn sanitize_html(raw: &str) -> String {
    SANITIZER.clean(raw).to_string()
}

/// Escapes HTML special characters in plain-text fields so they are safe in any renderer.
pub(crate) fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_documented_tags_and_rewrites_links() {
        let input = r#"<p>Hello <span class="h-card"><a class="u-url mention" href="https://social.test/@alice" target="_self" rel="opener">@alice</a></span> <a class="mention hashtag" href="https://social.test/tags/rust">#rust</a><br><strong>b</strong><em>i</em><del>d</del><code>c</code></p><pre>code</pre><blockquote>q</blockquote>"#;
        let out = sanitize_html(input);
        assert!(out.contains(r#"<span class="h-card">"#), "out: {out}");
        assert!(
            out.contains(r#"<a class="u-url mention" href="https://social.test/@alice" target="_blank" rel="nofollow noopener noreferrer">@alice</a>"#),
            "out: {out}"
        );
        assert!(
            out.contains(r#"<a class="mention hashtag" href="https://social.test/tags/rust" target="_blank" rel="nofollow noopener noreferrer">#rust</a>"#),
            "out: {out}"
        );
        assert!(out.contains("<br>"));
        assert!(out.contains("<strong>b</strong>"));
        assert!(out.contains("<em>i</em>"));
        assert!(out.contains("<del>d</del>"));
        assert!(out.contains("<code>c</code>"));
        assert!(out.contains("<pre>code</pre>"));
        assert!(out.contains("<blockquote>q</blockquote>"));
    }

    #[test]
    fn strips_scripts_event_handlers_and_javascript_urls() {
        let input = concat!(
            r#"<p onclick="alert(1)" style="color:red">Safe</p>"#,
            r#"<script>alert('xss')</script>"#,
            r#"<style>body{display:none}</style>"#,
            r#"<img src="x" onerror="alert(2)">"#,
            r#"<a href="javascript:alert(3)">js</a>"#,
            r#"<a href="data:text/html,<script>alert(4)</script>">data</a>"#,
            r#"<span class="ok" id="bad" onmouseover="evil()">hi</span>"#,
        );
        let out = sanitize_html(input);
        assert!(!out.contains("<script"));
        assert!(!out.contains("alert('xss')"));
        assert!(!out.contains("<style"));
        assert!(!out.contains("display:none"));
        assert!(!out.contains("<img"));
        assert!(!out.contains("onerror"));
        assert!(!out.contains("onclick"));
        assert!(!out.contains("onmouseover"));
        assert!(!out.contains("style="));
        assert!(!out.contains("id="));
        assert!(!out.contains("javascript:"));
        assert!(!out.contains("data:"));
        assert!(out.contains("<p>Safe</p>"), "out: {out}");
        assert!(out.contains(r#"<span class="ok">hi</span>"#), "out: {out}");
    }

    #[test]
    fn unwraps_unknown_tags_without_losing_text() {
        let out = sanitize_html("<div><h1>Title</h1><svg onload=alert(1)>keep me</svg></div>");
        assert!(!out.contains("<div"));
        assert!(!out.contains("<h1"));
        assert!(!out.contains("<svg"));
        assert!(!out.contains("onload"));
        assert_eq!(out, "Titlekeep me");
    }

    #[test]
    fn escapes_plain_text_fields() {
        assert_eq!(
            escape_text(r#"<script>alert("1")</script> & 'bob'"#),
            "&lt;script&gt;alert(&quot;1&quot;)&lt;/script&gt; &amp; &#39;bob&#39;"
        );
    }
}
