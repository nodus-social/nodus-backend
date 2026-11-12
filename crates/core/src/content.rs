//! How a status body is authored.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The source language of a status body.
///
/// `content_html` remains the canonical wire representation. The source and this
/// value exist so an editor can round-trip rich text and so a renderer knows how to
/// treat the source without guessing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentFormat {
    /// The source is already sanitised HTML.
    #[default]
    Html,
    /// Misskey Flavored Markdown.
    Mfm,
    /// CommonMark.
    Markdown,
}

impl ContentFormat {
    /// The database and wire value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Mfm => "mfm",
            Self::Markdown => "markdown",
        }
    }
}

impl fmt::Display for ContentFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A stored format value is not one this server understands.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("content format must be one of html, mfm, markdown")]
pub struct UnknownContentFormat;

impl FromStr for ContentFormat {
    type Err = UnknownContentFormat;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "html" => Ok(Self::Html),
            "mfm" => Ok(Self::Mfm),
            "markdown" => Ok(Self::Markdown),
            _ => Err(UnknownContentFormat),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_round_trips_through_its_wire_value() {
        for format in [
            ContentFormat::Html,
            ContentFormat::Mfm,
            ContentFormat::Markdown,
        ] {
            assert_eq!(format.as_str().parse::<ContentFormat>(), Ok(format));
        }
    }

    #[test]
    fn unknown_formats_are_rejected() {
        assert!("textile".parse::<ContentFormat>().is_err());
    }
}
