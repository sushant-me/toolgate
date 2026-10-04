//! toolgate — audit an MCP server's tool declarations before an agent connects.
//!
//! Three checks, each for a defect that has been found in the wild:
//!
//!   1. CONFUSABLE NAMES   two tools whose names normalise to the same string, so a
//!                         policy written against one silently matches the other.
//!   2. HIDDEN TEXT        instructions smuggled into a description using Unicode tag
//!                         characters or zero-width characters — invisible when read,
//!                         present in the model's context.
//!   3. UNMARKED RISK      a tool whose name or description says it is destructive,
//!                         with no `annotations.readOnlyHint` saying otherwise.
//!
//! Exit codes: 0 clean, 1 findings, 2 usage/input error. Fail-closed: an input it
//! cannot parse is exit 2, never "clean".

use std::process::ExitCode;

// ---------------------------------------------------------------- confusables

/// Fold a tool name to a comparable skeleton: lowercase, strip `_`/`-`, and map the
/// Cyrillic and Greek letters that are visually identical to Latin ones.
fn skeleton(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .map(|c| match c {
            // Cyrillic look-alikes
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c',
            'у' => 'y', 'х' => 'x', 'і' => 'i', 'ѕ' => 's', 'ј' => 'j',
            'ь' => 'b', 'н' => 'h', 'к' => 'k', 'м' => 'm', 'т' => 't',
            // Greek look-alikes
            'ο' => 'o', 'α' => 'a', 'ρ' => 'p', 'ν' => 'v', 'κ' => 'k',
            'τ' => 't', 'υ' => 'u', 'χ' => 'x', 'ι' => 'i',
            other => other,
        })
        .collect()
}


/// True when the name contains a character from a script that disguises a Latin letter.
fn has_lookalike(name: &str) -> bool {
    name.chars().any(|c| {
        let u = c as u32;
        // Cyrillic block and Greek block letters that render like Latin
        (0x0400..=0x04FF).contains(&u) || (0x0370..=0x03FF).contains(&u)
    })
}

// ------------------------------------------------------------- hidden text

/// Characters that are invisible or near-invisible in a rendered description.
fn is_hidden(c: char) -> bool {
    let u = c as u32;
    u == 0x200B            // zero-width space
        || u == 0x200C      // zero-width non-joiner
        || u == 0x200D      // zero-width joiner
        || u == 0xFEFF      // zero-width no-break space / BOM
        || u == 0x2060      // word joiner
        || (0xE0000..=0xE007F).contains(&u)   // Unicode tag block (the classic smuggle)
        || (0x2061..=0x2064).contains(&u)     // invisible operators
}

// ------------------------------------------------------------------ checks

#[derive(Debug, PartialEq)]
enum Severity { Critical, High, Medium }

#[derive(Debug)]
struct Finding {
    severity: Severity,
    tool: String,
    what: String,
}

/// Words that indicate a tool can change or destroy state.
const DESTRUCTIVE: &[&str] = &[
    "delete", "remove", "drop", "destroy", "purge", "truncate", "wipe",
    "write", "create", "update", "modify", "insert", "exec", "run", "shell",
    "send", "transfer", "pay", "charge", "move", "rename", "kill", "reset",
];

fn audit(tools: &[serde_json::Value]) -> Vec<Finding> {
    let mut out = Vec::new();

    // 1. confusable names
    let mut seen: Vec<(String, String)> = Vec::new();
    for t in tools {
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let sk = skeleton(name);
        for (other_sk, other_name) in &seen {
            if *other_sk == sk && other_name != name {
                // A Cyrillic/Greek look-alike is an attack. Two ordinary spellings of the same
                // name ("readFile" / "read_file") are a real ambiguity but not a disguise - and
                // calling both Critical would make the tool useless on any normal codebase.
                let disguised = has_lookalike(name) || has_lookalike(other_name);
                out.push(Finding {
                    severity: if disguised { Severity::Critical } else { Severity::Medium },
                    tool: name.to_string(),
                    what: format!(
                        "name is confusable with {:?}: both normalise to {:?} — a policy \
                         written against one will match the other{}",
                        other_name,
                        sk,
                        if disguised { "" } else { " (naming style, not a look-alike)" }
                    ),
                });
            }
        }
        seen.push((sk, name.to_string()));
    }

    for t in tools {
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("(unnamed)");
        let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("");

        // 2. hidden characters in name or description
        for (field, text) in [("name", name), ("description", desc)] {
            let hidden: Vec<char> = text.chars().filter(|c| is_hidden(*c)).collect();
            if !hidden.is_empty() {
                let codes: Vec<String> =
                    hidden.iter().take(4).map(|c| format!("U+{:04X}", *c as u32)).collect();
                out.push(Finding {
                    severity: Severity::Critical,
                    tool: name.to_string(),
                    what: format!(
                        "{} invisible or tag character(s) in the {} ({}{}) — text a reader \
                         cannot see is still in the model's context",
                        hidden.len(),
                        field,
                        codes.join(" "),
                        if hidden.len() > 4 { " …" } else { "" }
                    ),
                });
            }
        }

        // 3. destructive-sounding tool with no readOnlyHint
        let lower = format!("{} {}", name.to_lowercase(), desc.to_lowercase());
        let risky: Vec<&str> = DESTRUCTIVE.iter().copied().filter(|w| lower.contains(w)).collect();
        let has_hint = t
            .get("annotations")
            .and_then(|a| a.get("readOnlyHint"))
            .and_then(|v| v.as_bool());
        if !risky.is_empty() && has_hint.is_none() {
            out.push(Finding {
                severity: Severity::High,
                tool: name.to_string(),
                what: format!(
                    "name or description implies a state change ({}) with no \
                     annotations.readOnlyHint — a caller cannot tell read from write",
                    risky.join(", ")
                ),
            });
        }
    }
    out
}

// -------------------------------------------------------------------- main

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("usage: toolgate <tools.json>   (an MCP tools/list result)");
        return ExitCode::SUCCESS;
    }
    let path = match args.first() {
        Some(p) => p.clone(),
        None => {
            eprintln!("usage: toolgate <tools.json>");
            return ExitCode::from(2);
        }
    };
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot parse {path} as JSON: {e}");
            return ExitCode::from(2);
        }
    };
    // accept either {"tools":[...]} or a bare array
    let tools = match doc.get("tools").and_then(|t| t.as_array()) {
        Some(t) => t.clone(),
        None => match doc.as_array() {
            Some(t) => t.clone(),
            None => {
                eprintln!("{path}: no \"tools\" array found");
                return ExitCode::from(2);
            }
        },
    };

    let findings = audit(&tools);
    println!("toolgate — {} tool declaration(s) read from {path}", tools.len());
    if findings.is_empty() {
        println!("  no findings.\n  This says nothing about behaviour at runtime — only that");
        println!("  these declarations contain no confusable name, no hidden character,");
        println!("  and no unmarked state change.");
        return ExitCode::SUCCESS;
    }
    for f in &findings {
        println!("  {:?}\t{}\n\t{}", f.severity, f.tool, f.what);
    }
    println!("\n  {} finding(s).", findings.len());
    ExitCode::from(1)
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cyrillic_lookalike_is_caught() {
        // "read_file" and "reаd_file" with a Cyrillic 'а'
        let tools = vec![
            json!({"name": "read_file", "description": "read a file"}),
            json!({"name": "re\u{0430}d_file", "description": "read a file"}),
        ];
        let f = audit(&tools);
        assert_eq!(f.len(), 1, "expected exactly the confusable finding: {f:?}");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].what.contains("confusable"));
    }

    #[test]
    fn naming_style_is_medium_not_critical() {
        // Both normalise to "readfile", which is a genuine ambiguity - but nothing here is
        // disguised, so it must never be Critical or the tool cries wolf on normal code.
        let tools = vec![
            json!({"name": "readFile", "description": "x", "annotations": {"readOnlyHint": true}}),
            json!({"name": "read_file", "description": "x", "annotations": {"readOnlyHint": true}}),
        ];
        let f = audit(&tools);
        assert_eq!(f.len(), 1, "exactly the ambiguity: {f:?}");
        assert_eq!(f[0].severity, Severity::Medium, "not an attack: {f:?}");
        assert!(!has_lookalike("readFile"));
        assert!(has_lookalike("re\u{0430}d_file"));
    }

    #[test]
    fn ordinary_distinct_names_stay_silent() {
        let tools = vec![
            json!({"name": "read_file", "description": "x", "annotations": {"readOnlyHint": true}}),
            json!({"name": "write_file", "description": "x", "annotations": {"readOnlyHint": true}}),
        ];
        assert!(audit(&tools).is_empty(), "distinct names must not fire");
    }

    #[test]
    fn tag_characters_are_hidden_text() {
        // U+E0041 is a TAG LATIN CAPITAL LETTER A - invisible, present in context
        let tools = vec![json!({
            "name": "summarise",
            "description": "summarise a page\u{E0041}\u{E0042}"
        })];
        let f = audit(&tools);
        assert!(f.iter().any(|x| x.what.contains("invisible")), "got {f:?}");
    }

    #[test]
    fn read_only_hint_clears_a_destructive_name() {
        let bare = vec![json!({"name": "delete_record", "description": "delete it"})];
        assert!(audit(&bare).iter().any(|f| f.severity == Severity::High));
        let marked = vec![json!({
            "name": "delete_record",
            "description": "delete it",
            "annotations": {"readOnlyHint": true}
        })];
        assert!(!audit(&marked).iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn skeleton_folds_lookalikes() {
        assert_eq!(skeleton("re\u{0430}d_file"), skeleton("read_file"));
        assert_eq!(skeleton("READ-FILE"), skeleton("read_file"));
        assert_ne!(skeleton("read_file"), skeleton("write_file"));
    }
}
