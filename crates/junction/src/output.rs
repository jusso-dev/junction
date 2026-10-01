use serde_json::Value;
use std::collections::BTreeSet;

/// Tab-separated human-readable rows. JSON cells escape control characters and preserve types.
pub fn table(value: &Value) -> String {
    let array = value.as_array().or_else(|| {
        let object = value.as_object()?;
        if object.len() == 1 {
            object.values().next()?.as_array()
        } else {
            None
        }
    });
    if let Some(rows) = array {
        if rows.is_empty() {
            return "(no rows)".into();
        }
        if rows.iter().all(Value::is_object) {
            let columns: BTreeSet<_> = rows
                .iter()
                .flat_map(|row| row.as_object().unwrap().keys())
                .collect();
            let mut lines = vec![
                columns
                    .iter()
                    .map(|column| cell(&Value::String((*column).clone())))
                    .collect::<Vec<_>>()
                    .join("\t"),
            ];
            for row in rows {
                lines.push(
                    columns
                        .iter()
                        .map(|column| row.get(*column).map(cell).unwrap_or_else(|| "-".into()))
                        .collect::<Vec<_>>()
                        .join("\t"),
                );
            }
            return lines.join("\n");
        }
        return std::iter::once("INDEX\tVALUE".to_owned())
            .chain(
                rows.iter()
                    .enumerate()
                    .map(|(index, value)| format!("{index}\t{}", cell(value))),
            )
            .collect::<Vec<_>>()
            .join("\n");
    }
    let mut lines = vec!["FIELD\tVALUE".to_owned()];
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            lines.push(format!(
                "{}\t{}",
                cell(&Value::String(key.clone())),
                cell(value)
            ));
        }
    } else {
        lines.push(format!("value\t{}", cell(value)));
    }
    lines.join("\n")
}
fn cell(value: &Value) -> String {
    serde_json::to_string(value).expect("JSON values serialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn heterogeneous_rows_preserve_missing_null_nested_and_escape_control_characters() {
        let rendered = table(
            &json!({"matches":[{"a":null,"b":"line\n\u{1b}[31m","nested":{"x":1}},{"b":false}]}),
        );
        assert!(rendered.starts_with("\"a\"\t\"b\"\t\"nested\"\n"));
        assert!(rendered.contains("null\t\"line\\n\\u001b[31m\"\t{\"x\":1}"));
        assert!(rendered.ends_with("-\tfalse\t-"));
        assert!(!rendered.contains('\u{1b}'));
        assert_eq!(table(&json!({"items":[]})), "(no rows)");
    }
}
