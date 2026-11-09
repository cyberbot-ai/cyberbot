//! Bounded YAML/JSON data, with no constructors, tag handlers or alias expansion.
use serde_json::{Map, Value};
use yaml_rust2::{
    parser::{Event, Parser},
    scanner::TScalarStyle,
};

enum Frame {
    Map(Map<String, Value>, Option<String>),
    List(Vec<Value>),
}

fn push(stack: &mut [Frame], root: &mut Option<Value>, value: Value) -> Result<(), String> {
    match stack.last_mut() {
        Some(Frame::List(list)) => list.push(value),
        Some(Frame::Map(map, pending)) => {
            if let Some(key) = pending.take() {
                if map.insert(key, value).is_some() {
                    return Err("Repetitive key in inventory".into());
                }
            } else {
                let key = value
                    .as_str()
                    .ok_or("The inventory key should be a string")?;
                if key == "<<" {
                    return Err("YAML merge is not supported: state the meanings clearly".into());
                }
                *pending = Some(key.into());
            }
        }
        None if root.is_none() => *root = Some(value),
        None => return Err("One inventory document is expected".into()),
    }
    Ok(())
}

pub(super) fn parse(input: &str) -> Result<Value, String> {
    let mut parser = Parser::new_from_str(input);
    let mut stack = Vec::new();
    let mut root = None;
    let mut documents = 0;
    let mut nodes = 0;
    loop {
        let (event, _) = parser.next_token().map_err(|e| {
            // Never echo source lines, variable values or secrets in diagnostics.
            format!(
                "Incorrect YAML/JSON: line {}, column {}",
                e.marker().line(),
                e.marker().col()
            )
        })?;
        nodes += 1;
        if nodes > 100_000 {
            return Err("Too many elements of inventory (limit of 100,000)".into());
        }
        match event {
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err("One inventory document is expected".into());
                }
            }
            Event::Alias(_) => {
                return Err("YAML links are not supported: state the meanings clearly".into())
            }
            Event::Scalar(_, _, anchor, ref tag)
            | Event::MappingStart(anchor, ref tag)
            | Event::SequenceStart(anchor, ref tag)
                if anchor != 0 || tag.is_some() =>
            {
                return Err("YAML tags and anchors are not supported: use the usual values".into());
            }
            Event::MappingStart(_, _) | Event::SequenceStart(_, _) => {
                if stack.len() >= 32 {
                    return Err("Too deep nesting inventory (limit)".into());
                }
                stack.push(if matches!(event, Event::MappingStart(_, _)) {
                    Frame::Map(Map::new(), None)
                } else {
                    Frame::List(Vec::new())
                });
            }
            Event::Scalar(s, style, _, _) => {
                let value = if style == TScalarStyle::Plain
                    && matches!(s.as_str(), "" | "null" | "Null" | "NULL" | "~")
                {
                    Value::Null
                } else {
                    Value::String(s)
                };
                push(&mut stack, &mut root, value)?;
            }
            Event::MappingEnd | Event::SequenceEnd => {
                let value = match stack.pop() {
                    Some(Frame::Map(map, None)) => Value::Object(map),
                    Some(Frame::List(list)) => Value::Array(list),
                    _ => return Err("Incorrect inventory structure".into()),
                };
                push(&mut stack, &mut root, value)?;
            }
            _ => {}
        }
    }
    root.ok_or_else(|| "The inventory file is empty".into())
}
