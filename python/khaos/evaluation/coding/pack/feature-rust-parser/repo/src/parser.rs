#[derive(Debug, PartialEq)]
pub struct Record { pub key: String, pub value: String }

pub fn parse_record(input: &str) -> Result<Record, &'static str> {
    let mut parts = input.splitn(2, '=');
    Ok(Record { key: parts.next().unwrap_or("").to_string(), value: parts.next().unwrap_or("").to_string() })
}
