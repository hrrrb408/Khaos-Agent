use std::fmt;
struct 示例;
impl 示例 { fn method(&self) { fn nested() { println!("😀"); } nested(); } }
fn main() { 示例.method(); }
