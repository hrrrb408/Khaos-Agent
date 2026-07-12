import { value as unicodeValue } from "./dep.js";
class 示例 { method() { function nested() { return "😀"; } return nested(); } }
function main() { return new 示例().method(); }
