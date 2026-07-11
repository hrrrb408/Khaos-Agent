import type { Item } from "./types";
interface Named { name: string }
class 示例 implements Named { name = "😀"; method(): string { function nested() { return this.name; } return nested(); } }
function main(item: Item) { return new 示例().method(); }
