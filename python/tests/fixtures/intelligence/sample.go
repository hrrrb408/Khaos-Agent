package main
import "fmt"
type 示例 struct{}
func (示例) Method() string { nested := func() string { return "😀" }; return nested() }
func main() { fmt.Println(示例{}.Method()) }
