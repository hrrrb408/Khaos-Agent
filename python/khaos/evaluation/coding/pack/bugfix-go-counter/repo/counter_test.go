package counter

func ExampleCounter_Balance() {
	c := &Counter{}
	c.Add(3)
	println(c.Balance())
}
