package counter

type Counter struct { balance int }

func (c *Counter) Add(delta int) { c.balance += delta }

func (c *Counter) Decrement(delta int) bool {
	if delta < 0 { return false }
	c.balance -= delta
	return true
}

func (c *Counter) Balance() int { return c.balance }
