package counter

// Snapshot is the read-only representation used by callers that publish a balance.
type Snapshot struct {
	Balance int
}

func (c *Counter) Snapshot() Snapshot { return Snapshot{Balance: c.Balance()} }
