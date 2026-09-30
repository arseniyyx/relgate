package load

import (
	"context"
	"time"
)

// ticker is a minimal rate limiter: it releases up to maxRPS permits per second,
// spaced evenly. It avoids an external dependency and is enough for a bounded,
// self-targeted load test. Wait blocks until the next permit or ctx is done.
type ticker struct {
	interval time.Duration
	ch       chan time.Time
	stop     chan struct{}
}

func newTicker(maxRPS int) *ticker {
	if maxRPS < 1 {
		maxRPS = 1
	}
	t := &ticker{
		interval: time.Second / time.Duration(maxRPS),
		ch:       make(chan time.Time),
		stop:     make(chan struct{}),
	}
	go t.loop()
	return t
}

func (t *ticker) loop() {
	tk := time.NewTicker(t.interval)
	defer tk.Stop()
	for {
		select {
		case now := <-tk.C:
			select {
			case t.ch <- now:
			case <-t.stop:
				return
			}
		case <-t.stop:
			return
		}
	}
}

func (t *ticker) wait(ctx context.Context) error {
	select {
	case <-t.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *ticker) close() { close(t.stop) }
