package dockerwatch

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConsumeDebouncesBurst feeds a burst of event lines and asserts the
// debounce coalesces them into a single recompile.
func TestConsumeDebouncesBurst(t *testing.T) {
	var calls int32
	w := New(func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}, nil)
	w.debounce = 50 * time.Millisecond

	// Ten events arriving back-to-back must collapse to one recompile.
	r := strings.NewReader("start a\ndie a\nstart b\nstart c\ndie b\nstart d\nstart e\ndie c\nstart f\nstart g\n")
	w.consume(context.Background(), r)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("burst of 10 events triggered %d recompiles, want 1", got)
	}
}

// TestConsumeSeparatedEventsFireSeparately asserts that events spaced
// further apart than the debounce window each trigger their own recompile.
func TestConsumeSeparatedEventsFireSeparately(t *testing.T) {
	var calls int32
	w := New(func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}, nil)
	w.debounce = 20 * time.Millisecond

	pr, pw := newPipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.consume(context.Background(), pr)
	}()

	pw.write("start a\n")
	time.Sleep(60 * time.Millisecond) // let the first debounce fire
	pw.write("die a\n")
	time.Sleep(60 * time.Millisecond) // and the second
	pw.close()
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("two well-separated events triggered %d recompiles, want 2", got)
	}
}

// TestConsumeStopsOnContextCancel asserts consume returns promptly when
// the context is cancelled even with no further events.
func TestConsumeStopsOnContextCancel(t *testing.T) {
	w := New(func(context.Context) error { return nil }, nil)
	w.debounce = time.Hour // never fires on its own

	pr, _ := newPipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.consume(ctx, pr)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consume did not return after context cancel")
	}
}

// newPipe is a tiny blocking in-memory pipe so a test can feed lines to
// consume on its own schedule and signal EOF by closing.
func newPipe() (*pipeReader, *pipeWriter) {
	ch := make(chan []byte, 64)
	closed := make(chan struct{})
	return &pipeReader{ch: ch, closed: closed}, &pipeWriter{ch: ch, closed: closed}
}

type pipeReader struct {
	ch     chan []byte
	closed chan struct{}
	buf    []byte
}

func (p *pipeReader) Read(b []byte) (int, error) {
	for len(p.buf) == 0 {
		select {
		case chunk := <-p.ch:
			p.buf = chunk
		case <-p.closed:
			select {
			case chunk := <-p.ch:
				p.buf = chunk
			default:
				return 0, errEOF
			}
		}
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

type pipeWriter struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (p *pipeWriter) write(s string) { p.ch <- []byte(s) }
func (p *pipeWriter) close()         { p.once.Do(func() { close(p.closed) }) }

type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }

const errEOF = sentinelErr("EOF")
