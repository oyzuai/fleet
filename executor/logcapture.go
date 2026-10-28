package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

const (
	logChunkBytes   = 256 << 10
	logChunkEntries = 1000
	logCapBytes     = 512 << 20
	logDrainWindow  = 15 * time.Minute
	logOutcomeWait  = 30 * time.Second
)

type logPart struct {
	offset      int64
	size        int
	first, last int64
	hash        string
}

// logCapture is a masked disk spool. Only small chunk descriptors live in
// memory. Network delivery never holds the capture lock or a command pipe.
type logCapture struct {
	mu                           sync.Mutex
	scopes                       logScopes
	file                         *os.File
	tail                         *logRing
	dir                          string
	log                          *slog.Logger
	client                       *runnerclient.Client
	token                        string
	attempt                      int
	ctx                          context.Context
	cancel                       context.CancelFunc
	wake                         chan struct{}
	postFinish                   chan struct{}
	postFinishOnce               sync.Once
	done                         chan struct{}
	tickDone                     chan struct{}
	closed                       bool
	failed                       bool
	parts                        []logPart
	pending                      bytes.Buffer
	opened                       time.Time
	first, sequence, offset      int64
	digest                       hash.Hash
	capBytes                     int64
	headBytes                    int64
	tailing                      bool
	droppedBytes, droppedEntries int64
}

func newLogCapture(ctx context.Context, cfg Config, token string, job runnerclient.Job, log *slog.Logger) *logCapture {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c := &logCapture{log: log, client: cfg.Client, token: token, attempt: job.Attempt,
		ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), postFinish: make(chan struct{}), done: make(chan struct{}), tickDone: make(chan struct{}), digest: sha256.New(), capBytes: logCapBytes}
	// The checkout's parent may be / in a non-root container. Use the
	// executor's private temporary area, separate from captured source.
	var err error
	c.dir, err = os.MkdirTemp(cfg.SecretsDir, ".oyzu-log-")
	if err == nil {
		c.file, err = os.OpenFile(filepath.Join(c.dir, "entries.ndjson"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	}
	if err != nil {
		c.spoolError()
	}
	go c.upload()
	go func() {
		defer close(c.tickDone)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.mu.Lock()
				if !c.closed && !c.opened.IsZero() && time.Since(c.opened) >= time.Second {
					c.seal()
				}
				c.mu.Unlock()
			}
		}
	}()
	return c
}

func (c *logCapture) spoolError() {
	if !c.failed {
		c.log.Warn("log spool failed; log will be incomplete")
	}
	c.failed = true
}

func (c *logCapture) line(stream, text string, redacted int) runnerclient.LogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.scopes.entry(stream, text, redacted)
	c.add(e)
	return e
}

func (c *logCapture) system(text string, event *runnerclient.LogEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.add(runnerclient.LogEntry{Stream: "system", Time: time.Now().UTC(), Text: text, Scope: "runner", Event: event})
}

func (c *logCapture) add(e runnerclient.LogEntry) {
	if c.failed || c.closed {
		return
	}
	// Reserving the largest sequence width makes tail accounting conservative
	// before its final gapless sequence numbers are known.
	e.Sequence = 9223372036854775807
	b, err := json.Marshal(e)
	if err != nil {
		c.spoolError()
		return
	}
	if !c.tailing && c.headBytes+int64(len(b)+1) <= c.capBytes/2-1024 {
		c.headBytes += int64(len(b) + 1)
		c.append(e)
		return
	}
	c.tailing = true
	if c.tail == nil {
		f, err := os.OpenFile(filepath.Join(c.dir, "tail.ring"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
		if err != nil {
			c.spoolError()
			return
		}
		c.tail = &logRing{file: f, capacity: c.capBytes / 2}
	}
	n, size, err := c.tail.push(b)
	c.droppedEntries += n
	c.droppedBytes += size
	if err != nil {
		c.spoolError()
	}
}

func (c *logCapture) append(e runnerclient.LogEntry) {
	e.Sequence = c.sequence + 1
	b, err := json.Marshal(e)
	if err != nil {
		c.spoolError()
		return
	}
	b = append(b, '\n')
	if c.pending.Len() > 0 && c.pending.Len()+len(b) > logChunkBytes {
		c.seal()
	}
	if c.pending.Len() == 0 {
		c.opened = time.Now()
		c.first = e.Sequence
	}
	c.pending.Write(b)
	c.sequence = e.Sequence
	if c.pending.Len() >= logChunkBytes || c.sequence-c.first+1 >= logChunkEntries {
		c.seal()
	}
}

func (c *logCapture) seal() {
	if c.failed || c.pending.Len() == 0 {
		return
	}
	b := c.pending.Bytes()
	n, err := c.file.WriteAt(b, c.offset)
	if err != nil || n != len(b) {
		c.spoolError()
		return
	}
	sum := sha256.Sum256(b)
	c.parts = append(c.parts, logPart{c.offset, len(b), c.first, c.sequence, hex.EncodeToString(sum[:])})
	c.digest.Write(b)
	c.offset += int64(len(b))
	c.pending.Reset()
	c.opened = time.Time{}
	c.signal()
}

func (c *logCapture) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// finish seals capture while the uploader continues independently.
func (c *logCapture) finish() {
	c.mu.Lock()
	if c.tail != nil && !c.failed {
		if c.droppedEntries > 0 {
			c.append(runnerclient.LogEntry{Stream: "system", Scope: "runner", Time: time.Now().UTC(),
				Text: fmt.Sprintf("Log cap reached: dropped %d entries (%d bytes) from the middle.\n", c.droppedEntries, c.droppedBytes)})
		}
		for c.tail.used > 0 && !c.failed {
			b, err := c.tail.pop()
			if err != nil {
				c.spoolError()
				break
			}
			var e runnerclient.LogEntry
			if json.Unmarshal(b, &e) != nil {
				c.spoolError()
				break
			}
			c.append(e)
		}
	}
	c.seal()
	c.closed = true
	c.signal()
	c.mu.Unlock()
}

// beginPostFinishDrain gives the newly started log-only token window one
// prompt retry, even if delivery accumulated a long backoff while running.
// This is separate from ordinary entry notifications, which must not defeat
// retry backoff during a log outage.
func (c *logCapture) beginPostFinishDrain() {
	c.postFinishOnce.Do(func() { close(c.postFinish) })
}

// wait does not cancel delivery: Run may report the outcome between waits.
func (c *logCapture) wait(drain time.Duration) bool {
	t := time.NewTimer(drain)
	defer t.Stop()
	select {
	case <-c.done:
		return true
	case <-t.C:
		return false
	}
}

func (c *logCapture) cleanup() {
	c.cancel()
	<-c.done
	<-c.tickDone
	if c.file != nil {
		_ = c.file.Close()
	}
	if c.tail != nil {
		_ = c.tail.file.Close()
	}
	if c.dir != "" {
		_ = os.RemoveAll(c.dir)
	}
}

func (c *logCapture) upload() {
	defer close(c.done)
	next := int64(1)
	backoff := 100 * time.Millisecond
	postFinish := c.postFinish
	for {
		c.mu.Lock()
		count, closed := int64(len(c.parts)), c.closed
		var part logPart
		if next <= count {
			part = c.parts[next-1]
		}
		finish := runnerclient.LogFinish{Attempt: c.attempt, FinalSeq: count, TotalEntries: c.sequence, Hash: hex.EncodeToString(c.digest.Sum(nil)), Incomplete: c.failed}
		c.mu.Unlock()
		var err error
		var ack runnerclient.LogAck
		if next <= count {
			b := make([]byte, part.size)
			_, err = c.file.ReadAt(b, part.offset)
			if err != nil {
				c.log.Warn("log spool could not be read")
				return
			}
			var packed bytes.Buffer
			gz := gzip.NewWriter(&packed)
			_, _ = gz.Write(b)
			_ = gz.Close()
			ack, err = c.client.UploadLogs(c.ctx, c.token, runnerclient.LogChunk{Attempt: c.attempt, Seq: next,
				First: part.first, Last: part.last, Entries: part.last - part.first + 1, Data: packed.Bytes(), Hash: part.hash})
		} else if closed {
			ack, err = c.client.FinishLogs(c.ctx, c.token, finish)
			if err == nil {
				return
			}
		} else {
			select {
			case <-c.ctx.Done():
				return
			case <-c.wake:
				continue
			}
		}
		if err == nil {
			if ack.NextSeq <= next || ack.NextSeq > count+1 {
				c.log.Warn("log upload returned an invalid acknowledgement")
				return
			}
			next = ack.NextSeq
			backoff = 100 * time.Millisecond
			continue
		}
		if c.ctx.Err() != nil {
			return
		}
		var se *runnerclient.StatusError
		if errors.Is(err, runnerclient.ErrUnauthenticated) {
			c.log.Warn("log upload credential refused")
			return
		}
		if errors.As(err, &se) {
			if se.Status == http.StatusConflict && se.NextSeq >= 1 && se.NextSeq <= count+1 && se.NextSeq != next {
				next = se.NextSeq
			} else if se.Status >= 400 && se.Status < 500 && se.Status != 429 && se.Status != 409 {
				c.log.Warn("log upload refused", "status", se.Status)
				return
			}
		}
		c.log.Warn("log upload failed; retrying", "seq", next)
		t := time.NewTimer(backoff)
		select {
		case <-c.ctx.Done():
			t.Stop()
			return
		case <-postFinish:
			t.Stop()
			postFinish = nil // Consume the transition once, not every retry.
			backoff = 100 * time.Millisecond
			continue
		case <-t.C:
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

// logRing is a bounded disk FIFO of length-prefixed, already-masked entries.
// Its offsets, rather than one in-memory index per entry, bound memory too.
type logRing struct {
	file                  *os.File
	capacity, start, used int64
}

func (r *logRing) read(b []byte, pos int64) error {
	for len(b) > 0 {
		n := min(int64(len(b)), r.capacity-pos)
		if _, err := r.file.ReadAt(b[:n], pos); err != nil {
			return err
		}
		b, pos = b[n:], 0
	}
	return nil
}

func (r *logRing) write(b []byte, pos int64) error {
	for len(b) > 0 {
		n := min(int64(len(b)), r.capacity-pos)
		if wrote, err := r.file.WriteAt(b[:n], pos); err != nil {
			return err
		} else if int64(wrote) != n {
			return io.ErrShortWrite
		}
		b, pos = b[n:], 0
	}
	return nil
}

func (r *logRing) pop() ([]byte, error) {
	var header [4]byte
	if err := r.read(header[:], r.start); err != nil {
		return nil, err
	}
	n := int64(binary.BigEndian.Uint32(header[:]))
	if n+4 > r.used {
		return nil, errors.New("invalid spool frame")
	}
	b := make([]byte, n)
	if err := r.read(b, (r.start+4)%r.capacity); err != nil {
		return nil, err
	}
	r.start, r.used = (r.start+n+4)%r.capacity, r.used-n-4
	return b, nil
}

func (r *logRing) push(b []byte) (entries, size int64, err error) {
	if int64(len(b)+4) > r.capacity {
		return 1, int64(len(b) + 1), nil
	}
	for r.used+int64(len(b)+4) > r.capacity {
		old, e := r.pop()
		if e != nil {
			return entries, size, e
		}
		entries++
		size += int64(len(old) + 1)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	pos := (r.start + r.used) % r.capacity
	if err = r.write(header[:], pos); err != nil {
		return
	}
	if err = r.write(b, (pos+4)%r.capacity); err != nil {
		return
	}
	r.used += int64(len(b) + 4)
	return
}
