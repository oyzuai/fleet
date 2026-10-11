package runnerclient

import (
	"context"
	"time"
)

// LogEntry is one masked entry in an attempt's gapless log.
type LogEntry struct {
	Sequence    int64     `json:"sequence"`
	Stream      string    `json:"stream"`
	Time        time.Time `json:"time"`
	Text        string    `json:"text"`
	Scope       string    `json:"scope,omitempty"`
	ParentScope string    `json:"parent_scope,omitempty"`
	Redacted    int       `json:"redacted,omitempty"`
	Event       *LogEvent `json:"event,omitempty"`
}

type LogEvent struct {
	Kind       string `json:"kind"`
	State      string `json:"state,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Status     string `json:"status,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
}

// LogChunk carries base64-encoded gzip NDJSON in data. Hash is lowercase
// SHA-256 of the uncompressed NDJSON, including its terminating newlines.
type LogChunk struct {
	Attempt int    `json:"attempt"`
	Seq     int64  `json:"seq"`
	First   int64  `json:"first_sequence"`
	Last    int64  `json:"last_sequence"`
	Entries int64  `json:"entry_count"`
	Data    []byte `json:"data"`
	Hash    string `json:"hash"`
}

type LogAck struct {
	NextSeq int64  `json:"next_seq"`
	State   string `json:"log_state"`
}

// LogFinish hashes the concatenation of all uncompressed chunks, in order.
// Incomplete is set when capture failed even if the delivered prefix matches.
type LogFinish struct {
	Attempt      int    `json:"attempt"`
	FinalSeq     int64  `json:"final_seq"`
	TotalEntries int64  `json:"total_entries"`
	Hash         string `json:"hash"`
	Incomplete   bool   `json:"incomplete,omitempty"`
}

func (c *Client) UploadLogs(ctx context.Context, token string, in LogChunk) (LogAck, error) {
	var out LogAck
	err := c.do(ctx, "job/logs", token, in, &out)
	return out, err
}

func (c *Client) FinishLogs(ctx context.Context, token string, in LogFinish) (LogAck, error) {
	var out LogAck
	err := c.do(ctx, "job/logs/finish", token, in, &out)
	return out, err
}
