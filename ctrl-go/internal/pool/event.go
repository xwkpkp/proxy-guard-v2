package pool

import (
	"sync"
	"time"
)

// EventKind categorizes log entries surfaced in the TUI.
type EventKind string

// Event kinds.
const (
	EventAdded    EventKind = "added"
	EventSource   EventKind = "source"
	EventPass     EventKind = "pass"
	EventSlow     EventKind = "slow"
	EventRetry    EventKind = "retry"
	EventRetest   EventKind = "retest"
	EventFail     EventKind = "fail"
	EventRemoved  EventKind = "removed"
	EventDisabled EventKind = "disabled"
	EventEnabled  EventKind = "enabled"
	EventRotated  EventKind = "rotated"
	EventInfo     EventKind = "info"
)

// Event is a single line of the proxy activity log.
type Event struct {
	ID      int64
	Time    time.Time
	Kind    EventKind
	ProxyID string // host:port when the event concerns one proxy
	Text    string // short headline, e.g. "1.2.3.4:8080"
	Detail  string // optional extra info
}

// EventLog is a fixed-size ring buffer of events.
type EventLog struct {
	mu     sync.Mutex
	events []Event
	max    int
	seq    int64
}

// NewEventLog creates a log that keeps the last max events.
func NewEventLog(max int) *EventLog {
	if max < 1 {
		max = 1
	}
	return &EventLog{max: max}
}

// Append records a new event and returns it.
func (l *EventLog) Append(kind EventKind, proxyID, text, detail string) Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	ev := Event{
		ID:      l.seq,
		Time:    time.Now(),
		Kind:    kind,
		ProxyID: proxyID,
		Text:    text,
		Detail:  detail,
	}
	l.events = append(l.events, ev)
	if len(l.events) > l.max {
		l.events = l.events[len(l.events)-l.max:]
	}
	return ev
}

// Since returns events with an ID strictly greater than id, oldest first.
func (l *EventLog) Since(id int64) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, ev := range l.events {
		if ev.ID > id {
			out = append(out, ev)
		}
	}
	return out
}

// Tail returns up to n newest events, oldest first.
func (l *EventLog) Tail(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n >= len(l.events) {
		out := make([]Event, len(l.events))
		copy(out, l.events)
		return out
	}
	out := make([]Event, n)
	copy(out, l.events[len(l.events)-n:])
	return out
}

// LastID returns the ID of the newest event (0 when empty).
func (l *EventLog) LastID() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) == 0 {
		return 0
	}
	return l.events[len(l.events)-1].ID
}
