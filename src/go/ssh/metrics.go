// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"sync"
	"sync/atomic"
	"time"
)

const microsecondsPerMillisecond = 1000.0

// ChannelMetrics tracks byte counters for a single SSH channel.
type ChannelMetrics struct {
	bytesSent       int64
	bytesReceived   int64
	droppedRequests int64
}

// BytesSent returns the total number of data bytes sent on this channel.
func (m *ChannelMetrics) BytesSent() int64 {
	return atomic.LoadInt64(&m.bytesSent)
}

// BytesReceived returns the total number of data bytes received on this channel.
func (m *ChannelMetrics) BytesReceived() int64 {
	return atomic.LoadInt64(&m.bytesReceived)
}

// DroppedRequests returns the number of channel requests dropped due to a full queue.
func (m *ChannelMetrics) DroppedRequests() int64 {
	return atomic.LoadInt64(&m.droppedRequests)
}

// addBytesSent atomically adds to the bytes sent counter.
func (m *ChannelMetrics) addBytesSent(count int64) {
	atomic.AddInt64(&m.bytesSent, count)
}

// addBytesReceived atomically adds to the bytes received counter.
func (m *ChannelMetrics) addBytesReceived(count int64) {
	atomic.AddInt64(&m.bytesReceived, count)
}

// addDroppedRequest atomically increments the dropped requests counter.
func (m *ChannelMetrics) addDroppedRequest() {
	atomic.AddInt64(&m.droppedRequests, 1)
}

// SessionMetrics tracks byte, message, and latency counters for an SSH session.
// Latency is measured in microseconds internally but reported in milliseconds.
type SessionMetrics struct {
	messagesSent     int64
	messagesReceived int64
	bytesSent        int64
	bytesReceived    int64
	reconnections    int64

	// Latency tracking (all in microseconds).
	latencyCurrent int64
	latencyMin     int64
	latencyMax     int64
	latencySum     int64
	latencyCount   int64

	// Stopwatch for session-relative time (milliseconds).
	startTime time.Time

	// OnMessageSent is called when a message is sent.
	// Args: (sessionTimeMs int64, sizeBytes int).
	OnMessageSent func(int64, int)

	// OnMessageReceived is called when a message is received.
	// Args: (sessionTimeMs int64, sizeBytes int).
	OnMessageReceived func(int64, int)

	// OnLatencyUpdated is called when latency is measured.
	// Args: (sessionTimeMs int64, latencyMs float32).
	OnLatencyUpdated func(int64, float32)

	// OnSessionClosed is called when the session is closed.
	OnSessionClosed func()

	// callbackMu protects callback fields from concurrent modification.
	callbackMu sync.Mutex
}

// initMetrics initializes the session metrics start time.
func (m *SessionMetrics) initMetrics() {
	m.startTime = time.Now()
}

// sessionTimeMs returns the elapsed session time in milliseconds.
func (m *SessionMetrics) sessionTimeMs() int64 {
	return time.Since(m.startTime).Milliseconds()
}

// MessagesSent returns the total number of messages sent on this session.
func (m *SessionMetrics) MessagesSent() int64 {
	return atomic.LoadInt64(&m.messagesSent)
}

// MessagesReceived returns the total number of messages received on this session.
func (m *SessionMetrics) MessagesReceived() int64 {
	return atomic.LoadInt64(&m.messagesReceived)
}

// BytesSent returns the total number of wire bytes sent on this session.
func (m *SessionMetrics) BytesSent() int64 {
	return atomic.LoadInt64(&m.bytesSent)
}

// BytesReceived returns the total number of wire bytes received on this session.
func (m *SessionMetrics) BytesReceived() int64 {
	return atomic.LoadInt64(&m.bytesReceived)
}

// Reconnections returns the number of times this session has been reconnected.
func (m *SessionMetrics) Reconnections() int64 {
	return atomic.LoadInt64(&m.reconnections)
}

// LatencyCurrentMs returns the most recent round-trip latency in milliseconds.
// Returns 0 if latency has not been measured or the session is disconnected.
func (m *SessionMetrics) LatencyCurrentMs() float32 {
	return float32(atomic.LoadInt64(&m.latencyCurrent)) / microsecondsPerMillisecond
}

// LatencyMinMs returns the minimum measured round-trip latency in milliseconds.
func (m *SessionMetrics) LatencyMinMs() float32 {
	return float32(atomic.LoadInt64(&m.latencyMin)) / microsecondsPerMillisecond
}

// LatencyMaxMs returns the maximum measured round-trip latency in milliseconds.
func (m *SessionMetrics) LatencyMaxMs() float32 {
	return float32(atomic.LoadInt64(&m.latencyMax)) / microsecondsPerMillisecond
}

// LatencyAverageMs returns the average measured round-trip latency in milliseconds.
func (m *SessionMetrics) LatencyAverageMs() float32 {
	count := atomic.LoadInt64(&m.latencyCount)
	if count == 0 {
		return 0
	}
	sum := atomic.LoadInt64(&m.latencySum)
	return float32(sum/count) / microsecondsPerMillisecond
}

// addMessageSent atomically increments message count and adds wire bytes.
func (m *SessionMetrics) addMessageSent(size int) {
	atomic.AddInt64(&m.messagesSent, 1)
	atomic.AddInt64(&m.bytesSent, int64(size))

	m.callbackMu.Lock()
	cb := m.OnMessageSent
	m.callbackMu.Unlock()
	if cb != nil {
		cb(m.sessionTimeMs(), size)
	}
}

// addMessageReceived atomically increments message count and adds wire bytes.
func (m *SessionMetrics) addMessageReceived(size int) {
	atomic.AddInt64(&m.messagesReceived, 1)
	atomic.AddInt64(&m.bytesReceived, int64(size))

	m.callbackMu.Lock()
	cb := m.OnMessageReceived
	m.callbackMu.Unlock()
	if cb != nil {
		cb(m.sessionTimeMs(), size)
	}
}

// addReconnection atomically increments the reconnection counter.
func (m *SessionMetrics) addReconnection() {
	atomic.AddInt64(&m.reconnections, 1)
}

// updateLatency updates the latency measurement with a new value in microseconds.
// A negative value is ignored. A zero value indicates disconnection (resets current only).
func (m *SessionMetrics) updateLatency(latencyMicroseconds int64) {
	if latencyMicroseconds < 0 {
		return
	}

	atomic.StoreInt64(&m.latencyCurrent, latencyMicroseconds)

	if latencyMicroseconds == 0 {
		// Disconnected — reset current but keep min/max/avg.
		return
	}

	// Update min using CAS loop.
	for {
		currentMin := atomic.LoadInt64(&m.latencyMin)
		if currentMin != 0 && latencyMicroseconds >= currentMin {
			break
		}
		if atomic.CompareAndSwapInt64(&m.latencyMin, currentMin, latencyMicroseconds) {
			break
		}
	}

	// Update max using CAS loop.
	for {
		currentMax := atomic.LoadInt64(&m.latencyMax)
		if latencyMicroseconds <= currentMax {
			break
		}
		if atomic.CompareAndSwapInt64(&m.latencyMax, currentMax, latencyMicroseconds) {
			break
		}
	}

	// Accumulate sum and count for average.
	atomic.AddInt64(&m.latencySum, latencyMicroseconds)
	atomic.AddInt64(&m.latencyCount, 1)

	latencyMs := float32(latencyMicroseconds) / microsecondsPerMillisecond
	m.callbackMu.Lock()
	cb := m.OnLatencyUpdated
	m.callbackMu.Unlock()
	if cb != nil {
		cb(m.sessionTimeMs(), latencyMs)
	}
}

// closeMetrics resets current latency and fires the session closed callback.
func (m *SessionMetrics) closeMetrics() {
	atomic.StoreInt64(&m.latencyCurrent, 0)

	m.callbackMu.Lock()
	cb := m.OnSessionClosed
	m.callbackMu.Unlock()
	if cb != nil {
		cb()
	}
}

// TimeMicroseconds returns the current time in microseconds since Unix epoch.
// Used for latency tracking in reconnection support.
func (m *SessionMetrics) TimeMicroseconds() int64 {
	return time.Now().UnixMicro()
}
