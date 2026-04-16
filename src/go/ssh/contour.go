// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"encoding/base64"
	"fmt"
	"math"
	"sync"
)

const (
	contourInitialIntervalMs int64 = 1000 // 1 second in milliseconds
	contourDefaultMaxIntervals     = 256
)

// SessionMetric identifies a series of values in the exported contour format.
type sessionMetric byte

const (
	sessionMetricNone           sessionMetric = 0
	sessionMetricLatencyMin     sessionMetric = 1
	sessionMetricLatencyMax     sessionMetric = 2
	sessionMetricLatencyAverage sessionMetric = 3
	sessionMetricBytesSent      sessionMetric = 11
	sessionMetricBytesReceived  sessionMetric = 12
)

// SessionContour collects session metrics over time, producing an outline of the
// timing, speed, and quantity of bytes sent/received during the session.
//
// Metrics are recorded across a number of equal time intervals. As the session time
// increases, intervals are expanded to keep the number of intervals under the
// configured maximum. Each expansion doubles the length of all intervals, while
// combining the metrics within each pair of combined intervals.
type SessionContour struct {
	mu sync.Mutex

	maxIntervals  int
	intervalCount int
	intervalMs    int64 // current interval duration in milliseconds

	bytesSent    []int64
	bytesReceived []int64
	latencyMin   []float32
	latencyMax   []float32
	latencySum   []float64
	latencyCount []int64

	// updateCh receives contour updates to be processed.
	updateCh chan ContourUpdate
	// doneCh is closed when CollectMetrics finishes.
	doneCh chan struct{}
	closed bool
}

// ContourUpdate contains a single metrics update to be applied to the contour.
type ContourUpdate struct {
	Time          int64
	BytesSent     int
	BytesReceived int
	Latency       float32
}

// NewSessionContour creates a new SessionContour with the given maximum intervals.
// maxIntervals must be a power of two and at least 2.
func NewSessionContour(maxIntervals int) *SessionContour {
	if maxIntervals < 2 || (maxIntervals&(maxIntervals-1)) != 0 {
		panic("contour intervals must be a power of two and at least 2")
	}
	return &SessionContour{
		maxIntervals:  maxIntervals,
		intervalMs:    contourInitialIntervalMs,
		bytesSent:     make([]int64, maxIntervals),
		bytesReceived: make([]int64, maxIntervals),
		latencyMin:    make([]float32, maxIntervals),
		latencyMax:    make([]float32, maxIntervals),
		latencySum:    make([]float64, maxIntervals),
		latencyCount:  make([]int64, maxIntervals),
		updateCh:      make(chan ContourUpdate, 256),
		doneCh:        make(chan struct{}),
	}
}

// MaxIntervals returns the maximum number of intervals this contour can record.
func (c *SessionContour) MaxIntervals() int {
	return c.maxIntervals
}

// IntervalCount returns the current number of intervals with recorded metrics.
func (c *SessionContour) IntervalCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.intervalCount
}

// IntervalMs returns the current interval duration in milliseconds.
func (c *SessionContour) IntervalMs() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.intervalMs
}

// BytesSentAt returns the bytes sent for the interval at index i.
func (c *SessionContour) BytesSentAt(i int) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesSent[i]
}

// BytesReceivedAt returns the bytes received for the interval at index i.
func (c *SessionContour) BytesReceivedAt(i int) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesReceived[i]
}

// LatencyMinMsAt returns the minimum latency in ms for the interval at index i.
func (c *SessionContour) LatencyMinMsAt(i int) float32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latencyMin[i]
}

// LatencyMaxMsAt returns the maximum latency in ms for the interval at index i.
func (c *SessionContour) LatencyMaxMsAt(i int) float32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latencyMax[i]
}

// LatencyAverageMsAt returns the average latency in ms for the interval at index i.
func (c *SessionContour) LatencyAverageMsAt(i int) float32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := c.latencyCount[i]
	if count == 0 {
		return 0
	}
	return float32(c.latencySum[i] / float64(count))
}

// BytesSentSlice returns a copy of the bytes sent values for all recorded intervals.
func (c *SessionContour) BytesSentSlice() []int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]int64, c.intervalCount)
	copy(result, c.bytesSent[:c.intervalCount])
	return result
}

// BytesReceivedSlice returns a copy of the bytes received values for all recorded intervals.
func (c *SessionContour) BytesReceivedSlice() []int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]int64, c.intervalCount)
	copy(result, c.bytesReceived[:c.intervalCount])
	return result
}

// LatencyMinMsSlice returns a copy of the min latency values for all recorded intervals.
func (c *SessionContour) LatencyMinMsSlice() []float32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]float32, c.intervalCount)
	copy(result, c.latencyMin[:c.intervalCount])
	return result
}

// LatencyMaxMsSlice returns a copy of the max latency values for all recorded intervals.
func (c *SessionContour) LatencyMaxMsSlice() []float32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]float32, c.intervalCount)
	copy(result, c.latencyMax[:c.intervalCount])
	return result
}

// LatencyAverageMsSlice returns a copy of the average latency values for all recorded intervals.
func (c *SessionContour) LatencyAverageMsSlice() []float32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]float32, c.intervalCount)
	for i := 0; i < c.intervalCount; i++ {
		count := c.latencyCount[i]
		if count == 0 {
			result[i] = 0
		} else {
			result[i] = float32(c.latencySum[i] / float64(count))
		}
	}
	return result
}

// CollectMetrics starts collecting session metrics and processes them until
// Stop is called or the session is closed.
func (c *SessionContour) CollectMetrics(metrics *SessionMetrics) {
	metrics.callbackMu.Lock()
	prevSent := metrics.OnMessageSent
	prevReceived := metrics.OnMessageReceived
	prevLatency := metrics.OnLatencyUpdated
	prevClosed := metrics.OnSessionClosed

	metrics.OnMessageSent = func(timeMs int64, size int) {
		if prevSent != nil {
			prevSent(timeMs, size)
		}
		select {
		case c.updateCh <- ContourUpdate{Time: timeMs, BytesSent: size}:
		default:
		}
	}
	metrics.OnMessageReceived = func(timeMs int64, size int) {
		if prevReceived != nil {
			prevReceived(timeMs, size)
		}
		select {
		case c.updateCh <- ContourUpdate{Time: timeMs, BytesReceived: size}:
		default:
		}
	}
	metrics.OnLatencyUpdated = func(timeMs int64, latencyMs float32) {
		if prevLatency != nil {
			prevLatency(timeMs, latencyMs)
		}
		select {
		case c.updateCh <- ContourUpdate{Time: timeMs, Latency: latencyMs}:
		default:
		}
	}
	metrics.OnSessionClosed = func() {
		if prevClosed != nil {
			prevClosed()
		}
		c.Stop()
	}
	metrics.callbackMu.Unlock()

	go func() {
		defer func() {
			// Restore previous callbacks.
			metrics.callbackMu.Lock()
			metrics.OnMessageSent = prevSent
			metrics.OnMessageReceived = prevReceived
			metrics.OnLatencyUpdated = prevLatency
			metrics.OnSessionClosed = prevClosed
			metrics.callbackMu.Unlock()

			close(c.doneCh)
		}()

		for update := range c.updateCh {
			c.applyUpdate(update)
		}
	}()
}

// Stop signals the contour to stop collecting and waits for it to finish.
func (c *SessionContour) Stop() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	close(c.updateCh)
	<-c.doneCh
}

// applyUpdate applies a single metrics update to the contour.
func (c *SessionContour) applyUpdate(u ContourUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	idx := c.updateInterval(u.Time)

	c.bytesSent[idx] += int64(u.BytesSent)
	c.bytesReceived[idx] += int64(u.BytesReceived)

	latency := u.Latency
	if latency != 0 {
		if c.latencyMin[idx] == 0 || latency < c.latencyMin[idx] {
			c.latencyMin[idx] = latency
		}
		if latency > c.latencyMax[idx] {
			c.latencyMax[idx] = latency
		}
		c.latencySum[idx] += float64(latency)
		c.latencyCount[idx]++
	}
}

// updateInterval determines the interval index for the given time,
// expanding intervals as needed. Must be called with c.mu held.
func (c *SessionContour) updateInterval(timeMs int64) int {
	idx := int(timeMs / c.intervalMs)
	if idx >= c.intervalCount {
		for idx >= c.maxIntervals {
			c.expandIntervals()
			idx = int(timeMs / c.intervalMs)
		}
		c.intervalCount = idx + 1
	}
	return idx
}

// expandIntervals doubles the interval duration and combines pairs of intervals.
// Must be called with c.mu held.
func (c *SessionContour) expandIntervals() {
	combineLatency := func(a, b float32, f func(float32, float32) float32) float32 {
		if a == 0 {
			return b
		}
		if b == 0 {
			return a
		}
		return f(a, b)
	}

	half := c.maxIntervals / 2
	for i := 0; i < half; i++ {
		iA := 2 * i
		iB := 2*i + 1
		c.latencyMin[i] = combineLatency(c.latencyMin[iA], c.latencyMin[iB],
			func(a, b float32) float32 {
				if a < b {
					return a
				}
				return b
			})
		c.latencyMax[i] = combineLatency(c.latencyMax[iA], c.latencyMax[iB],
			func(a, b float32) float32 {
				if a > b {
					return a
				}
				return b
			})
		c.latencySum[i] = c.latencySum[iA] + c.latencySum[iB]
		c.latencyCount[i] = c.latencyCount[iA] + c.latencyCount[iB]
		c.bytesSent[i] = c.bytesSent[iA] + c.bytesSent[iB]
		c.bytesReceived[i] = c.bytesReceived[iA] + c.bytesReceived[iB]
	}

	// Clear the upper half.
	for i := half; i < c.maxIntervals; i++ {
		c.latencyMin[i] = 0
		c.latencyMax[i] = 0
		c.latencySum[i] = 0
		c.latencyCount[i] = 0
		c.bytesSent[i] = 0
		c.bytesReceived[i] = 0
	}

	c.intervalMs *= 2
}

// AddUpdate directly adds a contour update. Useful for testing.
func (c *SessionContour) AddUpdate(u ContourUpdate) {
	c.applyUpdate(u)
}

// Export serializes the session contour into a compact base64-encoded form.
func (c *SessionContour) Export() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	getScale := func(max float64) byte {
		if max <= 0 {
			return 0
		}
		v := math.Ceil(math.Log2(max / 255))
		if v < 0 {
			return 0
		}
		return byte(v)
	}

	applyReverseScale := func(value float64, scale byte) byte {
		return byte(math.Round(value / math.Pow(2, float64(scale))))
	}

	const metricsPerInterval = 5
	n := c.intervalCount
	bytes := make([]byte, 3+(2+n)*metricsPerInterval)

	timeScale := byte(math.Log2(float64(c.intervalMs) / float64(contourInitialIntervalMs)))

	bytes[0] = 1 // version
	bytes[1] = metricsPerInterval
	bytes[2] = timeScale

	// Compute max values for each metric series.
	var maxLatencyMin, maxLatencyMax, maxLatencyAvg float64
	var maxBytesSent, maxBytesReceived float64
	for i := 0; i < n; i++ {
		if float64(c.latencyMin[i]) > maxLatencyMin {
			maxLatencyMin = float64(c.latencyMin[i])
		}
		if float64(c.latencyMax[i]) > maxLatencyMax {
			maxLatencyMax = float64(c.latencyMax[i])
		}
		avg := float64(0)
		if c.latencyCount[i] > 0 {
			avg = c.latencySum[i] / float64(c.latencyCount[i])
		}
		if avg > maxLatencyAvg {
			maxLatencyAvg = avg
		}
		if float64(c.bytesSent[i]) > maxBytesSent {
			maxBytesSent = float64(c.bytesSent[i])
		}
		if float64(c.bytesReceived[i]) > maxBytesReceived {
			maxBytesReceived = float64(c.bytesReceived[i])
		}
	}

	// Value scales.
	bytes[3] = getScale(maxLatencyMin)
	bytes[4] = getScale(maxLatencyMax)
	bytes[5] = getScale(maxLatencyAvg)
	bytes[6] = getScale(maxBytesSent)
	bytes[7] = getScale(maxBytesReceived)

	// Metric IDs.
	bytes[8] = byte(sessionMetricLatencyMin)
	bytes[9] = byte(sessionMetricLatencyMax)
	bytes[10] = byte(sessionMetricLatencyAverage)
	bytes[11] = byte(sessionMetricBytesSent)
	bytes[12] = byte(sessionMetricBytesReceived)

	// Per-interval data.
	for i := 0; i < n; i++ {
		offset := 13 + metricsPerInterval*i
		avg := float64(0)
		if c.latencyCount[i] > 0 {
			avg = c.latencySum[i] / float64(c.latencyCount[i])
		}
		bytes[offset+0] = applyReverseScale(float64(c.latencyMin[i]), bytes[3])
		bytes[offset+1] = applyReverseScale(float64(c.latencyMax[i]), bytes[4])
		bytes[offset+2] = applyReverseScale(avg, bytes[5])
		bytes[offset+3] = applyReverseScale(float64(c.bytesSent[i]), bytes[6])
		bytes[offset+4] = applyReverseScale(float64(c.bytesReceived[i]), bytes[7])
	}

	return base64.StdEncoding.EncodeToString(bytes)
}

// ImportContour deserializes a session contour that was previously exported.
func ImportContour(contourBase64 string) (*SessionContour, error) {
	data, err := base64.StdEncoding.DecodeString(contourBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(data) < 3 {
		return nil, fmt.Errorf("invalid session contour string")
	}

	version := data[0]
	metricsPerInterval := int(data[1])
	timeScale := data[2]

	if version != 1 {
		return nil, fmt.Errorf("unsupported session contour version: %d", version)
	}

	intervalCount := (len(data)-3)/metricsPerInterval - 2
	if intervalCount < 1 || len(data) != 3+metricsPerInterval*(intervalCount+2) {
		return nil, fmt.Errorf("incomplete session contour string")
	}

	// Round maxIntervals up to next power of two.
	maxIntervals := 2
	for maxIntervals < intervalCount {
		maxIntervals *= 2
	}

	sc := NewSessionContour(maxIntervals)
	sc.intervalMs = int64(math.Pow(2, float64(timeScale))) * contourInitialIntervalMs
	sc.intervalCount = intervalCount

	scales := make([]int, metricsPerInterval)
	for m := 0; m < metricsPerInterval; m++ {
		scales[m] = int(math.Pow(2, float64(data[3+m])))
	}

	ids := make([]sessionMetric, metricsPerInterval)
	for m := 0; m < metricsPerInterval; m++ {
		ids[m] = sessionMetric(data[3+metricsPerInterval+m])
	}

	for i := 0; i < intervalCount; i++ {
		offset := 3 + (2+i)*metricsPerInterval
		for m := 0; m < metricsPerInterval; m++ {
			v := data[offset+m]
			switch ids[m] {
			case sessionMetricLatencyMin:
				sc.latencyMin[i] = float32(int(v) * scales[m])
			case sessionMetricLatencyMax:
				sc.latencyMax[i] = float32(int(v) * scales[m])
			case sessionMetricLatencyAverage:
				sc.latencySum[i] = float64(int(v) * scales[m])
				if v == 0 {
					sc.latencyCount[i] = 0
				} else {
					sc.latencyCount[i] = 1
				}
			case sessionMetricBytesSent:
				sc.bytesSent[i] = int64(v) * int64(scales[m])
			case sessionMetricBytesReceived:
				sc.bytesReceived[i] = int64(v) * int64(scales[m])
			}
		}
	}

	return sc, nil
}
