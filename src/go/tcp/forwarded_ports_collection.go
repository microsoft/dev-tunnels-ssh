// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import "sync"

// ForwardedPortsCollection is a thread-safe observable collection of forwarded ports.
// It tracks active port forwardings and fires callbacks when ports are added or removed.
type ForwardedPortsCollection struct {
	mu    sync.Mutex
	ports map[int]*ForwardedPort

	// OnPortAdded is called when a port is added to the collection.
	OnPortAdded func(port *ForwardedPort)

	// OnPortRemoved is called when a port is removed from the collection.
	OnPortRemoved func(port *ForwardedPort)
}

// NewForwardedPortsCollection creates a new empty ForwardedPortsCollection.
func NewForwardedPortsCollection() *ForwardedPortsCollection {
	return &ForwardedPortsCollection{
		ports: make(map[int]*ForwardedPort),
	}
}

// Add adds a forwarded port to the collection, keyed by local or remote port
// depending on the forwarding direction. If the port already exists, it is replaced.
// Fires OnPortAdded callback after adding.
func (c *ForwardedPortsCollection) Add(key int, port *ForwardedPort) {
	c.mu.Lock()
	c.ports[key] = port
	cb := c.OnPortAdded
	c.mu.Unlock()

	if cb != nil {
		cb(port)
	}
}

// Remove removes a forwarded port from the collection by key.
// Returns true if the port was found and removed, false otherwise.
// Fires OnPortRemoved callback if a port was removed.
func (c *ForwardedPortsCollection) Remove(key int) bool {
	c.mu.Lock()
	port, ok := c.ports[key]
	if ok {
		delete(c.ports, key)
	}
	cb := c.OnPortRemoved
	c.mu.Unlock()

	if ok && cb != nil {
		cb(port)
	}
	return ok
}

// Contains returns true if the collection contains a port with the given key.
func (c *ForwardedPortsCollection) Contains(key int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.ports[key]
	return ok
}

// Count returns the number of forwarded ports in the collection.
func (c *ForwardedPortsCollection) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ports)
}

// Get returns the forwarded port for the given key, or nil if not found.
func (c *ForwardedPortsCollection) Get(key int) *ForwardedPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ports[key]
}

// clear removes all ports from the collection, calling OnPortRemoved for each.
func (c *ForwardedPortsCollection) clear() {
	c.mu.Lock()
	ports := make(map[int]*ForwardedPort, len(c.ports))
	for k, v := range c.ports {
		ports[k] = v
	}
	c.ports = make(map[int]*ForwardedPort)
	cb := c.OnPortRemoved
	c.mu.Unlock()

	if cb != nil {
		for _, port := range ports {
			cb(port)
		}
	}
}
