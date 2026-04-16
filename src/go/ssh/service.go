// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// Service is the interface that SSH services must implement.
// Services handle incoming requests and are activated on-demand based on
// activation rules (service request name, session request type, channel type,
// channel request type).
type Service interface {
	// OnSessionRequest is called when a session request is received that
	// matches this service's activation rule.
	OnSessionRequest(args *RequestEventArgs)

	// OnChannelOpening is called when a channel open request is received
	// that matches this service's channel type activation rule.
	OnChannelOpening(args *ChannelOpeningEventArgs)

	// OnChannelRequest is called when a channel request is received that
	// matches this service's channel request activation rule.
	OnChannelRequest(channel *Channel, args *RequestEventArgs)

	// Close is called when the session is closing to clean up resources.
	// Implements io.Closer.
	Close() error
}

// ServiceActivation defines activation rules for a service.
// Each field specifies a condition under which the service is activated.
// For services that respond to multiple triggers (e.g., port forwarding), use the
// plural fields (SessionRequests, ChannelTypes) which accept slices.
type ServiceActivation struct {
	// ServiceRequest activates the service when a service request (MSG 5) is
	// received with the specified name. Only server-side.
	ServiceRequest string

	// SessionRequest activates the service when a session request (MSG 80) is
	// received with the specified request type.
	SessionRequest string

	// SessionRequests activates the service when a session request (MSG 80)
	// matches any of the specified request types.
	SessionRequests []string

	// ChannelType activates the service when a channel open request is received
	// for the specified channel type.
	ChannelType string

	// ChannelTypes activates the service when a channel open request matches
	// any of the specified channel types.
	ChannelTypes []string

	// ChannelRequest activates the service when a channel request is received
	// for the specified request type. If ChannelType is also set, both must match.
	ChannelRequest string
}

// ServiceFactory creates a new instance of a service for the given session.
// The config parameter is the value from SessionConfig.Services map (may be nil).
type ServiceFactory func(session *Session, config interface{}) Service

// ServiceRegistration combines activation rules with a factory function.
type ServiceRegistration struct {
	Activation ServiceActivation
	Factory    ServiceFactory
	Config     interface{}
}

// AddService registers a service with activation rules in the session configuration.
func (c *SessionConfig) AddService(name string, activation ServiceActivation, factory ServiceFactory, config interface{}) {
	if c.ServiceRegistrations == nil {
		c.ServiceRegistrations = make(map[string]*ServiceRegistration)
	}
	c.ServiceRegistrations[name] = &ServiceRegistration{
		Activation: activation,
		Factory:    factory,
		Config:     config,
	}
}

// findServiceByServiceRequest finds a registered service that activates on the given
// service request name. Returns the service name and registration, or ("", nil) if not found.
func (c *SessionConfig) findServiceByServiceRequest(requestName string) (string, *ServiceRegistration) {
	for name, reg := range c.ServiceRegistrations {
		if reg.Activation.ServiceRequest == requestName {
			return name, reg
		}
	}
	return "", nil
}

// findServiceBySessionRequest finds a registered service that activates on the given
// session request type. Returns the service name and registration, or ("", nil) if not found.
func (c *SessionConfig) findServiceBySessionRequest(requestType string) (string, *ServiceRegistration) {
	for name, reg := range c.ServiceRegistrations {
		if reg.Activation.SessionRequest == requestType {
			return name, reg
		}
		for _, sr := range reg.Activation.SessionRequests {
			if sr == requestType {
				return name, reg
			}
		}
	}
	return "", nil
}

// findServiceByChannelType finds a registered service that activates on the given
// channel type (with no channel request constraint). Returns the service name and
// registration, or ("", nil) if not found.
func (c *SessionConfig) findServiceByChannelType(channelType string) (string, *ServiceRegistration) {
	for name, reg := range c.ServiceRegistrations {
		if reg.Activation.ChannelRequest != "" {
			continue
		}
		if reg.Activation.ChannelType == channelType {
			return name, reg
		}
		for _, ct := range reg.Activation.ChannelTypes {
			if ct == channelType {
				return name, reg
			}
		}
	}
	return "", nil
}

// findServiceByChannelRequest finds a registered service that activates on the given
// channel request type. If the service also has a ChannelType constraint, the channelType
// must match. Returns the service name and registration, or ("", nil) if not found.
func (c *SessionConfig) findServiceByChannelRequest(channelType string, requestType string) (string, *ServiceRegistration) {
	for name, reg := range c.ServiceRegistrations {
		if reg.Activation.ChannelRequest == requestType {
			if reg.Activation.ChannelType == "" && len(reg.Activation.ChannelTypes) == 0 {
				return name, reg
			}
			if reg.Activation.ChannelType == channelType {
				return name, reg
			}
			for _, ct := range reg.Activation.ChannelTypes {
				if ct == channelType {
					return name, reg
				}
			}
		}
	}
	return "", nil
}

// GetService returns the active service with the given name, or nil if not activated.
func (s *Session) GetService(name string) Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activatedServices == nil {
		return nil
	}
	return s.activatedServices[name]
}

// ActivateService activates a service by name. If the service is already activated,
// returns the existing instance. Returns nil if the service name is not registered.
func (s *Session) ActivateService(name string) Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activateServiceLocked(name)
}

// activateServiceLocked is the internal activation that assumes s.mu is held.
func (s *Session) activateServiceLocked(name string) Service {
	if s.activatedServices == nil {
		s.activatedServices = make(map[string]Service)
	}

	// Return existing instance if already activated.
	if svc, ok := s.activatedServices[name]; ok {
		return svc
	}

	// Look up registration.
	reg, ok := s.Config.ServiceRegistrations[name]
	if !ok {
		return nil
	}

	// Create the service instance.
	svc := reg.Factory(s, reg.Config)
	s.activatedServices[name] = svc

	// Fire callback outside lock.
	onActivated := s.OnServiceActivated
	s.mu.Unlock()
	if onActivated != nil {
		onActivated(svc)
	}
	s.mu.Lock()

	return svc
}

// activateServiceByServiceRequest tries to activate a service that matches the given
// service request name. Returns the activated service, or nil if none found.
func (s *Session) activateServiceByServiceRequest(requestName string) Service {
	s.mu.Lock()
	defer s.mu.Unlock()

	name, reg := s.Config.findServiceByServiceRequest(requestName)
	if reg == nil {
		return nil
	}

	return s.activateServiceByNameLocked(name, reg)
}

// activateServiceBySessionRequest tries to activate a service that matches the given
// session request type. Returns the activated service, or nil if none found.
func (s *Session) activateServiceBySessionRequest(requestType string) Service {
	s.mu.Lock()
	defer s.mu.Unlock()

	name, reg := s.Config.findServiceBySessionRequest(requestType)
	if reg == nil {
		return nil
	}

	return s.activateServiceByNameLocked(name, reg)
}

// activateServiceByChannelType tries to activate a service that matches the given
// channel type. Returns the activated service, or nil if none found.
func (s *Session) activateServiceByChannelType(channelType string) Service {
	s.mu.Lock()
	defer s.mu.Unlock()

	name, reg := s.Config.findServiceByChannelType(channelType)
	if reg == nil {
		return nil
	}

	return s.activateServiceByNameLocked(name, reg)
}

// activateServiceByChannelRequest tries to activate a service that matches the given
// channel request type on the given channel type. Returns the activated service, or nil.
func (s *Session) activateServiceByChannelRequest(channelType string, requestType string) Service {
	s.mu.Lock()
	defer s.mu.Unlock()

	name, reg := s.Config.findServiceByChannelRequest(channelType, requestType)
	if reg == nil {
		return nil
	}

	return s.activateServiceByNameLocked(name, reg)
}

// activateServiceByNameLocked activates a service by name with a known registration.
// Assumes s.mu is held.
func (s *Session) activateServiceByNameLocked(name string, reg *ServiceRegistration) Service {
	if s.activatedServices == nil {
		s.activatedServices = make(map[string]Service)
	}

	// Return existing instance if already activated.
	if svc, ok := s.activatedServices[name]; ok {
		return svc
	}

	// Create the service instance.
	svc := reg.Factory(s, reg.Config)
	s.activatedServices[name] = svc

	// Fire callback outside lock.
	onActivated := s.OnServiceActivated
	s.mu.Unlock()
	if onActivated != nil {
		onActivated(svc)
	}
	s.mu.Lock()

	return svc
}

// Services returns a snapshot of all currently activated services.
func (s *Session) Services() []Service {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]Service, 0, len(s.activatedServices))
	for _, svc := range s.activatedServices {
		result = append(result, svc)
	}
	return result
}

// closeServices closes all activated services.
func (s *Session) closeServices() {
	s.mu.Lock()
	services := make([]Service, 0, len(s.activatedServices))
	for _, svc := range s.activatedServices {
		services = append(services, svc)
	}
	s.mu.Unlock()

	for _, svc := range services {
		svc.Close()
	}
}

// RequestService sends a service request (SSH_MSG_SERVICE_REQUEST) to the remote side
// and waits for the service accept response. This is used by clients to request
// server-side service activation.
//
// This is a convenience wrapper around RequestServiceContext with context.Background().
func (s *Session) RequestService(serviceName string) error {
	return s.RequestServiceContext(context.Background(), serviceName)
}

// RequestServiceContext sends a service request (SSH_MSG_SERVICE_REQUEST) to the remote side
// and waits for the service accept response, respecting the provided context for
// cancellation and timeouts. This is used by clients to request server-side service activation.
func (s *Session) RequestServiceContext(ctx context.Context, serviceName string) error {
	// Check context before starting any work.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Register the pending response channel BEFORE sending the request
	// to avoid a race where the response arrives before we're listening.
	s.mu.Lock()
	if s.pendingServiceRequests == nil {
		s.pendingServiceRequests = make(map[string]chan struct{})
	}
	ch := make(chan struct{}, 1)
	s.pendingServiceRequests[serviceName] = ch
	s.mu.Unlock()

	msg := &messages.ServiceRequestMessage{
		ServiceName: serviceName,
	}
	if err := s.SendMessage(msg); err != nil {
		s.mu.Lock()
		delete(s.pendingServiceRequests, serviceName)
		s.mu.Unlock()
		return err
	}

	select {
	case <-ch:
		return nil
	case <-s.done:
		return &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session closed while waiting for service accept",
		}
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pendingServiceRequests, serviceName)
		s.mu.Unlock()
		return ctx.Err()
	}
}
