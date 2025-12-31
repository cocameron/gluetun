package protonvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/provider/utils"
)

var ErrServerPortForwardNotSupported = errors.New("server does not support port forwarding")

// checkPortAvailable attempts to bind to a port to verify it's available.
// Returns a listener if the port is available, or an error if it's in use.
func checkPortAvailable(port uint16) (listener net.Listener, err error) {
	listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("port %d is in use: %w", port, err)
	}
	return listener, nil
}

// cleanupListeners closes all held internal port listeners.
func (p *Provider) cleanupListeners() {
	for _, ln := range p.internalListeners {
		if ln != nil {
			ln.Close()
		}
	}
	p.internalListeners = nil
}

// portMapping tracks a successful NAT-PMP mapping for cleanup purposes.
type portMapping struct {
	internalPort uint16
	externalPort uint16
}

// closeListener closes a listener if it's not nil.
func closeListener(ln net.Listener) {
	if ln != nil {
		ln.Close()
	}
}

// portChecker is a function that checks if a port is available for binding.
type portChecker func(port uint16) (listener net.Listener, err error)

// deletePortMapping removes a NAT-PMP port mapping for both TCP and UDP.
func deletePortMapping(ctx context.Context, client utils.PortForwardObjects, internalPort uint16) {
	client.NATClient.AddPortMapping(ctx, client.Gateway, "tcp", internalPort, 0, 0)
	client.NATClient.AddPortMapping(ctx, client.Gateway, "udp", internalPort, 0, 0)
}

// tryAssignPort attempts to assign a port with NAT-PMP and verify local availability.
// Returns listeners for internal and external ports if they're available, or an error explaining why it failed.
func tryAssignPort(
	ctx context.Context,
	client utils.PortForwardObjects,
	candidateInternal, candidateExternal uint16,
	lifetime time.Duration,
	logger utils.Logger,
	portNum uint8,
	attempt int,
	checkPort portChecker,
) (tcpInternal, tcpExternal, udpExternal uint16, internalLn, externalLn net.Listener, err error) {
	logger.Info(fmt.Sprintf("requesting port %d (attempt %d): internal=%d external=%d",
		portNum, attempt, candidateInternal, candidateExternal))

	// Request UDP mapping
	_, _, udpExternal, assignedLifetime, err := client.NATClient.AddPortMapping(
		ctx, client.Gateway, "udp", candidateInternal, candidateExternal, lifetime)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("UDP mapping failed: %w", err)
	}
	checkLifetime(logger, fmt.Sprintf("UDP %d", portNum), lifetime, assignedLifetime)

	// Request TCP mapping
	_, tcpInternal, tcpExternal, assignedLifetime, err = client.NATClient.AddPortMapping(
		ctx, client.Gateway, "tcp", candidateInternal, candidateExternal, lifetime)
	if err != nil {
		// Clean up UDP mapping
		deletePortMapping(ctx, client, candidateInternal)
		return 0, 0, 0, nil, nil, fmt.Errorf("TCP mapping failed: %w", err)
	}
	checkLifetime(logger, fmt.Sprintf("TCP %d", portNum), lifetime, assignedLifetime)
	checkExternalPorts(logger, udpExternal, tcpExternal)

	// Verify internal port is available
	internalLn, err = checkPort(tcpInternal)
	if err != nil {
		// Clean up both mappings
		deletePortMapping(ctx, client, tcpInternal)
		// Return assigned ports so caller can avoid retrying same ports
		return tcpInternal, tcpExternal, udpExternal, nil, nil, fmt.Errorf("internal port %d in use: %w", tcpInternal, err)
	}

	// Verify external port is available if asymmetrical
	if tcpInternal != tcpExternal {
		externalLn, err = checkPort(tcpExternal)
		if err != nil {
			internalLn.Close()
			deletePortMapping(ctx, client, tcpInternal)
			// Return assigned ports so caller can avoid retrying same ports
			return tcpInternal, tcpExternal, udpExternal, nil, nil, fmt.Errorf("external port %d in use: %w", tcpExternal, err)
		}
	}

	return tcpInternal, tcpExternal, udpExternal, internalLn, externalLn, nil
}

// PortForward obtains a VPN server side port forwarded from ProtonVPN gateway.
func (p *Provider) PortForward(ctx context.Context, objects utils.PortForwardObjects) (
	ports []uint16, err error,
) {
	if !objects.CanPortForward {
		return nil, ErrServerPortForwardNotSupported
	}

	// Clean up any existing internal port listeners from previous port forward sessions
	p.cleanupListeners()

	client := objects.NATClient
	_, externalIPv4Address, err := client.ExternalAddress(ctx,
		objects.Gateway)
	if err != nil {
		if strings.HasSuffix(err.Error(), "connection refused") {
			err = fmt.Errorf("%w - make sure you have +pmp at the end of your OpenVPN username", err)
		}
		return nil, fmt.Errorf("getting external IPv4 address: %w", err)
	}

	logger := objects.Logger

	logger.Info("gateway external IPv4 address is " + externalIPv4Address.String())
	const lifetime = 60 * time.Second

	numPorts := objects.NumPorts
	if numPorts < 1 || numPorts > 6 {
		return nil, fmt.Errorf("number of ports must be between 1 and 6, got %d", numPorts)
	}

	logger.Info(fmt.Sprintf("requesting %d port(s)", numPorts))
	ports = make([]uint16, 0, numPorts)

	// Use the port checker from the provider, or default to the real implementation
	checkPort := p.portChecker
	if checkPort == nil {
		checkPort = checkPortAvailable
	}

	// Track all created mappings for cleanup on error
	createdMappings := make([]portMapping, 0, numPorts*2) // TCP + UDP per port
	newListeners := make([]net.Listener, 0, numPorts)
	assignedInternalPorts := make([]uint16, 0, numPorts)

	// Cleanup helper - closes listeners and deletes NAT-PMP mappings
	cleanup := func() {
		for _, ln := range newListeners {
			closeListener(ln)
		}
		for _, mapping := range createdMappings {
			deletePortMapping(ctx, objects, mapping.internalPort)
		}
	}

	// First port: request symmetrical mapping (internal=0, external=0 for automatic)
	// Note: This may or may not result in a symmetrical mapping
	const maxPortAttempts = 20
	var firstInternal, firstExternal, firstUDPExternal uint16
	var firstPortListener, externalListener net.Listener

	// Track ports we've tried and failed to avoid requesting the same port repeatedly
	previouslyTriedPorts := make(map[uint16]bool)
	candidateInternal := uint16(0) // Start with automatic (0)

	firstPortAssigned := false
	for attempt := 0; attempt < maxPortAttempts; attempt++ {
		var err error
		firstInternal, firstExternal, firstUDPExternal,
			firstPortListener, externalListener, err = tryAssignPort(
			ctx, objects, candidateInternal, 0, lifetime, logger, 1, attempt+1, checkPort)
		if err != nil {
			logger.Warn(fmt.Sprintf("Port 1 attempt %d: %v", attempt+1, err))

			// If NAT-PMP assigned a port but it's unavailable locally, avoid it next time
			if firstInternal != 0 && !previouslyTriedPorts[firstInternal] {
				previouslyTriedPorts[firstInternal] = true
				// Request a different port explicitly instead of automatic (0)
				candidateInternal = firstInternal + 1
				// Skip any ports we've already tried
				for previouslyTriedPorts[candidateInternal] && candidateInternal < 65535 {
					candidateInternal++
				}
			}
			continue
		}

		// Success!
		firstPortAssigned = true
		createdMappings = append(createdMappings,
			portMapping{firstInternal, firstExternal},
			portMapping{firstInternal, firstUDPExternal})
		closeListener(externalListener) // Don't need to hold external
		break
	}

	if !firstPortAssigned {
		return nil, fmt.Errorf("failed to find available port for slot 1 after %d attempts", maxPortAttempts)
	}

	if firstInternal == firstExternal {
		logger.Info(fmt.Sprintf("port 1: %d (symmetrical, no redirect needed)", firstExternal))
		firstPortListener.Close() // User app needs it
	} else {
		logger.Info(fmt.Sprintf("port 1: internal=%d external=%d", firstInternal, firstExternal))

		// Set up iptables redirect for asymmetrical mapping
		if objects.PortAllower != nil {
			err := objects.PortAllower.RedirectPort(ctx, objects.Interface,
				firstInternal, firstExternal)
			if err != nil {
				firstPortListener.Close()
				cleanup()
				return nil, fmt.Errorf("redirecting port 1: %w", err)
			}
		} else {
			logger.Warn("cannot redirect port: PortAllower not provided")
		}

		// Asymmetrical - hold internal port
		newListeners = append(newListeners, firstPortListener)
	}

	ports = append(ports, firstExternal)
	assignedInternalPorts = append(assignedInternalPorts, firstInternal)

	// Additional ports: use high internal port numbers (50001, 50002, etc.)
	// These count toward the 5-port quota
	const baseInternalPort = 50001

	for i := uint8(1); i < numPorts; i++ {
		portNum := i + 1
		var internal, external, udpExternal uint16
		var internalListener, externalListener net.Listener

		portAssigned := false
		for attempt := 0; attempt < maxPortAttempts; attempt++ {
			// Calculate candidate internal port, spacing attempts to reduce collisions
			// Port 2: 50001, 50001+numPorts, 50001+numPorts*2, ...
			// Port 3: 50002, 50002+numPorts, 50002+numPorts*2, ...
			candidateInternal := baseInternalPort + uint16(i-1) + uint16(attempt)*uint16(numPorts)

			var err error
			internal, external, udpExternal,
				internalListener, externalListener, err = tryAssignPort(
				ctx, objects, candidateInternal, 0, lifetime, logger, portNum, attempt+1, checkPort)
			if err != nil {
				logger.Warn(fmt.Sprintf("Port %d attempt %d: %v", portNum, attempt+1, err))
				continue
			}

			// Success!
			portAssigned = true
			createdMappings = append(createdMappings,
				portMapping{internal, external},
				portMapping{internal, udpExternal})
			break
		}

		if !portAssigned {
			cleanup()
			return nil, fmt.Errorf("failed to find available port for slot %d after %d attempts", portNum, maxPortAttempts)
		}

		logger.Info(fmt.Sprintf("port %d: internal=%d external=%d", portNum, internal, external))
		assignedInternalPorts = append(assignedInternalPorts, internal)

		// Set up iptables redirect and manage listeners
		if internal != external {
			// Asymmetrical mapping: hold internal port, release external port
			logger.Info(fmt.Sprintf("redirecting %d -> %d", internal, external))

			if objects.PortAllower != nil {
				err := objects.PortAllower.RedirectPort(ctx, objects.Interface,
					internal, external)
				if err != nil {
					closeListener(internalListener)
					closeListener(externalListener)
					cleanup()
					return nil, fmt.Errorf("redirecting port %d: %w", portNum, err)
				}
			} else {
				logger.Warn("cannot redirect port: PortAllower not provided")
			}

			// Hold internal port listener to prevent other services from using it
			newListeners = append(newListeners, internalListener)
			closeListener(externalListener) // Close external port - user app needs it
		} else {
			// Symmetrical mapping: can't hold the port, user needs it
			closeListener(internalListener)
		}

		ports = append(ports, external)
	}

	// Store listeners and port information in provider to keep them alive
	p.internalListeners = newListeners
	p.portsForwarded = ports
	p.internalPorts = assignedInternalPorts

	logger.Info(fmt.Sprintf("ports forwarded are %v", ports))

	return ports, nil
}

func checkLifetime(logger utils.Logger, protocol string,
	requested, actual time.Duration,
) {
	if requested != actual {
		logger.Warn(fmt.Sprintf("assigned %s port lifetime %s differs"+
			" from requested lifetime %s", strings.ToUpper(protocol),
			actual, requested))
	}
}

func checkExternalPorts(logger utils.Logger, udpPort, tcpPort uint16) {
	if udpPort != tcpPort {
		logger.Warn(fmt.Sprintf("UDP external port %d differs from TCP external port %d",
			udpPort, tcpPort))
	}
}

var ErrExternalPortChanged = errors.New("external port changed")

func (p *Provider) KeepPortForward(ctx context.Context,
	objects utils.PortForwardObjects,
) (err error) {
	client := objects.NATClient
	refreshTimeout := p.keepPortRefreshTimeout
	if refreshTimeout == 0 {
		refreshTimeout = 45 * time.Second
	}
	timer := time.NewTimer(refreshTimeout)
	logger := objects.Logger
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}

		logger.Debug("refreshing port forwards since 45 seconds have elapsed")
		const lifetime = 60 * time.Second

		// Refresh all ports using the tracked internal ports from PortForward
		for i, externalPort := range p.portsForwarded {
			internalPort := p.internalPorts[i]

			for _, protocol := range []string{"udp", "tcp"} {
				_, _, assignedExternalPort, assignedLifetime, err := client.AddPortMapping(
					ctx, objects.Gateway, protocol, internalPort, externalPort, lifetime)
				if err != nil {
					return fmt.Errorf("adding port mapping %d: %w", i+1, err)
				}

				checkLifetime(logger, protocol, lifetime, assignedLifetime)

				if externalPort != assignedExternalPort {
					return fmt.Errorf("%w: port %d %d changed to %d",
						ErrExternalPortChanged, i+1, externalPort, assignedExternalPort)
				}
			}
		}

		logger.Debug(fmt.Sprintf("ports forwarded %v maintained", p.portsForwarded))

		timer.Reset(refreshTimeout)
	}
}
