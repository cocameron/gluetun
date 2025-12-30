package protonvpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/natpmp"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

var ErrServerPortForwardNotSupported = errors.New("server does not support port forwarding")

// PortForward obtains a VPN server side port forwarded from ProtonVPN gateway.
func (p *Provider) PortForward(ctx context.Context, objects utils.PortForwardObjects) (
	ports []uint16, err error,
) {
	if !objects.CanPortForward {
		return nil, fmt.Errorf("%w", ErrServerPortForwardNotSupported)
	}

	client := natpmp.New()
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

	// First port: request symmetrical mapping (internal=0, external=0 for automatic)
	// This is the free port that doesn't count toward the 5-port quota
	const firstInternalPort, firstExternalPort = 0, 0
	logger.Info(fmt.Sprintf("requesting port 1 (symmetrical): internal=%d external=%d", firstInternalPort, firstExternalPort))

	_, _, assignedUDP1ExternalPort, assignedLifetime, err := client.AddPortMapping(ctx, objects.Gateway, "udp",
		firstInternalPort, firstExternalPort, lifetime)
	if err != nil {
		return nil, fmt.Errorf("adding UDP port mapping 1: %w", err)
	}
	checkLifetime(logger, "UDP 1", lifetime, assignedLifetime)

	_, assignedTCP1InternalPort, assignedTCP1ExternalPort, assignedLifetime, err := client.AddPortMapping(ctx, objects.Gateway, "tcp",
		firstInternalPort, firstExternalPort, lifetime)
	if err != nil {
		return nil, fmt.Errorf("adding TCP port mapping 1: %w", err)
	}
	checkLifetime(logger, "TCP 1", lifetime, assignedLifetime)

	if assignedTCP1InternalPort == assignedTCP1ExternalPort {
		logger.Info(fmt.Sprintf("port 1: %d (symmetrical, no redirect needed)", assignedTCP1ExternalPort))
	} else {
		logger.Info(fmt.Sprintf("port 1: internal=%d external=%d", assignedTCP1InternalPort, assignedTCP1ExternalPort))
	}
	checkExternalPorts(logger, assignedUDP1ExternalPort, assignedTCP1ExternalPort)
	ports = append(ports, assignedTCP1ExternalPort)

	// Additional ports: use high internal port numbers (50001, 50002, etc.)
	// These count toward the 5-port quota
	const baseInternalPort = 50001
	for i := uint8(1); i < numPorts; i++ {
		portNum := i + 1
		internalPort := uint16(baseInternalPort + uint16(i-1))
		const externalPort = 0 // automatic assignment

		logger.Info(fmt.Sprintf("requesting port %d: internal=%d external=%d", portNum, internalPort, externalPort))

		_, _, assignedUDPExternalPort, assignedLifetime, err := client.AddPortMapping(ctx, objects.Gateway, "udp",
			internalPort, externalPort, lifetime)
		if err != nil {
			return nil, fmt.Errorf("adding UDP port mapping %d: %w", portNum, err)
		}
		checkLifetime(logger, fmt.Sprintf("UDP %d", portNum), lifetime, assignedLifetime)

		_, assignedTCPInternalPort, assignedTCPExternalPort, assignedLifetime, err := client.AddPortMapping(ctx, objects.Gateway, "tcp",
			internalPort, externalPort, lifetime)
		if err != nil {
			return nil, fmt.Errorf("adding TCP port mapping %d: %w", portNum, err)
		}
		checkLifetime(logger, fmt.Sprintf("TCP %d", portNum), lifetime, assignedLifetime)

		logger.Info(fmt.Sprintf("port %d: internal=%d external=%d", portNum, assignedTCPInternalPort, assignedTCPExternalPort))
		checkExternalPorts(logger, assignedUDPExternalPort, assignedTCPExternalPort)

		// Set up iptables redirect if internal != external
		if assignedTCPInternalPort != assignedTCPExternalPort {
			logger.Info(fmt.Sprintf("setting up iptables redirect %d -> %d", assignedTCPInternalPort, assignedTCPExternalPort))
			if objects.PortAllower != nil {
				err := objects.PortAllower.RedirectPort(ctx, objects.Interface,
					assignedTCPInternalPort, assignedTCPExternalPort)
				if err != nil {
					return nil, fmt.Errorf("redirecting port %d: %w", portNum, err)
				}
			} else {
				logger.Warn("cannot redirect port: PortAllower not provided")
			}
		}

		ports = append(ports, assignedTCPExternalPort)
	}

	p.portsForwarded = ports
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
	client := natpmp.New()
	const refreshTimeout = 45 * time.Second
	timer := time.NewTimer(refreshTimeout)
	logger := objects.Logger
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}

		objects.Logger.Debug("refreshing port forwards since 45 seconds have elapsed")
		networkProtocols := []string{"udp", "tcp"}
		const lifetime = 60 * time.Second

		// Refresh first port (symmetrical, internal=0)
		const firstInternalPort = 0
		for _, networkProtocol := range networkProtocols {
			_, _, assignedExternalPort, assignedLiftetime, err := client.AddPortMapping(ctx, objects.Gateway, networkProtocol,
				firstInternalPort, p.portsForwarded[0], lifetime)
			if err != nil {
				return fmt.Errorf("adding port mapping 1: %w", err)
			}

			if assignedLiftetime != lifetime {
				logger.Warn(fmt.Sprintf("assigned lifetime %s differs"+
					" from requested lifetime %s",
					assignedLiftetime, lifetime))
			}

			if p.portsForwarded[0] != assignedExternalPort {
				return fmt.Errorf("%w: port 1 %d changed to %d",
					ErrExternalPortChanged, p.portsForwarded[0], assignedExternalPort)
			}
		}

		// Refresh additional ports (use same internal ports as initial request)
		const baseInternalPort = 50001
		for i := 1; i < len(p.portsForwarded); i++ {
			internalPort := uint16(baseInternalPort + uint16(i-1))
			for _, networkProtocol := range networkProtocols {
				_, _, assignedExternalPort, assignedLiftetime, err := client.AddPortMapping(ctx, objects.Gateway, networkProtocol,
					internalPort, p.portsForwarded[i], lifetime)
				if err != nil {
					return fmt.Errorf("adding port mapping %d: %w", i+1, err)
				}

				if assignedLiftetime != lifetime {
					logger.Warn(fmt.Sprintf("assigned lifetime %s differs"+
						" from requested lifetime %s",
						assignedLiftetime, lifetime))
				}

				if p.portsForwarded[i] != assignedExternalPort {
					return fmt.Errorf("%w: port %d %d changed to %d",
						ErrExternalPortChanged, i+1, p.portsForwarded[i], assignedExternalPort)
				}
			}
		}

		objects.Logger.Debug(fmt.Sprintf("ports forwarded %v maintained", p.portsForwarded))

		timer.Reset(refreshTimeout)
	}
}
