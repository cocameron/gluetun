package protonvpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/provider/utils"
	"github.com/stretchr/testify/assert"
)

const (
	testExternalIP = "185.98.171.188"
	testGatewayIP  = "10.2.0.1"
)

func testGateway() netip.Addr {
	return netip.MustParseAddr(testGatewayIP)
}

func testExternalAddr() netip.Addr {
	return netip.MustParseAddr(testExternalIP)
}

type mockLogger struct {
	messages []string
}

func (m *mockLogger) Info(s string) {
	m.messages = append(m.messages, "INFO: "+s)
}

func (m *mockLogger) Warn(s string) {
	m.messages = append(m.messages, "WARN: "+s)
}

func (m *mockLogger) Debug(s string) {
	m.messages = append(m.messages, "DEBUG: "+s)
}

func (m *mockLogger) Error(s string) {
	m.messages = append(m.messages, "ERROR: "+s)
}

// mockListener is a fake listener that doesn't actually bind to ports.
type mockListener struct {
	port uint16
}

func (m *mockListener) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockListener) Close() error {
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{Port: int(m.port)}
}

// mockPortChecker is a port checker that always succeeds without real binding.
func mockPortChecker(port uint16) (net.Listener, error) {
	return &mockListener{port: port}, nil
}

// mockPortCheckerWithBlocked returns a port checker that fails for specific ports.
func mockPortCheckerWithBlocked(blockedPorts map[uint16]bool) portChecker {
	return func(port uint16) (net.Listener, error) {
		if blockedPorts[port] {
			return nil, errors.New("port in use")
		}
		return &mockListener{port: port}, nil
	}
}

type mockPortAllower struct {
	redirects   []redirect
	failOnPort  uint16 // Fail when redirecting this source port (0 = never fail)
	redirectErr error  // Error to return when failing
}

type redirect struct {
	intf        string
	source      uint16
	destination uint16
}

func (m *mockPortAllower) RedirectPort(ctx context.Context, intf string, sourcePort, destinationPort uint16) error {
	if m.failOnPort != 0 && sourcePort == m.failOnPort {
		return m.redirectErr
	}
	m.redirects = append(m.redirects, redirect{
		intf:        intf,
		source:      sourcePort,
		destination: destinationPort,
	})
	return nil
}

type mockNATClient struct {
	externalAddress    netip.Addr
	externalAddressErr error
	callCount          int
	mappingFunc        func(protocol string, internalPort, externalPort uint16, callIndex int) (assignedInt, assignedExt uint16, err error)
}

var _ utils.NATPMPClient = (*mockNATClient)(nil)

func (m *mockNATClient) ExternalAddress(ctx context.Context, gateway netip.Addr) (
	time.Duration, netip.Addr, error) {
	if m.externalAddressErr != nil {
		return 0, netip.Addr{}, m.externalAddressErr
	}
	return 100 * time.Second, m.externalAddress, nil
}

func (m *mockNATClient) AddPortMapping(ctx context.Context, gateway netip.Addr,
	protocol string, internalPort, requestedExternalPort uint16,
	lifetime time.Duration) (time.Duration, uint16, uint16, time.Duration, error) {

	defer func() { m.callCount++ }()

	// Use custom function if provided, otherwise use sensible default
	if m.mappingFunc != nil {
		assignedInt, assignedExt, err := m.mappingFunc(protocol, internalPort, requestedExternalPort, m.callCount)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		return 100 * time.Second, assignedInt, assignedExt, lifetime, nil
	}

	// Default: echo back what was requested (symmetrical mappings)
	assignedInt := internalPort
	assignedExt := requestedExternalPort
	if requestedExternalPort == 0 {
		assignedExt = 40000 + uint16(m.callCount)*1000
	}
	if internalPort == 0 {
		assignedInt = assignedExt
	}

	return 100 * time.Second, assignedInt, assignedExt, lifetime, nil
}

func Test_Provider_PortForward(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		numPorts       uint8
		canPortForward bool
		natClient      *mockNATClient
		portAllower    *mockPortAllower
		portChecker    portChecker
		ports          []uint16
		redirectCount  int
		errMessage     string
	}{
		"server not supported": {
			numPorts:       2,
			canPortForward: false,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
			},
			errMessage: "server does not support port forwarding",
		},
		"external address failure": {
			numPorts:       1,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddressErr: errors.New("connection refused"),
			},
			errMessage: "getting external IPv4 address: connection refused - make sure you have +pmp at the end of your OpenVPN username",
		},
		"invalid num ports zero": {
			numPorts:       0,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
			},
			errMessage: "number of ports must be between 1 and 6, got 0",
		},
		"invalid num ports too many": {
			numPorts:       7,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
			},
			errMessage: "number of ports must be between 1 and 6, got 7",
		},
		"first port udp mapping fails": {
			numPorts:       1,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					if protocol == "udp" {
						return 0, 0, errors.New("NAT-PMP UDP mapping failed")
					}
					return 41340, 41340, nil
				},
			},
			errMessage: "failed to find available port for slot 1 after 20 attempts",
		},
		"first port tcp mapping fails": {
			numPorts:       1,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					if protocol == "tcp" {
						return 0, 0, errors.New("NAT-PMP TCP mapping failed")
					}
					return 41340, 41340, nil
				},
			},
			errMessage: "failed to find available port for slot 1 after 20 attempts",
		},
		"redirect port fails for first port": {
			numPorts:       1,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					return 50000, 45000, nil // Asymmetrical to trigger redirect
				},
			},
			portAllower: &mockPortAllower{
				failOnPort:  50000,
				redirectErr: errors.New("iptables failed"),
			},
			errMessage: "redirecting port 1: iptables failed",
		},
		"second port retry exhaustion": {
			numPorts:       2,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					// First port succeeds
					if callIndex < 2 {
						return 41340, 41340, nil
					}
					// Second port always fails
					return 0, 0, errors.New("NAT-PMP error")
				},
			},
			portAllower: &mockPortAllower{},
			errMessage:  "failed to find available port for slot 2 after 20 attempts",
		},
		"redirect port fails for second port": {
			numPorts:       2,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					if callIndex < 2 {
						return 41340, 41340, nil // First port symmetrical
					}
					return 50001, 44761, nil // Second port asymmetrical
				},
			},
			portAllower: &mockPortAllower{
				failOnPort:  50001,
				redirectErr: errors.New("iptables redirect failed"),
			},
			errMessage: "redirecting port 2: iptables redirect failed",
		},
		"first port retries with different ports": {
			numPorts:       1,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					// First attempt (internal=0): NAT-PMP assigns 41340
					if internalPort == 0 {
						return 41340, 41340, nil
					}
					// Second attempt: retry logic requests internal=41341 to avoid 41340
					if internalPort == 41341 {
						return 41341, 41341, nil
					}
					// Shouldn't reach here
					return internalPort, internalPort, nil
				},
			},
			portChecker: mockPortCheckerWithBlocked(map[uint16]bool{
				41340: true, // First assigned port is blocked locally
			}),
			ports: []uint16{41341}, // Should successfully get 41341 on second attempt
		},
		"one port symmetrical": {
			numPorts:       1,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					return 41340, 41340, nil // Symmetrical
				},
			},
			ports:         []uint16{41340},
			redirectCount: 0,
		},
		"two ports with redirect": {
			numPorts:       2,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					// First port (calls 0,1): symmetrical
					if callIndex < 2 {
						return 41340, 41340, nil
					}
					// Second port (calls 2,3): asymmetrical
					return 50001, 44761, nil
				},
			},
			portAllower:   &mockPortAllower{},
			ports:         []uint16{41340, 44761},
			redirectCount: 1,
		},
		"first port asymmetrical": {
			numPorts:       1,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					// Even first port is asymmetrical (internal != external)
					return 60000, 45000, nil
				},
			},
			portAllower:   &mockPortAllower{},
			ports:         []uint16{45000},
			redirectCount: 1,
		},
		"six ports maximum": {
			numPorts:       6,
			canPortForward: true,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					// Port 1 (calls 0,1): symmetrical
					if callIndex < 2 {
						return 41340, 41340, nil
					}
					// Ports 2-6 (calls 2-11): asymmetrical with different external ports
					portIndex := callIndex / 2
					internalPort = uint16(50001 + portIndex - 1)
					externalPort = uint16(44000 + (portIndex-1)*100)
					return internalPort, externalPort, nil
				},
			},
			portAllower:   &mockPortAllower{},
			ports:         []uint16{41340, 44000, 44100, 44200, 44300, 44400},
			redirectCount: 5,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Use custom port checker if provided, otherwise use default mock
			checker := testCase.portChecker
			if checker == nil {
				checker = mockPortChecker
			}

			provider := &Provider{
				portChecker: checker,
			}
			logger := &mockLogger{}

			objects := utils.PortForwardObjects{
				Logger:         logger,
				Gateway:        testGateway(),
				CanPortForward: testCase.canPortForward,
				NumPorts:       testCase.numPorts,
				NATClient:      testCase.natClient,
				PortAllower:    testCase.portAllower,
				Interface:      "tun0",
			}

			ports, err := provider.PortForward(context.Background(), objects)

			assert.Equal(t, testCase.ports, ports)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.ports, provider.portsForwarded)
				if testCase.portAllower != nil {
					assert.Len(t, testCase.portAllower.redirects, testCase.redirectCount)
				}
			}
		})
	}
}

func Test_tryAssignPort(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		candidateInternal uint16
		candidateExternal uint16
		natClient         *mockNATClient
		expectError       bool
		errorContains     string
		expectSymmetrical bool
	}{
		"symmetrical mapping success": {
			candidateInternal: 0,
			candidateExternal: 0,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					return 41340, 41340, nil
				},
			},
			expectSymmetrical: true,
		},
		"asymmetrical mapping success": {
			candidateInternal: 50001,
			candidateExternal: 0,
			natClient: &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
					return 50001, 44761, nil
				},
			},
			expectSymmetrical: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			logger := &mockLogger{}
			objects := utils.PortForwardObjects{
				Logger:    logger,
				Gateway:   testGateway(),
				NATClient: testCase.natClient,
			}

			tcpInt, tcpExt, udpExt, internalLn, externalLn, err := tryAssignPort(
				context.Background(),
				objects,
				testCase.candidateInternal,
				testCase.candidateExternal,
				60*time.Second,
				logger,
				1,
				1,
				mockPortChecker,
			)

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.errorContains != "" {
					assert.Contains(t, err.Error(), testCase.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotZero(t, tcpInt)
				assert.NotZero(t, tcpExt)
				assert.NotZero(t, udpExt)
				assert.NotNil(t, internalLn)

				// Cleanup
				closeListener(internalLn)
				closeListener(externalLn)

				if testCase.expectSymmetrical {
					assert.Equal(t, tcpInt, tcpExt)
					assert.Nil(t, externalLn)
				} else {
					assert.NotEqual(t, tcpInt, tcpExt)
					// externalLn may or may not be nil depending on whether external port was checked
				}
			}
		})
	}
}

func Test_Provider_PortForward_ListenerManagement(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		numPorts            uint8
		mappingFunc         func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error)
		expectedListeners   int
		expectedInternalIPs []uint16
	}{
		"one symmetrical port - no listeners held": {
			numPorts: 1,
			mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
				return 41340, 41340, nil
			},
			expectedListeners:   0,
			expectedInternalIPs: []uint16{41340},
		},
		"one asymmetrical port - one listener held": {
			numPorts: 1,
			mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
				return 50000, 41340, nil
			},
			expectedListeners:   1,
			expectedInternalIPs: []uint16{50000},
		},
		"two ports - one symmetrical one asymmetrical": {
			numPorts: 2,
			mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
				// First port (calls 0,1): symmetrical
				if callIndex < 2 {
					return 41340, 41340, nil
				}
				// Second port (calls 2,3): asymmetrical
				return 50001, 44000, nil
			},
			expectedListeners:   1, // Only asymmetrical port
			expectedInternalIPs: []uint16{41340, 50001},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider := &Provider{
				portChecker: mockPortChecker,
			}
			logger := &mockLogger{}
			portAllower := &mockPortAllower{}

			natClient := &mockNATClient{
				externalAddress: testExternalAddr(),
				mappingFunc:     testCase.mappingFunc,
			}

			objects := utils.PortForwardObjects{
				Logger:         logger,
				Gateway:        testGateway(),
				CanPortForward: true,
				NumPorts:       testCase.numPorts,
				NATClient:      natClient,
				PortAllower:    portAllower,
				Interface:      "tun0",
			}

			ports, err := provider.PortForward(context.Background(), objects)
			if err != nil {
				t.Fatalf("PortForward failed: %v\nLogger messages:\n%v", err, logger.messages)
			}
			assert.NoError(t, err)

			assert.Len(t, provider.internalListeners, testCase.expectedListeners,
				"should hold exactly %d listener(s)", testCase.expectedListeners)
			assert.Equal(t, testCase.expectedInternalIPs, provider.internalPorts,
				"internalPorts mismatch. Returned ports: %v, Logger: %v", ports, logger.messages)

			// Verify listeners are actually bound (non-nil)
			for i, ln := range provider.internalListeners {
				assert.NotNil(t, ln, "listener %d should not be nil", i)
			}
		})
	}
}

func Test_Provider_PortForward_CleanupListeners(t *testing.T) {
	t.Parallel()

	provider := &Provider{
		portChecker: mockPortChecker,
	}
	logger := &mockLogger{}
	portAllower := &mockPortAllower{}

	// First call: create asymmetrical mapping with listener
	natClient1 := &mockNATClient{
		externalAddress: testExternalAddr(),
		mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
			return 50000, 41340, nil // Asymmetrical
		},
	}

	objects1 := utils.PortForwardObjects{
		Logger:         logger,
		Gateway:        testGateway(),
		CanPortForward: true,
		NumPorts:       1,
		NATClient:      natClient1,
		PortAllower:    portAllower,
		Interface:      "tun0",
	}

	_, err := provider.PortForward(context.Background(), objects1)
	assert.NoError(t, err)
	assert.Len(t, provider.internalListeners, 1)

	// Second call: should clean up previous listeners
	natClient2 := &mockNATClient{
		externalAddress: testExternalAddr(),
		mappingFunc: func(protocol string, internalPort, externalPort uint16, callIndex int) (uint16, uint16, error) {
			return 41340, 41340, nil // Symmetrical
		},
	}

	objects2 := utils.PortForwardObjects{
		Logger:         logger,
		Gateway:        testGateway(),
		CanPortForward: true,
		NumPorts:       1,
		NATClient:      natClient2,
		PortAllower:    portAllower,
		Interface:      "tun0",
	}

	_, err = provider.PortForward(context.Background(), objects2)
	assert.NoError(t, err)

	// Symmetrical mapping doesn't hold listeners
	assert.Len(t, provider.internalListeners, 0)
}

func Test_Provider_KeepPortForward(t *testing.T) {
	t.Parallel()

	t.Run("maintains ports successfully", func(t *testing.T) {
		t.Parallel()

		provider := &Provider{
			portsForwarded:         []uint16{41340, 44000},
			internalPorts:          []uint16{41340, 50001},
			keepPortRefreshTimeout: 10 * time.Millisecond, // Fast refresh for testing
		}

		logger := &mockLogger{}
		natClient := &mockNATClient{
			externalAddress: testExternalAddr(),
		}

		objects := utils.PortForwardObjects{
			Logger:    logger,
			Gateway:   testGateway(),
			NATClient: natClient,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := provider.KeepPortForward(ctx, objects)

		// Should return context deadline exceeded (normal termination)
		assert.ErrorIs(t, err, context.DeadlineExceeded)

		// Should have called AddPortMapping to refresh ports
		// With 10ms refresh interval and 100ms timeout, should get ~10 refreshes
		// Each refresh: 2 ports * 2 protocols = 4 calls, so minimum 4 calls
		assert.GreaterOrEqual(t, natClient.callCount, 4)
	})

	t.Run("returns error when port changes", func(t *testing.T) {
		t.Parallel()

		provider := &Provider{
			portsForwarded:         []uint16{41340},
			internalPorts:          []uint16{41340},
			keepPortRefreshTimeout: 10 * time.Millisecond, // Fast refresh for testing
		}

		logger := &mockLogger{}
		callIndex := 0
		natClient := &mockNATClient{
			externalAddress: testExternalAddr(),
			mappingFunc: func(protocol string, internalPort, externalPort uint16, idx int) (uint16, uint16, error) {
				callIndex++
				// After first refresh cycle (2 calls: UDP + TCP), return different external port
				if callIndex > 2 {
					return internalPort, 65000, nil // Changed external port
				}
				return internalPort, externalPort, nil
			},
		}

		objects := utils.PortForwardObjects{
			Logger:    logger,
			Gateway:   testGateway(),
			NATClient: natClient,
		}

		ctx := context.Background()
		err := provider.KeepPortForward(ctx, objects)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrExternalPortChanged)
	})

	t.Run("context cancellation stops loop", func(t *testing.T) {
		t.Parallel()

		provider := &Provider{
			portsForwarded: []uint16{41340},
			internalPorts:  []uint16{41340},
		}

		logger := &mockLogger{}
		natClient := &mockNATClient{
			externalAddress: testExternalAddr(),
		}

		objects := utils.PortForwardObjects{
			Logger:    logger,
			Gateway:   testGateway(),
			NATClient: natClient,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := provider.KeepPortForward(ctx, objects)

		assert.ErrorIs(t, err, context.Canceled)
	})
}
