package utils

import (
	"context"
	"net/http"
	"net/netip"
)

// PortForwardObjects contains fields that may or may not need to be set
// depending on the port forwarding provider code.
type PortForwardObjects struct {
	// Logger is a logger, used by both Private Internet Access and ProtonVPN.
	Logger Logger
	// Gateway is the VPN gateway IP address, used by Private Internet Access
	// and ProtonVPN.
	Gateway netip.Addr
	// InternalIP is the VPN internal IP address assigned, used by Perfect Privacy.
	InternalIP netip.Addr
	// Client is used to query the VPN gateway for Private Internet Access.
	Client *http.Client
	// ServerName is used by Private Internet Access for port forwarding.
	ServerName string
	// CanPortForward is used by Private Internet Access for port forwarding.
	CanPortForward bool
	// Username is used by Private Internet Access for port forwarding.
	Username string
	// Password is used by Private Internet Access for port forwarding.
	Password string
	// NumPorts is the number of ports to request (used by ProtonVPN, 1-6).
	NumPorts uint8
	// PortAllower provides firewall control for iptables redirects (used by ProtonVPN).
	PortAllower PortAllower
	// Interface is the VPN interface name (used by ProtonVPN for iptables).
	Interface string
}

// PortAllower provides methods to configure firewall rules for port forwarding.
type PortAllower interface {
	// RedirectPort sets up an iptables redirect from sourcePort to destinationPort.
	RedirectPort(ctx context.Context, intf string, sourcePort,
		destinationPort uint16) (err error)
}

type Routing interface {
	VPNLocalGatewayIP(vpnInterface string) (gateway netip.Addr, err error)
}
