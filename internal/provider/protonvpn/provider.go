package protonvpn

import (
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/protonvpn/updater"
)

type Provider struct {
	storage        common.Storage
	randSource     rand.Source
	common.Fetcher
	portsForwarded []uint16
	// internalPorts tracks the actual internal ports assigned by NAT-PMP.
	// These may differ from the requested ports due to retry logic when ports are in use.
	internalPorts []uint16
	// internalListeners holds net.Listener instances for internal ports
	// in asymmetrical port mappings to prevent other services from binding to them.
	// These listeners are not actively accepting connections; they exist only
	// to reserve the ports since iptables redirects traffic to the external port.
	// Note: No mutex needed because PortForward() completes before KeepPortForward()
	// starts, and KeepPortForward() is cancelled before the next PortForward() call.
	internalListeners []net.Listener
	// portChecker is used to verify port availability. If nil, defaults to checkPortAvailable.
	// This is primarily for testing to avoid real port binds.
	portChecker portChecker
	// keepPortRefreshTimeout is the interval between port refresh attempts.
	// If zero, defaults to 45 seconds. Primarily for testing.
	keepPortRefreshTimeout time.Duration
}

func New(storage common.Storage, randSource rand.Source,
	client *http.Client, updaterWarner common.Warner,
	email, password string,
) *Provider {
	return &Provider{
		storage:    storage,
		randSource: randSource,
		Fetcher:    updater.New(client, updaterWarner, email, password),
	}
}

func (p *Provider) Name() string {
	return providers.Protonvpn
}
