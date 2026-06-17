package attack

import "context"

// FloodStrategy is the Strategy interface — every L4/L7 method implements it.
// Adding a new method = registering one function, no switch needed.
type FloodStrategy interface {
	Execute(ctx context.Context)
}

// ---- L4 registry (Strategy + Registry pattern) ----

// l4Registry maps method name → bound method on *Layer4.
// Lookup is O(1); adding a method requires only one line here.
var l4Registry map[string]func(*Layer4)

func init() {
	l4Registry = map[string]func(*Layer4){
		"TCP":         (*Layer4).tcp,
		"UDP":         (*Layer4).udp,
		"SYN":         (*Layer4).syn,
		"ICMP":        (*Layer4).icmp,
		"VSE":         (*Layer4).vse,
		"TS3":         (*Layer4).ts3,
		"MCPE":        (*Layer4).mcpe,
		"FIVEM":       (*Layer4).fivem,
		"FIVEM-TOKEN": (*Layer4).fivemToken,
		"OVH-UDP":     (*Layer4).ovhudp,
		"MINECRAFT":   (*Layer4).minecraft,
		"MCBOT":       (*Layer4).mcbot,
		"CPS":         (*Layer4).cps,
		"CONNECTION":  (*Layer4).connection,
		// AMP methods share one handler; payload resolved inside amp()
		"MEM":   (*Layer4).ampDispatch,
		"NTP":   (*Layer4).ampDispatch,
		"DNS":   (*Layer4).ampDispatch,
		"RDP":   (*Layer4).ampDispatch,
		"CLDAP": (*Layer4).ampDispatch,
		"CHAR":  (*Layer4).ampDispatch,
		"ARD":   (*Layer4).ampDispatch,
	}
}

// l7Registry maps method name → bound method on *HttpFlood.
var l7Registry map[string]func(*HttpFlood)

func init() {
	l7Registry = map[string]func(*HttpFlood){
		"GET":        (*HttpFlood).get,
		"POST":       (*HttpFlood).post,
		"HEAD":       (*HttpFlood).head,
		"OVH":        (*HttpFlood).ovh,
		"STRESS":     (*HttpFlood).stress,
		"DYN":        (*HttpFlood).dyn,
		"SLOW":       (*HttpFlood).slow,
		"NULL":       (*HttpFlood).null,
		"COOKIE":     (*HttpFlood).cookie,
		"PPS":        (*HttpFlood).pps,
		"EVEN":       (*HttpFlood).even,
		"GSB":        (*HttpFlood).gsb,
		"BOT":        (*HttpFlood).bot,
		"APACHE":     (*HttpFlood).apache,
		"XMLRPC":     (*HttpFlood).xmlrpc,
		"CFB":        (*HttpFlood).bypass,
		"CFBUAM":     (*HttpFlood).bypass,
		"BYPASS":     (*HttpFlood).bypass,
		"DGB":        (*HttpFlood).bypass,
		"AVB":        (*HttpFlood).bypass,
		"TOR":        (*HttpFlood).tor,
		"RHEX":       (*HttpFlood).rhex,
		"STOMP":      (*HttpFlood).stomp,
		"DOWNLOADER": (*HttpFlood).downloader,
		"KILLER":     (*HttpFlood).killer,
		"BOMB":       (*HttpFlood).bypass,
	}
}
