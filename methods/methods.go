package methods

var Layer7 = map[string]bool{
	"CFB": true, "BYPASS": true, "GET": true, "POST": true, "OVH": true,
	"STRESS": true, "DYN": true, "SLOW": true, "HEAD": true, "NULL": true,
	"COOKIE": true, "PPS": true, "EVEN": true, "GSB": true, "DGB": true,
	"AVB": true, "CFBUAM": true, "APACHE": true, "XMLRPC": true, "BOT": true,
	"BOMB": true, "DOWNLOADER": true, "KILLER": true, "TOR": true,
	"RHEX": true, "STOMP": true,
}

var Layer4AMP = map[string]bool{
	"MEM": true, "NTP": true, "DNS": true, "ARD": true,
	"CLDAP": true, "CHAR": true, "RDP": true,
}

var Layer4 = func() map[string]bool {
	m := map[string]bool{
		"TCP": true, "UDP": true, "SYN": true, "VSE": true,
		"MINECRAFT": true, "MCBOT": true, "CONNECTION": true,
		"CPS": true, "FIVEM": true, "FIVEM-TOKEN": true,
		"TS3": true, "MCPE": true, "ICMP": true, "OVH-UDP": true,
	}
	for k := range Layer4AMP {
		m[k] = true
	}
	return m
}()

var All = func() map[string]bool {
	m := make(map[string]bool)
	for k := range Layer7 {
		m[k] = true
	}
	for k := range Layer4 {
		m[k] = true
	}
	return m
}()

func IsLayer7(method string) bool    { return Layer7[method] }
func IsLayer4(method string) bool    { return Layer4[method] }
func IsLayer4AMP(method string) bool { return Layer4AMP[method] }
func IsValid(method string) bool     { return All[method] }

// NeedsRawSocket returns true for methods that require CAP_NET_RAW.
func NeedsRawSocket(method string) bool {
	switch method {
	case "NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD", "SYN", "ICMP":
		return true
	}
	return false
}
