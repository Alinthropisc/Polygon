//go:build !linux

package attack

func (l *Layer4) syn()              {}
func (l *Layer4) icmp()             {}
func (l *Layer4) amp(_ []byte, _ uint16) {}
func (l *Layer4) ovhudp()           {}
