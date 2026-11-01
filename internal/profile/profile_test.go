package profile

import "testing"

func TestAcceptAnyStatusDefaultsTrue(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u"}`)
	if err!=nil{t.Fatal(err)}
	if !p.AcceptAnyStatus{t.Fatal("acceptAnyStatus should default true")}
}

func TestAcceptAnyStatusCanBeDisabled(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","acceptAnyStatus":false}`)
	if err!=nil{t.Fatal(err)}
	if p.AcceptAnyStatus{t.Fatal("explicit false ignored")}
}

func TestUDPAndDNSDefaultsMatchLegacy(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u"}`)
	if err!=nil{t.Fatal(err)}
	if !p.UDPForward||p.UDPResolver!="127.0.0.1:7300"{t.Fatalf("UDP defaults: enabled=%v resolver=%q",p.UDPForward,p.UDPResolver)}
	if !p.DNSForward||p.DNSResolver!="1.1.1.1"{t.Fatalf("DNS defaults: enabled=%v resolver=%q",p.DNSForward,p.DNSResolver)}
}

func TestSSLModeDoesNotRequireProxy(t *testing.T){
	p:=Profile{Mode:ModeSSL,Host:"ssh.example",Port:443,Username:"u"}
	if err:=p.Validate();err!=nil{t.Fatal(err)}
}

func TestPayloadSSLModeDoesNotRequireProxy(t *testing.T){
	p:=Profile{Mode:ModePayloadSSL,Host:"ssh.example",Port:443,Username:"u"}
	if err:=p.Validate();err!=nil{t.Fatal(err)}
}

func TestProxyModeRequiresProxyEndpoint(t *testing.T){
	p:=Profile{Mode:ModeProxy,Host:"ssh.example",Port:22,Username:"u"}
	if err:=p.Validate();err==nil{t.Fatal("expected proxy endpoint validation")}
}

func TestSSHURIImport(t *testing.T) {
	p,err:=ParseURI("ssh://user:pass@ssh.example.test:2222?mode=proxy&proxyHost=proxy.example.test&proxyPort=8080&sni=front.example.test&acceptAnyStatus=true#test")
	if err!=nil{t.Fatal(err)}
	if p.Host!="ssh.example.test"||p.Port!=2222||p.Username!="user"||p.Password!="pass"||p.Mode!=ModeProxy||p.ProxyHost!="proxy.example.test"||p.ProxyPort!=8080||p.SNI!="front.example.test"||p.Name!="test"{t.Fatalf("unexpected profile: %+v",p)}
}

func TestJSONDefaultsTCPNoDelayToLegacySetting(t *testing.T) {
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u"}`)
	if err!=nil{t.Fatal(err)}
	if !p.DisableDelaySSH{t.Fatal("legacy TCP_NODELAY default should be enabled")}
}

func TestLocalSocksPortDefaultsToLegacy(t *testing.T) {
	p, err := ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u"}`)
	if err != nil { t.Fatal(err) }
	if p.LocalSocksPort != 1080 { t.Fatalf("local SOCKS port=%d, want 1080", p.LocalSocksPort) }
}

func TestSSHURIImportsLocalSocksPort(t *testing.T) {
	p, err := ParseURI("ssh://user:pass@ssh.example.test:22?localSocksPort=2080")
	if err != nil { t.Fatal(err) }
	if p.LocalSocksPort != 2080 { t.Fatalf("local SOCKS port=%d, want 2080", p.LocalSocksPort) }
}

func TestKeepAliveDefaultsToLegacyThreeSeconds(t *testing.T) {
	p, err := ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u"}`)
	if err != nil { t.Fatal(err) }
	if p.KeepAliveSeconds != 3 { t.Fatalf("keepalive=%d, want 3", p.KeepAliveSeconds) }
}

func TestKeepAliveCanBeDisabledExplicitly(t *testing.T) {
	p, err := ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","keepAliveSeconds":0}`)
	if err != nil { t.Fatal(err) }
	if p.KeepAliveSeconds != 0 { t.Fatalf("keepalive=%d, want 0", p.KeepAliveSeconds) }
}

func TestSSHURIUsesLegacyDefaults(t *testing.T) {
	p, err := ParseURI("ssh://user:pass@ssh.example.test:22")
	if err != nil { t.Fatal(err) }
	if p.LocalSocksPort != 1080 || p.KeepAliveSeconds != 3 || !p.DisableDelaySSH || !p.UDPForward || !p.DNSForward {
		t.Fatalf("legacy defaults not preserved: %+v", p)
	}
}

func TestDNSOnlyForwardingRequiresUDPGWEndpoint(t *testing.T) {
	p := Profile{
		Mode: ModeDirect, Host: "ssh.example", Port: 22, Username: "u",
		DNSForward: true, UDPForward: false, UDPResolver: "invalid",
		DNSResolver: "1.1.1.1",
	}
	if err := p.Validate(); err == nil { t.Fatal("DNS-only forwarding accepted an invalid UDPGW endpoint") }
}
