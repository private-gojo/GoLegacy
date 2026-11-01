package profile

import ("testing"; "strings")

func TestAcceptAnyStatusDefaultsTrue(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p"}`)
	if err!=nil{t.Fatal(err)}
	if !p.AcceptAnyStatus{t.Fatal("acceptAnyStatus should default true")}
}

func TestAcceptAnyStatusCanBeDisabled(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p","acceptAnyStatus":false}`)
	if err!=nil{t.Fatal(err)}
	if p.AcceptAnyStatus{t.Fatal("explicit false ignored")}
}

func TestUDPAndDNSDefaultsMatchLegacy(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p"}`)
	if err!=nil{t.Fatal(err)}
	if !p.UDPForward||p.UDPResolver!="127.0.0.1:7300"{t.Fatalf("UDP defaults: enabled=%v resolver=%q",p.UDPForward,p.UDPResolver)}
	if !p.DNSForward||p.DNSResolver!="1.1.1.1"{t.Fatalf("DNS defaults: enabled=%v resolver=%q",p.DNSForward,p.DNSResolver)}
}

func TestSSLModeDoesNotRequireProxy(t *testing.T){
	p:=Profile{Mode:ModeSSL,Host:"ssh.example",Port:443,Username:"u",Password:"p"}
	if err:=p.Validate();err!=nil{t.Fatal(err)}
}

func TestPayloadSSLModeDoesNotRequireProxy(t *testing.T){
	p:=Profile{Mode:ModePayloadSSL,Host:"ssh.example",Port:443,Username:"u",Password:"p",Payload:"CONNECT [host_port] [protocol][crlf][crlf]"}
	if err:=p.Validate();err!=nil{t.Fatal(err)}
}

func TestProxyModeRequiresProxyEndpoint(t *testing.T){
	p:=Profile{Mode:ModeProxy,Host:"ssh.example",Port:22,Username:"u",Password:"p"}
	if err:=p.Validate();err==nil{t.Fatal("expected proxy endpoint validation")}
}

func TestSSHURIImport(t *testing.T) {
	p,err:=ParseURI("ssh://user:pass@ssh.example.test:2222?mode=proxy&proxyHost=proxy.example.test&proxyPort=8080&sni=front.example.test&acceptAnyStatus=true#test")
	if err!=nil{t.Fatal(err)}
	if p.Host!="ssh.example.test"||p.Port!=2222||p.Username!="user"||p.Password!="pass"||p.Mode!=ModeProxy||p.ProxyHost!="proxy.example.test"||p.ProxyPort!=8080||p.SNI!="front.example.test"||p.Name!="test"{t.Fatalf("unexpected profile: %+v",p)}
}

func TestJSONDefaultsTCPNoDelayToLegacySetting(t *testing.T) {
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p"}`)
	if err!=nil{t.Fatal(err)}
	if !p.DisableDelaySSH{t.Fatal("legacy TCP_NODELAY default should be enabled")}
}

func TestLocalSocksPortDefaultsToLegacy(t *testing.T) {
	p, err := ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p"}`)
	if err != nil { t.Fatal(err) }
	if p.LocalSocksPort != 1080 { t.Fatalf("local SOCKS port=%d, want 1080", p.LocalSocksPort) }
}

func TestSSHURIImportsLocalSocksPort(t *testing.T) {
	p, err := ParseURI("ssh://user:pass@ssh.example.test:22?localSocksPort=2080")
	if err != nil { t.Fatal(err) }
	if p.LocalSocksPort != 2080 { t.Fatalf("local SOCKS port=%d, want 2080", p.LocalSocksPort) }
}

func TestKeepAliveDefaultsToLegacyThreeSeconds(t *testing.T) {
	p, err := ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p"}`)
	if err != nil { t.Fatal(err) }
	if p.KeepAliveSeconds != 3 { t.Fatalf("keepalive=%d, want 3", p.KeepAliveSeconds) }
}

func TestKeepAliveCanBeDisabledExplicitly(t *testing.T) {
	p, err := ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p","keepAliveSeconds":0}`)
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
		Password: "p", DNSForward: true, UDPForward: false, UDPResolver: "invalid",
		DNSResolver: "1.1.1.1",
	}
	if err := p.Validate(); err == nil { t.Fatal("DNS-only forwarding accepted an invalid UDPGW endpoint") }
}

func TestProfileRequiresAuthentication(t *testing.T) {
	p := Profile{Mode: ModeDirect, Host: "ssh.example", Port: 22, Username: "u"}
	if err := p.Validate(); err == nil { t.Fatal("profile without SSH authentication was accepted") }
}

func TestProfileRejectsInvalidTLSFingerprint(t *testing.T) {
	p := Profile{Mode: ModeDirect, Host: "ssh.example", Port: 22, Username: "u", Password: "p", TLSFingerprint: "not-a-fingerprint"}
	if err := p.Validate(); err == nil { t.Fatal("invalid TLS fingerprint was accepted") }
}

func TestProfileRejectsInvalidHostKeyFingerprint(t *testing.T) {
	p := Profile{Mode: ModeDirect, Host: "ssh.example", Port: 22, Username: "u", Password: "p", HostKeySHA256: "SHA256:invalid"}
	if err := p.Validate(); err == nil { t.Fatal("invalid SSH host-key fingerprint was accepted") }
}

func TestProfileJSONSizeLimit(t *testing.T) {
	raw := strings.Repeat("x", (1<<20)+1)
	if _, err := ParseJSON(raw); err == nil { t.Fatal("oversized profile JSON was accepted") }
}

func TestAppFilterRequiresPackages(t *testing.T) {
	p := Profile{Mode: ModeDirect, Host: "ssh.example", Port: 22, Username: "u", Password: "p", EnableFilterApps: true}
	if err := p.Validate(); err == nil { t.Fatal("empty app filter was accepted") }
}

func TestRouteExclusionsRequireIPv4(t *testing.T) {
	p := Profile{Mode: ModeDirect, Host: "ssh.example", Port: 22, Username: "u", Password: "p", ExcludeIPs: []string{"2001:db8::1"}}
	if err := p.Validate(); err == nil { t.Fatal("IPv6 address accepted in IPv4 exclusion list") }
}

func TestSSHTimeoutsMatchLegacyDefaults(t *testing.T) {
	p, err := ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","password":"p"}`)
	if err != nil { t.Fatal(err) }
	if p.ConnectTimeoutMs != 10000 || p.HandshakeTimeoutMs != 20000 {
		t.Fatalf("timeouts connect=%d handshake=%d", p.ConnectTimeoutMs, p.HandshakeTimeoutMs)
	}
}

func TestSSHURIImportsProxyCredentials(t *testing.T) {
	p, err := ParseURI("ssh://user:pass@ssh.example.test:22?mode=proxy&proxyHost=proxy.example.test&proxyPort=8080&proxyUsername=proxy-user&proxyPassword=proxy-pass")
	if err != nil { t.Fatal(err) }
	if p.ProxyUsername != "proxy-user" || p.ProxyPassword != "proxy-pass" {
		t.Fatalf("proxy credentials not imported: %+v", p)
	}
}
