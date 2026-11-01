package profile

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Mode string

const (
	ModeDirect Mode = "direct"
	ModeProxy Mode = "proxy"
	ModeSSL Mode = "ssl"
	ModePayloadSSL Mode = "payload+ssl"
)

type Profile struct {
	Name string `json:"name,omitempty"`
	LocalSocksPort uint16 `json:"localSocksPort,omitempty"`
	Mode Mode `json:"mode"`
	Host string `json:"host"`
	Port uint16 `json:"port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	ProxyHost string `json:"proxyHost,omitempty"`
	ProxyPort uint16 `json:"proxyPort,omitempty"`
	SNI string `json:"sni,omitempty"`
	Payload string `json:"payload,omitempty"`
	AcceptAnyStatus bool `json:"acceptAnyStatus"`
	VerifyTLS bool `json:"verifyTls"`
	TLSFingerprint string `json:"tlsFingerprint,omitempty"`
	HostKeySHA256 string `json:"hostKeySha256,omitempty"`
	DisableDelaySSH bool `json:"disableDelaySSH"`
	KeepAliveSeconds int `json:"keepAliveSeconds,omitempty"`
	UDPForward bool `json:"udpForward"`
	UDPResolver string `json:"udpResolver"`
	DNSForward bool `json:"dnsForward"`
	DNSResolver string `json:"dnsResolver"`
	ExcludeIPs []string `json:"excludeIps,omitempty"`
	EnableFilterApps bool `json:"enableFilterApps"`
	FilterBypassMode bool `json:"filterBypassMode"`
	FilterApps []string `json:"filterApps,omitempty"`
	TetheringSubnet bool `json:"tetheringSubnet"`
	BlockRoot bool `json:"blockRoot,omitempty"`
	AntiVpnSniffer bool `json:"antiVpnSniffer"`
	ConnectTimeout time.Duration `json:"connectTimeout,omitempty"`
}

func ParseJSON(raw string)(Profile,error){
	var p Profile
	if len(raw) > 1<<20 { return p, errors.New("profile JSON exceeds 1 MiB") }
	if err:=json.Unmarshal([]byte(raw),&p);err!=nil{return p,fmt.Errorf("decode profile: %w",err)}
	var fields map[string]json.RawMessage
	if err:=json.Unmarshal([]byte(raw),&fields);err!=nil{return p,err}
	if p.Mode==""{p.Mode=ModeDirect}
	if _,ok:=fields["localSocksPort"];!ok{p.LocalSocksPort=1080}
	if p.LocalSocksPort==0{p.LocalSocksPort=1080}
	if _,ok:=fields["keepAliveSeconds"];!ok{p.KeepAliveSeconds=3}
	if _,ok:=fields["acceptAnyStatus"];!ok{p.AcceptAnyStatus=true}
	if _,ok:=fields["disableDelaySSH"];!ok{p.DisableDelaySSH=true}
	if _,ok:=fields["udpForward"];!ok{p.UDPForward=true}
	if _,ok:=fields["udpResolver"];!ok{p.UDPResolver="127.0.0.1:7300"}
	if _,ok:=fields["dnsForward"];!ok{p.DNSForward=true}
	if _,ok:=fields["dnsResolver"];!ok{p.DNSResolver="1.1.1.1"}
	return p,p.Validate()
}

func ParseURI(raw string)(Profile,error){
	if len(raw) > 1<<20 { return Profile{}, errors.New("SSH URI exceeds 1 MiB") }
	u,err:=url.Parse(raw);if err!=nil{return Profile{},err}
	if u.Scheme!="ssh"{return Profile{},errors.New("unsupported URI scheme")}
	port:=u.Port();if port==""{port="22"}
	n,err:=strconv.ParseUint(port,10,16);if err!=nil||n==0{return Profile{},errors.New("invalid SSH port")}
	p:=Profile{Mode:ModeDirect,Host:u.Hostname(),Port:uint16(n),LocalSocksPort:1080,KeepAliveSeconds:3,AcceptAnyStatus:true,DisableDelaySSH:true,UDPForward:true,UDPResolver:"127.0.0.1:7300",DNSForward:true,DNSResolver:"1.1.1.1"}
	if u.User!=nil{p.Username=u.User.Username();p.Password,_=u.User.Password()}
	q:=u.Query()
	if q.Get("mode")!=""{p.Mode=Mode(q.Get("mode"))}
	p.SNI=q.Get("sni");p.Payload=q.Get("payload");p.ProxyHost=q.Get("proxyHost")
	if v:=q.Get("proxyPort");v!=""{x,e:=strconv.ParseUint(v,10,16);if e!=nil||x==0{return p,errors.New("invalid proxy port")};p.ProxyPort=uint16(x)}
	if v:=q.Get("localSocksPort");v!=""{x,e:=strconv.ParseUint(v,10,16);if e!=nil||x==0{return p,errors.New("invalid local SOCKS port")};p.LocalSocksPort=uint16(x)}
	if v:=q.Get("acceptAnyStatus");v!=""{p.AcceptAnyStatus=v!="false"}
	p.VerifyTLS=q.Get("verifyTls")=="true";p.TLSFingerprint=q.Get("tlsFingerprint");p.HostKeySHA256=q.Get("hostKeySha256")
	if v:=q.Get("disableDelaySSH");v!=""{p.DisableDelaySSH=v!="false"}
	if v:=q.Get("keepalive");v!=""{x,e:=strconv.Atoi(v);if e!=nil{return p,errors.New("invalid keepalive")};p.KeepAliveSeconds=x}
	if v:=q.Get("udp");v!=""{p.UDPForward=v!="false"}
	if v:=q.Get("udpResolver");v!=""{p.UDPResolver=v}
	if v:=q.Get("dns");v!=""{p.DNSForward=v!="false"}
	if v:=q.Get("dnsResolver");v!=""{p.DNSResolver=v}
	p.Name=u.Fragment
	return p,p.Validate()
}

func(p Profile)Validate()error{
	if p.Mode==""{p.Mode=ModeDirect}
	switch p.Mode{case ModeDirect,ModeProxy,ModeSSL,ModePayloadSSL:default:return fmt.Errorf("unsupported tunnel mode %q",p.Mode)}
	if p.Host==""{return errors.New("SSH host is required")}
	if strings.ContainsAny(p.Host," /\\"){return errors.New("invalid SSH host")}
	if net.ParseIP(p.Host)==nil&&strings.Contains(p.Host,":"){return errors.New("invalid SSH host")}
	if p.Port==0{return errors.New("SSH port is required")}
	if p.Username==""{return errors.New("SSH username is required")}
	if p.Password==""&&p.PrivateKey==""{return errors.New("SSH password or private key is required")}
	if p.Mode==ModeProxy&&(p.ProxyHost==""||p.ProxyPort==0){return errors.New("proxy host and port are required for proxy mode")}
	if p.KeepAliveSeconds<0||p.KeepAliveSeconds>3600{return errors.New("keepalive must be between 0 and 3600 seconds")}
	if p.UDPForward || p.DNSForward {
		host,port,err:=net.SplitHostPort(p.UDPResolver);if err!=nil||host==""{return errors.New("invalid UDPGW resolver endpoint")}
		n,e:=strconv.Atoi(port);if e!=nil||n<1||n>65535{return errors.New("invalid UDPGW resolver port")}
	}
	if p.DNSResolver != "" {
		dnsIP := net.ParseIP(p.DNSResolver)
		if dnsIP == nil || dnsIP.To4() == nil { return errors.New("DNS resolver must be an IPv4 address") }
	}
	if p.TLSFingerprint != "" {
		fingerprint := strings.ReplaceAll(p.TLSFingerprint, ":", "")
		decoded, err := hex.DecodeString(fingerprint)
		if err != nil || len(decoded) != sha256.Size { return errors.New("invalid TLS SHA-256 fingerprint") }
	}
	if p.EnableFilterApps && len(p.FilterApps) == 0 { return errors.New("app filtering requires at least one package") }
	for _, app := range p.FilterApps {
		if strings.TrimSpace(app) == "" || strings.ContainsAny(app, " /\\") { return errors.New("invalid app package in filter list") }
	}
	for _, ip := range p.ExcludeIPs {
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if parsed == nil || parsed.To4() == nil { return fmt.Errorf("invalid excluded IPv4 address %q", ip) }
	}
	if p.HostKeySHA256 != "" {
		fingerprint := strings.TrimPrefix(p.HostKeySHA256, "SHA256:")
		decoded, err := base64.RawStdEncoding.DecodeString(fingerprint)
		if err != nil || len(decoded) != sha256.Size { return errors.New("invalid SSH host-key SHA-256 fingerprint") }
	}
	return nil
}
