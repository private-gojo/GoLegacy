package profile

import (
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
	ConnectTimeout time.Duration `json:"connectTimeout,omitempty"`
}

func ParseJSON(raw string)(Profile,error){
	var p Profile
	if err:=json.Unmarshal([]byte(raw),&p);err!=nil{return p,fmt.Errorf("decode profile: %w",err)}
	return p,p.Validate()
}

func ParseURI(raw string)(Profile,error){
	u,err:=url.Parse(raw);if err!=nil{return Profile{},err}
	if u.Scheme!="ssh"{return Profile{},errors.New("unsupported URI scheme")}
	port:=u.Port();if port==""{port="22"}
	n,err:=strconv.ParseUint(port,10,16);if err!=nil||n==0{return Profile{},errors.New("invalid SSH port")}
	p:=Profile{Mode:ModeDirect,Host:u.Hostname(),Port:uint16(n)}
	if u.User!=nil{p.Username=u.User.Username();p.Password,_=u.User.Password()}
	q:=u.Query()
	if q.Get("mode")!=""{p.Mode=Mode(q.Get("mode"))}
	p.SNI=q.Get("sni");p.Payload=q.Get("payload");p.ProxyHost=q.Get("proxyHost")
	if v:=q.Get("proxyPort");v!=""{x,e:=strconv.ParseUint(v,10,16);if e!=nil||x==0{return p,errors.New("invalid proxy port")};p.ProxyPort=uint16(x)}
	p.Name=u.Fragment
	return p,p.Validate()
}

func (p Profile) Validate()error{
	if p.Mode==""{p.Mode=ModeDirect}
	switch p.Mode{case ModeDirect,ModeProxy,ModeSSL,ModePayloadSSL:default:return fmt.Errorf("unsupported tunnel mode %q",p.Mode)}
	if p.Host==""{return errors.New("SSH host is required")}
	if strings.ContainsAny(p.Host," /\\"){return errors.New("invalid SSH host")}
	if net.ParseIP(p.Host)==nil&&strings.Contains(p.Host,":"){return errors.New("invalid SSH host")}
	if p.Port==0{return errors.New("SSH port is required")}
	if p.Username==""{return errors.New("SSH username is required")}
	if p.Mode==ModeProxy||p.Mode==ModeSSL||p.Mode==ModePayloadSSL{
		if p.ProxyHost==""||p.ProxyPort==0{return errors.New("proxy host and port are required for selected mode")}
	}
	if p.Mode==ModePayloadSSL&&p.Payload==""{return errors.New("payload is required for payload+ssl mode")}
	if p.KeepAliveSeconds<0||p.KeepAliveSeconds>3600{return errors.New("keepalive must be between 0 and 3600 seconds")}
	return nil
}
