package mobile

import (
	"sync"
	"errors"
	"encoding/json"
	"net"
	"strconv"
	"time"

	"dev.go.core/internal/config"

	"dev.go.core/internal/payload"
	"dev.go.core/internal/profile"
	"dev.go.core/internal/socks5"
	"dev.go.core/internal/sshclient"
	"dev.go.core/internal/udpgw"
)

type SocketProtector interface{Protect(fd int)bool}

type Bridge struct{
	mu sync.Mutex
	ssh *sshclient.Client
	socks *socks5.Server
	udp *udpgw.Client
	protector SocketProtector
	formatter *payload.Formatter
	dnsResolver string
}

func NewBridge()*Bridge{return &Bridge{formatter:payload.NewFormatter()}}

func(b *Bridge)SetSocketProtector(p SocketProtector){b.mu.Lock();defer b.mu.Unlock();b.protector=p}

func (b *Bridge) ValidateProfile(profileJSON string) error {
	p, err := profile.ParseJSON(profileJSON)
	if err != nil { return err }
	return sshclient.ValidateProfile(p)
}

func(b *Bridge)Connect(profileJSON string)error{
	p,err:=profile.ParseJSON(profileJSON);if err!=nil{return err}
	if err=sshclient.ValidateProfile(p);err!=nil{return err}
	b.mu.Lock();protector:=b.protector;formatter:=b.formatter;b.mu.Unlock()
	client:=&sshclient.Client{Formatter:formatter}
	if protector!=nil{client.Protect=protector.Protect}
	if err=client.Connect(p);err!=nil{return err}
	var udpClient *udpgw.Client
	if p.UDPForward { udpClient=udpgw.New(client,p.UDPResolver) }
	if p.LocalSocksPort==0{p.LocalSocksPort=1080}
	server:=&socks5.Server{Addr:net.JoinHostPort("127.0.0.1",strconv.Itoa(int(p.LocalSocksPort))),Dial:client.Dial,UDP:udpClient,DNSForward:p.DNSForward,DNSResolver:p.DNSResolver,UDPOnlyDNS:!p.UDPForward&&p.DNSForward}
	if err=server.Start();err!=nil{if udpClient!=nil{_=udpClient.Close()};_=client.Close();return err}
	b.mu.Lock();defer b.mu.Unlock()
	if b.socks!=nil{_=b.socks.Close()}
	if b.udp!=nil{_=b.udp.Close()}
	if b.ssh!=nil{_=b.ssh.Close()}
	b.ssh=client;b.socks=server;b.udp=udpClient;b.dnsResolver=p.DNSResolver
	return nil
}

func(b *Bridge)WaitForSSH() error {
	b.mu.Lock()
	client := b.ssh
	b.mu.Unlock()
	if client == nil { return errors.New("SSH client is not connected") }
	return client.Wait()
}

func(b *Bridge)SocksAddress()string{b.mu.Lock();defer b.mu.Unlock();if b.socks==nil{return ""};return b.socks.AddrString()}
func(b *Bridge)DNSResolver()string{b.mu.Lock();defer b.mu.Unlock();return b.dnsResolver}

func(b *Bridge)Close()error{
	b.mu.Lock();defer b.mu.Unlock()
	if b.socks!=nil{_=b.socks.Close();b.socks=nil}
	if b.udp!=nil{_=b.udp.Close();b.udp=nil}
	b.dnsResolver=""
	if b.ssh!=nil{err:=b.ssh.Close();b.ssh=nil;return err}
	return nil
}



func (b *Bridge) ParseSSHURI(uri string) (string, error) {
	p, err := profile.ParseURI(uri)
	if err != nil { return "", err }
	encoded, err := json.Marshal(p)
	if err != nil { return "", err }
	return string(encoded), nil
}

func (b *Bridge) ImportLockedURI(uri, passcode string, nowUnixMilli int64) (string, error) {
	imported, err := config.DecodeLockedURI(uri, passcode, time.UnixMilli(nowUnixMilli))
	if err != nil { return "", err }
	encoded, err := json.Marshal(imported)
	if err != nil { return "", err }
	return string(encoded), nil
}

func (b *Bridge) ExportLockedURI(profileJSON string, expiryUnixMilli int64, message string, blockRoot bool, passcode string) (string, error) {
	p, err := profile.ParseJSON(profileJSON)
	if err != nil { return "", err }
	return config.EncodeLockedURI(config.LockedConfig{
		Profile: p, Locked: true, ExpiryUnixMilli: expiryUnixMilli,
		Message: message, BlockRoot: blockRoot,
	}, passcode)
}

func (b *Bridge) ImportSKS(raw []byte, appVersionCode int, nowUnixMilli int64) (string, error) {
	imported, err := config.ImportSKS(raw, appVersionCode, time.UnixMilli(nowUnixMilli))
	if err != nil { return "", err }
	encoded, err := json.Marshal(imported)
	if err != nil { return "", err }
	return string(encoded), nil
}

func(b *Bridge)IsConnected()bool{b.mu.Lock();defer b.mu.Unlock();return b.ssh!=nil&&b.socks!=nil}
