package mobile

import (
	"encoding/json"
	"errors"
	"sync"

	"dev.go.core/internal/profile"
	"dev.go.core/internal/socks5"
	"dev.go.core/internal/sshclient"
)

type Bridge struct {
	mu sync.Mutex
	ssh *sshclient.Client
	socks *socks5.Server
}

func NewBridge() *Bridge { return &Bridge{} }

func (b *Bridge) Connect(profileJSON string) error {
	p,err:=profile.ParseJSON(profileJSON); if err!=nil{return err}
	client:=&sshclient.Client{}
	if err=client.Connect(p);err!=nil{return err}
	server:=&socks5.Server{Addr:"127.0.0.1:0",Dial:client.Dial}
	if err=server.Start();err!=nil{_=client.Close();return err}
	b.mu.Lock(); defer b.mu.Unlock()
	if b.socks!=nil{_=b.socks.Close()};if b.ssh!=nil{_=b.ssh.Close()}
	b.ssh=client;b.socks=server
	return nil
}

func (b *Bridge) ConnectJSON(raw string) error {
	var v map[string]any
	if err:=json.Unmarshal([]byte(raw),&v);err!=nil{return err}
	return b.Connect(raw)
}

func (b *Bridge) SocksAddress() string {
	b.mu.Lock();defer b.mu.Unlock()
	if b.socks==nil{return ""}
	return b.socks.AddrString()
}

func (b *Bridge) Close() error {
	b.mu.Lock();defer b.mu.Unlock()
	if b.socks!=nil{_=b.socks.Close();b.socks=nil}
	if b.ssh!=nil{err:=b.ssh.Close();b.ssh=nil;return err}
	return nil
}

func (b *Bridge) IsConnected() bool {
	b.mu.Lock();defer b.mu.Unlock()
	if b.ssh==nil{return false}
	if b.socks==nil{return false}
	return true
}

var ErrUDPNotImplemented = errors.New("UDP forwarding is not enabled until the legacy UDPGW parity adapter is validated")
