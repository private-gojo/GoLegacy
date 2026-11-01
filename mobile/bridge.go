package mobile

import (
	"sync"

	"dev.go.core/internal/payload"
	"dev.go.core/internal/profile"
	"dev.go.core/internal/socks5"
	"dev.go.core/internal/sshclient"
)

type SocketProtector interface { Protect(fd int) bool }

type Bridge struct {
	mu sync.Mutex
	ssh *sshclient.Client
	socks *socks5.Server
	protector SocketProtector
	formatter *payload.Formatter
}

func NewBridge()*Bridge{return &Bridge{formatter:payload.NewFormatter()}}

func(b *Bridge)SetSocketProtector(p SocketProtector){b.mu.Lock();defer b.mu.Unlock();b.protector=p}

func(b *Bridge)Connect(profileJSON string)error{
	p,err:=profile.ParseJSON(profileJSON);if err!=nil{return err}
	b.mu.Lock();protector:=b.protector;formatter:=b.formatter;b.mu.Unlock()
	client:=&sshclient.Client{Formatter:formatter}
	if protector!=nil{client.Protect=protector.Protect}
	if err=client.Connect(p);err!=nil{return err}
	server:=&socks5.Server{Addr:"127.0.0.1:0",Dial:client.Dial}
	if err=server.Start();err!=nil{_=client.Close();return err}
	b.mu.Lock();defer b.mu.Unlock()
	if b.socks!=nil{_=b.socks.Close()};if b.ssh!=nil{_=b.ssh.Close()}
	b.ssh=client;b.socks=server
	return nil
}

func(b *Bridge)SocksAddress()string{b.mu.Lock();defer b.mu.Unlock();if b.socks==nil{return ""};return b.socks.AddrString()}

func(b *Bridge)Close()error{
	b.mu.Lock();defer b.mu.Unlock()
	if b.socks!=nil{_=b.socks.Close();b.socks=nil}
	if b.ssh!=nil{err:=b.ssh.Close();b.ssh=nil;return err}
	return nil
}

func(b *Bridge)IsConnected()bool{b.mu.Lock();defer b.mu.Unlock();return b.ssh!=nil&&b.socks!=nil}
