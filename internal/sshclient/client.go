package sshclient

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"dev.go.core/internal/payload"
	"dev.go.core/internal/profile"
	"dev.go.core/internal/transport"
)

type Client struct {
	mu sync.Mutex
	conn net.Conn
	client *ssh.Client
	Protect func(fd int) bool
	Formatter *payload.Formatter
	keepAliveStop chan struct{}
}

func ValidateProfile(p profile.Profile) error {
	if err := p.Validate(); err != nil { return err }
	if p.PrivateKey == "" { return nil }
	if p.Passphrase != "" {
		_, err := ssh.ParsePrivateKeyWithPassphrase([]byte(p.PrivateKey), []byte(p.Passphrase))
		return err
	}
	_, err := ssh.ParsePrivateKey([]byte(p.PrivateKey))
	return err
}

func(c *Client)Connect(p profile.Profile)error{
	if err := ValidateProfile(p); err != nil { return err }
	d:=&transport.Dialer{Protect:c.Protect,Formatter:c.Formatter}
	raw,err:=d.Dial(p);if err!=nil{return err}
	supported := ssh.SupportedAlgorithms()
	sshConfig := ssh.Config{
		KeyExchanges: append(supported.KeyExchanges,
			ssh.InsecureKeyExchangeDHGEXSHA1,
			ssh.InsecureKeyExchangeDH14SHA1,
			ssh.InsecureKeyExchangeDH1SHA1,
		),
		Ciphers: append(supported.Ciphers,
			ssh.InsecureCipherAES128CBC,
			ssh.InsecureCipherTripleDESCBC,
		),
		MACs: append(supported.MACs, ssh.InsecureHMACSHA196),
	}
	cfg:=&ssh.ClientConfig{Config:sshConfig,User:p.Username,Timeout:15*time.Second,ClientVersion:"SSH-2.0-TrileadSSH2Java_213",HostKeyCallback:hostKeyCallback(p)}
	if p.Password!=""{cfg.Auth=append(cfg.Auth,ssh.Password(p.Password))}
	if p.PrivateKey!=""{
		var signer ssh.Signer
		if p.Passphrase!=""{signer,err=ssh.ParsePrivateKeyWithPassphrase([]byte(p.PrivateKey),[]byte(p.Passphrase))}else{signer,err=ssh.ParsePrivateKey([]byte(p.PrivateKey))}
		if err!=nil{_=raw.Close();return fmt.Errorf("parse SSH private key: %w",err)}
		cfg.Auth=append(cfg.Auth,ssh.PublicKeys(signer))
	}
	if len(cfg.Auth)==0{_=raw.Close();return errors.New("SSH password or private key is required")}
	cc,chans,reqs,err:=ssh.NewClientConn(raw,net.JoinHostPort(p.Host,fmt.Sprint(p.Port)),cfg)
	if err!=nil{_=raw.Close();return fmt.Errorf("SSH handshake: %w",err)}
	c.mu.Lock()
	if c.client!=nil{_=c.client.Close()}
	if c.keepAliveStop!=nil{close(c.keepAliveStop)}
	c.conn=raw;c.client=ssh.NewClient(cc,chans,reqs);c.keepAliveStop=nil
	client:=c.client
	if p.KeepAliveSeconds>0{stop:=make(chan struct{});c.keepAliveStop=stop;go keepAlive(client,stop,time.Duration(p.KeepAliveSeconds)*time.Second)}
	c.mu.Unlock()
	return nil
}

func keepAlive(client *ssh.Client,stop <-chan struct{},interval time.Duration){
	t:=time.NewTicker(interval);defer t.Stop()
	for{select{case<-stop:return;case<-t.C:_,_,_=client.SendRequest("trilead-ping",true,nil)}}
}

func hostKeyCallback(p profile.Profile)ssh.HostKeyCallback{
	if p.HostKeySHA256==""{return func(_ string,_ net.Addr,_ ssh.PublicKey)error{return nil}}
	return func(_ string,_ net.Addr,key ssh.PublicKey)error{
		sum:=sha256.Sum256(key.Marshal());got:=base64.RawStdEncoding.EncodeToString(sum[:]);want:=strings.TrimPrefix(p.HostKeySHA256,"SHA256:")
		if got!=want{return errors.New("SSH host key fingerprint mismatch")};return nil
	}
}

func(c *Client)Wait() error {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil { return errors.New("SSH client is not connected") }
	return client.Wait()
}

func(c *Client)Dial(network,address string)(net.Conn,error){
	c.mu.Lock();client:=c.client;c.mu.Unlock()
	if client==nil{return nil,errors.New("SSH client is not connected")}
	return client.Dial(network,address)
}

func(c *Client)Exec(command string)([]byte,error){
	c.mu.Lock();client:=c.client;c.mu.Unlock()
	if client==nil{return nil,errors.New("SSH client is not connected")}
	session,err:=client.NewSession();if err!=nil{return nil,err}
	defer session.Close()
	return session.CombinedOutput(command)
}

func(c *Client)Close()error{
	c.mu.Lock();defer c.mu.Unlock()
	if c.keepAliveStop!=nil{close(c.keepAliveStop);c.keepAliveStop=nil}
	var err error
	if c.client!=nil{err=c.client.Close();c.client=nil}
	if c.conn!=nil{_=c.conn.Close();c.conn=nil}
	return err
}
