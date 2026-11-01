package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dev.go.core/internal/payload"
	"dev.go.core/internal/profile"
)

type Dialer struct {
	Base net.Dialer
	Protect func(fd int) bool
	Formatter *payload.Formatter
}

func (d *Dialer) Dial(p profile.Profile) (net.Conn,error) {
	if err:=p.Validate();err!=nil{return nil,err}
	timeout:=p.ConnectTimeout;if timeout<=0{timeout=15*time.Second}
	d.Base.Timeout=timeout
	if d.Protect!=nil{d.Base.Control=func(_, _ string,raw syscall.RawConn)error{
		var protectErr error
		if err:=raw.Control(func(fd uintptr){if !d.Protect(int(fd)){protectErr=errors.New("VpnService.protect rejected socket")}});err!=nil{return err}
		return protectErr
	}}
	address:=net.JoinHostPort(p.Host,strconv.Itoa(int(p.Port)))
	if p.Mode==profile.ModeProxy||p.Mode==profile.ModeSSL||p.Mode==profile.ModePayloadSSL{address=net.JoinHostPort(p.ProxyHost,strconv.Itoa(int(p.ProxyPort)))}
	conn,err:=d.Base.Dial("tcp",address);if err!=nil{return nil,err}
	fail:=func(e error)(net.Conn,error){_=conn.Close();return nil,e}
	if tcp,ok:=conn.(*net.TCPConn);ok{if err:=tcp.SetNoDelay(p.DisableDelaySSH);err!=nil{return fail(err)}}
	if p.Mode==profile.ModeSSL||p.Mode==profile.ModePayloadSSL{
		serverName:=p.SNI;if serverName==""{serverName=p.ProxyHost}
		cfg:=&tls.Config{ServerName:serverName,InsecureSkipVerify:!p.VerifyTLS}
		if p.TLSFingerprint!=""{
			expected,e:=hex.DecodeString(strings.ReplaceAll(p.TLSFingerprint,":",""));if e!=nil||len(expected)!=sha256.Size{return fail(errors.New("invalid TLS SHA-256 fingerprint"))}
			cfg.InsecureSkipVerify=true
			cfg.VerifyPeerCertificate=func(rawCerts [][]byte,_ [][]*x509.Certificate)error{
				if len(rawCerts)==0{return errors.New("server sent no certificate")}
				sum:=sha256.Sum256(rawCerts[0]);if !equal(sum[:],expected){return errors.New("TLS certificate fingerprint mismatch")};return nil
			}
		}
		tlsConn:=tls.Client(conn,cfg);if err:=tlsConn.Handshake();err!=nil{return fail(err)};conn=tlsConn
	}
	if p.Payload!=""{
		formatter:=d.Formatter;if formatter==nil{formatter=payload.NewFormatter()}
		data:=formatter.Format(p.Payload,payload.Context{Host:p.Host,Port:p.Port,Protocol:"HTTP/1.0"})
		if _,err:=conn.Write(data);err!=nil{return fail(err)}
		if err:=readPayloadResponse(conn,p.AcceptAnyStatus);err!=nil{return fail(err)}
	}else if p.Mode==profile.ModeProxy||p.Mode==profile.ModeSSL{
		target:=net.JoinHostPort(p.Host,strconv.Itoa(int(p.Port)))
		request:="CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\nProxy-Connection: Keep-Alive\r\n\r\n"
		if _,err:=io.WriteString(conn,request);err!=nil{return fail(err)}
		if err:=readPayloadResponse(conn,p.AcceptAnyStatus);err!=nil{return fail(err)}
	}
	return conn,nil
}

func readPayloadResponse(conn net.Conn,acceptAny bool)error{
	_=conn.SetReadDeadline(time.Now().Add(15*time.Second));defer conn.SetReadDeadline(time.Time{})
	buf:=make([]byte,0,1024)
	for len(buf)<64<<10{var one [1]byte;if _,err:=io.ReadFull(conn,one[:]);err!=nil{return fmt.Errorf("read proxy response: %w",err)};buf=append(buf,one[0]);n:=len(buf);if n>=4&&string(buf[n-4:])=="\r\n\r\n"{break}}
	if len(buf)>=64<<10{return errors.New("proxy response headers exceed 64 KiB")}
	end:=strings.IndexByte(string(buf),'\n');if end<0{return errors.New("malformed proxy status line")}
	fields:=strings.Fields(strings.TrimSpace(string(buf[:end])));if len(fields)<2||!strings.HasPrefix(fields[0],"HTTP/"){return errors.New("malformed proxy status line")}
	code,err:=strconv.Atoi(fields[1]);if err!=nil||code<100||code>599{return errors.New("invalid proxy status code")}
	if !acceptAny&&code!=200{return fmt.Errorf("proxy returned HTTP %d",code)}
	return nil
}

func equal(a,b []byte)bool{if len(a)!=len(b){return false};var v byte;for i:=range a{v|=a[i]^b[i]};return v==0}
