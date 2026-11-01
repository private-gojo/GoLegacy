package transport

import (
	"bufio"
	"bytes"
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

func(d *Dialer)Dial(p profile.Profile)(net.Conn,error){
	if err:=p.Validate();err!=nil{return nil,err}
	timeout:=time.Duration(p.ConnectTimeoutMs)*time.Millisecond
	d.Base.Timeout=timeout
	if d.Protect!=nil{d.Base.Control=func(_, _ string,raw syscall.RawConn)error{
		var protectErr error
		if err:=raw.Control(func(fd uintptr){if !d.Protect(int(fd)){protectErr=errors.New("VpnService.protect rejected socket")}});err!=nil{return err}
		return protectErr
	}}
	connectHost,connectPort:=p.Host,p.Port
	if p.Mode==profile.ModeProxy{connectHost,connectPort=p.ProxyHost,p.ProxyPort}
	conn,err:=d.Base.Dial("tcp",net.JoinHostPort(connectHost,strconv.Itoa(int(connectPort))))
	if err!=nil{return nil,err}
	fail:=func(e error)(net.Conn,error){_=conn.Close();return nil,e}
	if tcp,ok:=conn.(*net.TCPConn);ok{if err:=tcp.SetNoDelay(p.DisableDelaySSH);err!=nil{return fail(err)}}

	if p.Mode==profile.ModeSSL||p.Mode==profile.ModePayloadSSL{
		serverName:=p.SNI;if serverName==""{serverName=p.Host}
		cfg:=&tls.Config{ServerName:serverName,InsecureSkipVerify:!p.VerifyTLS}
		if p.TLSFingerprint!=""{
			expected,e:=hex.DecodeString(strings.ReplaceAll(p.TLSFingerprint,":",""));if e!=nil||len(expected)!=sha256.Size{return fail(errors.New("invalid TLS SHA-256 fingerprint"))}
			cfg.InsecureSkipVerify=true
			cfg.VerifyPeerCertificate=func(rawCerts [][]byte,_ [][]*x509.Certificate)error{
				if len(rawCerts)==0{return errors.New("server sent no certificate")}
				sum:=sha256.Sum256(rawCerts[0]);if !equal(sum[:],expected){return errors.New("TLS certificate fingerprint mismatch")};return nil
			}
		}
		handshakeTimeout := time.Duration(p.HandshakeTimeoutMs) * time.Millisecond
		if handshakeTimeout <= 0 { handshakeTimeout = 20 * time.Second }
		if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil { return fail(err) }
		tlsConn:=tls.Client(conn,cfg);if err:=tlsConn.Handshake();err!=nil{return fail(err)}
		_ = tlsConn.SetDeadline(time.Time{})
		conn=tlsConn
	}

	switch p.Mode{
	case profile.ModeDirect:
		if p.Payload!=""{if err:=d.sendPayload(conn,p);err!=nil{return fail(err)}}
	case profile.ModeProxy:
		if p.Payload!=""{if err:=d.sendPayload(conn,p);err!=nil{return fail(err)}}else{
			if err:=writeAndCheck(conn,defaultConnect(p.Host,p.Port),p.AcceptAnyStatus);err!=nil{return fail(err)}
		}
		if p.Payload!=""{if err:=readPayloadResponse(conn,p.AcceptAnyStatus);err!=nil{return fail(err)}}
	case profile.ModeSSL:
		// TLS wraps the SSH endpoint directly; no HTTP CONNECT is sent.
	case profile.ModePayloadSSL:
		if p.Payload==""{
			if err:=writeAndCheck(conn,defaultConnect(p.Host,p.Port),p.AcceptAnyStatus);err!=nil{return fail(err)}
		}else{
			if err:=d.sendPayload(conn,p);err!=nil{return fail(err)}
			if err:=readPayloadResponse(conn,p.AcceptAnyStatus);err!=nil{return fail(err)}
		}
	}
	return conn,nil
}

func(d *Dialer)sendPayload(conn net.Conn,p profile.Profile)error{
	formatter:=d.Formatter;if formatter==nil{formatter=payload.NewFormatter()}
	data:=formatter.Format(p.Payload,payload.Context{Host:p.Host,Port:p.Port,Protocol:"HTTP/1.0"})
	if bytes.Contains(data,[]byte("[split]"))||bytes.Contains(data,[]byte("[delay_split]")){
		writer:=bufio.NewWriter(conn)
		handled,err:=payload.InjectSplitPayload(string(data),writer);if err!=nil{return err}
		if !handled{if _,err=writer.Write(payload.EncodeLatin1(string(data)));err!=nil{return err};return writer.Flush()}
		return nil
	}
	_,err:=conn.Write(payload.EncodeLatin1(string(data)))
	return err
}

func defaultConnect(host string,port uint16)[]byte{
	return []byte("CONNECT "+host+":"+strconv.Itoa(int(port))+" HTTP/1.0\r\n\r\n")
}

func writeAndCheck(conn net.Conn,data []byte,acceptAny bool)error{
	if _,err:=conn.Write(data);err!=nil{return err}
	return readPayloadResponse(conn,acceptAny)
}

func readPayloadResponse(conn net.Conn,acceptAny bool)error{
	_=conn.SetReadDeadline(time.Now().Add(15*time.Second));defer conn.SetReadDeadline(time.Time{})
	buf:=make([]byte,0,1024)
	for len(buf)<64<<10{
		var one [1]byte
		if _,err:=io.ReadFull(conn,one[:]);err!=nil{return fmt.Errorf("read proxy response: %w",err)}
		buf=append(buf,one[0]);n:=len(buf);if n>=4&&string(buf[n-4:])=="\r\n\r\n"{break}
	}
	if len(buf)>=64<<10{return errors.New("proxy response headers exceed 64 KiB")}
	end:=strings.IndexByte(string(buf),'\n');if end<0{return errors.New("malformed proxy status line")}
	fields:=strings.Fields(strings.TrimSpace(string(buf[:end])))
	if len(fields)<2||!strings.HasPrefix(fields[0],"HTTP/"){return errors.New("malformed proxy status line")}
	code,err:=strconv.Atoi(fields[1]);if err!=nil||code<100||code>599{return errors.New("invalid proxy status code")}
	if !acceptAny&&code!=200&&code!=101{return fmt.Errorf("proxy returned HTTP %d",code)}
	return nil
}

func equal(a,b []byte)bool{if len(a)!=len(b){return false};var v byte;for i:=range a{v|=a[i]^b[i]};return v==0}
