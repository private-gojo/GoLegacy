package transport

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"dev.go.core/internal/profile"
)

func TestProfileRejectsMissingProxy(t *testing.T) {
	p := profile.Profile{Mode:profile.ModeSSL, Host:"ssh.example", Port:22, Username:"u"}
	if err := p.Validate(); err == nil { t.Fatal("expected proxy validation error") }
}

func TestPayloadStatusLineGuard(t *testing.T) {
	c := &fakeConn{response:"garbage\r\n\r\n"}
	if err := readPayloadResponse(c, true); err == nil { t.Fatal("malformed status accepted") }
}

func TestAcceptAnyStatusDoesNotRewriteResponse(t *testing.T) {
	c := &fakeConn{response:"HTTP/1.1 302 Found\r\nLocation: https://example.test/\r\n\r\n"}
	if err := readPayloadResponse(c, true); err != nil { t.Fatal(err) }
	if strings.Contains(c.written, "200 Connection established") { t.Fatal("synthetic 200 must never be written") }
}

func TestRejectNon200WhenDisabled(t *testing.T) {
	c := &fakeConn{response:"HTTP/1.1 400 Bad Request\r\n\r\n"}
	if err := readPayloadResponse(c, false); err == nil { t.Fatal("expected non-200 rejection") }
}

type fakeConn struct { response string; written string }
func (f *fakeConn) Read(p []byte)(int,error){ if f.response=="" { return 0,io.EOF }; n:=copy(p,f.response); f.response=f.response[n:]; return n,nil }
func (f *fakeConn) Write(p []byte)(int,error){ f.written+=string(p); return len(p),nil }
func (f *fakeConn) Close()error{return nil}
func (f *fakeConn) LocalAddr() net.Addr{return fakeAddr("local")}
func (f *fakeConn) RemoteAddr() net.Addr{return fakeAddr("remote")}
func (f *fakeConn) SetDeadline(time.Time)error{return nil}
func (f *fakeConn) SetReadDeadline(time.Time)error{return nil}
func (f *fakeConn) SetWriteDeadline(time.Time)error{return nil}
type fakeAddr string
func (a fakeAddr) Network()string{return "test"}
func (a fakeAddr) String()string{return string(a)}
