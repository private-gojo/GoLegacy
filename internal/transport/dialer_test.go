package transport

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"dev.go.core/internal/profile"
)

func TestProfileRejectsMissingProxy(t *testing.T) {
	p := profile.Profile{Mode:profile.ModeProxy, Host:"ssh.example", Port:22, Username:"u"}
	if err := p.Validate(); err == nil { t.Fatal("expected proxy validation error") }
}

func TestPayloadStatusLineGuard(t *testing.T) {
	c := &fakeConn{response:"garbage\r\n\r\n"}
	if err := readPayloadResponse(c, true); err == nil { t.Fatal("malformed status accepted") }
}

func TestAcceptAnyStatusDoesNotWriteSynthetic200(t *testing.T) {
	c := &fakeConn{response:"HTTP/1.1 302 Found\r\nLocation: https://example.test/\r\n\r\n"}
	if err := readPayloadResponse(c, true); err != nil { t.Fatal(err) }
	if strings.Contains(c.written, "HTTP/1.0 200 Connection established") { t.Fatal("synthetic 200 must not be written") }
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

func TestAcceptAnyStatusLiveProxyDoesNotWriteSynthetic200(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil { serverResult <- err; return }
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil { serverResult <- readErr; return }
			if line == "\r\n" { break }
		}
		if _, err = io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: https://example.test/\r\n\r\n"); err != nil {
			serverResult <- err
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buffer := make([]byte, 256)
		n, _ := conn.Read(buffer)
		if n > 0 && strings.Contains(string(buffer[:n]), "200 Connection established") {
			serverResult <- errors.New("synthetic 200 was written to the proxy")
			return
		}
		serverResult <- nil
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	if err := writeAndCheck(conn, []byte("CONNECT ssh.example:22 HTTP/1.0\r\n\r\n"), true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverResult:
		if err != nil { t.Fatal(err) }
	case <-time.After(time.Second):
		t.Fatal("proxy runtime check timed out")
	}
}

func TestWriteFullHandlesPartialWrites(t *testing.T) {
	base := &fakeConn{}
	conn := &shortWriteConn{fakeConn: base, max: 2}
	if err := writeFull(conn, []byte("abcdef")); err != nil { t.Fatal(err) }
	if base.written != "abcdef" { t.Fatalf("written=%q", base.written) }
}
