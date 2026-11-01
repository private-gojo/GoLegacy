package sshclient

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"dev.go.core/internal/profile"
)

func TestSSHAgainstLegacyServerTypes(t *testing.T) {
	username:=os.Getenv("SSH_TEST_USERNAME")
	password:=os.Getenv("SSH_TEST_PASSWORD")
	if username==""||password==""{t.Skip("SSH integration environment not configured")}
	servers:=[]struct{name,portEnv string}{
		{name:"OpenSSH",portEnv:"SSH_TEST_PORT"},
		{name:"Dropbear",portEnv:"DROPBEAR_TEST_PORT"},
		{name:"LegacyAlgorithms",portEnv:"LEGACY_SSH_TEST_PORT"},
	}
	for _,server:=range servers{
		t.Run(server.name,func(t *testing.T){
			portText:=os.Getenv(server.portEnv);if portText==""{t.Skip("server port not configured")}
			port,err:=strconv.Atoi(portText);if err!=nil{t.Fatal(err)}
			p:=profile.Profile{Mode:profile.ModeDirect,Host:"127.0.0.1",Port:uint16(port),Username:username,Password:password}
			c:=&Client{}
			if err:=c.Connect(p);err!=nil{t.Fatalf("SSH connect: %v",err)}
			defer c.Close()
			out,err:=c.Exec("printf golegacy-ssh-ok")
			if err!=nil{t.Fatalf("SSH exec: %v",err)}
			if string(out)!="golegacy-ssh-ok"{t.Fatalf("unexpected output: %q",out)}
		})
	}
}

func TestSSHThroughHTTPProxyAndTLSModes(t *testing.T) {
	username := os.Getenv("SSH_TEST_USERNAME")
	password := os.Getenv("SSH_TEST_PASSWORD")
	portText := os.Getenv("SSH_TEST_PORT")
	if username == "" || password == "" || portText == "" {
		t.Skip("SSH integration environment not configured")
	}
	portValue, err := strconv.Atoi(portText)
	if err != nil { t.Fatal(err) }
	target := net.JoinHostPort("127.0.0.1", portText)

	t.Run("HTTPProxy", func(t *testing.T) {
		proxy := startHTTPConnectProxy(t, target)
		host, portText, _ := net.SplitHostPort(proxy)
		port, _ := strconv.Atoi(portText)
		p := profile.Profile{
			Mode: profile.ModeProxy, Host: "127.0.0.1", Port: uint16(portValue),
			Username: username, Password: password, ProxyHost: host, ProxyPort: uint16(port),
			AcceptAnyStatus: true,
		}
		assertSSHExec(t, p, "http-proxy")
	})

	t.Run("HTTPProxyCustomPayload", func(t *testing.T) {
		proxy := startHTTPConnectProxy(t, target)
		host, portText, _ := net.SplitHostPort(proxy)
		port, _ := strconv.Atoi(portText)
		p := profile.Profile{
			Mode: profile.ModeProxy, Host: "127.0.0.1", Port: uint16(portValue),
			Username: username, Password: password, ProxyHost: host, ProxyPort: uint16(port),
			Payload: "CONNECT [host_port] [protocol][crlf][crlf]", AcceptAnyStatus: true,
		}
		assertSSHExec(t, p, "http-proxy-payload")
	})

	t.Run("TLS", func(t *testing.T) {
		front := startTLSBridge(t, target, false)
		host, portText, _ := net.SplitHostPort(front)
		port, _ := strconv.Atoi(portText)
		p := profile.Profile{
			Mode: profile.ModeSSL, Host: host, Port: uint16(port),
			Username: username, Password: password, SNI: "localhost",
		}
		assertSSHExec(t, p, "tls")
	})

	t.Run("PayloadTLS", func(t *testing.T) {
		front := startTLSBridge(t, target, true)
		host, portText, _ := net.SplitHostPort(front)
		port, _ := strconv.Atoi(portText)
		p := profile.Profile{
			Mode: profile.ModePayloadSSL, Host: host, Port: uint16(port),
			Username: username, Password: password, SNI: "localhost",
			Payload: "CONNECT [host_port] [protocol][crlf][crlf]", AcceptAnyStatus: true,
		}
		assertSSHExec(t, p, "payload-tls")
	})
}

func assertSSHExec(t *testing.T, p profile.Profile, marker string) {
	t.Helper()
	client := &Client{}
	if err := client.Connect(p); err != nil { t.Fatalf("SSH connect: %v", err) }
	defer client.Close()
	out, err := client.Exec("printf " + marker)
	if err != nil { t.Fatalf("SSH exec: %v", err) }
	if string(out) != marker { t.Fatalf("unexpected output: %q", out) }
}

func startHTTPConnectProxy(t *testing.T, target string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	t.Cleanup(func(){ _ = listener.Close() })
	go func(){
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil { return }
			go func(conn net.Conn){
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil { return }
					if line == "\r\n" { break }
				}
				upstream, dialErr := net.Dial("tcp", target)
				if dialErr != nil { return }
				defer upstream.Close()
				if _, writeErr := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); writeErr != nil { return }
				done := make(chan struct{}, 1)
				go func(){ _, _ = io.Copy(upstream, reader); done <- struct{}{} }()
				_, _ = io.Copy(conn, upstream)
				<-done
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func startTLSBridge(t *testing.T, target string, expectHTTP bool) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { t.Fatal(err) }
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil { t.Fatal(err) }
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil { t.Fatal(err) }
	t.Cleanup(func(){ _ = listener.Close() })
	go func(){
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil { return }
			go func(conn net.Conn){
				defer conn.Close()
				tlsConn := conn.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil { return }
				reader := bufio.NewReader(tlsConn)
				if expectHTTP {
					for {
						line, readErr := reader.ReadString('\n')
						if readErr != nil { return }
						if line == "\r\n" { break }
					}
					if _, err := io.WriteString(tlsConn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil { return }
				}
				upstream, dialErr := net.Dial("tcp", target)
				if dialErr != nil { return }
				defer upstream.Close()
				done := make(chan struct{}, 1)
				go func(){ _, _ = io.Copy(upstream, reader); done <- struct{}{} }()
				_, _ = io.Copy(tlsConn, upstream)
				<-done
			}(conn)
		}
	}()
	return listener.Addr().String()
}
