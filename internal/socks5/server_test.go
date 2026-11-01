package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

func TestSOCKS5UDPRequestIPv4(t *testing.T){
	packet:=[]byte{0,0,0,1,1,2,3,4,0,53,0xaa}
	addr,payload,err:=parseUDPRequest(packet)
	if err!=nil{t.Fatal(err)}
	if !addr.IP.Equal(net.IPv4(1,2,3,4))||addr.Port!=53||len(payload)!=1||payload[0]!=0xaa{t.Fatalf("addr=%v payload=%v",addr,payload)}
}

func TestSOCKS5UDPResponseIPv6(t *testing.T){
	addr:=&net.UDPAddr{IP:net.ParseIP("2001:db8::1"),Port:5353}
	packet,err:=makeUDPResponse(addr,[]byte{1,2})
	if err!=nil{t.Fatal(err)}
	if packet[3]!=4||len(packet)!=3+1+16+2+2{t.Fatalf("packet=%v",packet)}
}

func TestSOCKS5UDPRejectsFragments(t *testing.T){
	_,_,err:=parseUDPRequest([]byte{0,0,1,1,1,2,3,4,0,53})
	if err==nil{t.Fatal("fragmented UDP packet accepted")}
}

func TestForwardDNSUsesTCPLengthPrefix(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	query := []byte{0x12, 0x34, 1, 0, 0, 1}
	response := []byte{0x12, 0x34, 0x81, 0x80, 0, 1}
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil { serverErr <- err; return }
		defer conn.Close()
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil { serverErr <- err; return }
		got := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err = io.ReadFull(conn, got); err != nil { serverErr <- err; return }
		if !bytes.Equal(got, query) { serverErr <- errors.New("DNS query payload mismatch"); return }
		binary.BigEndian.PutUint16(size[:], uint16(len(response)))
		if _, err = conn.Write(size[:]); err != nil { serverErr <- err; return }
		_, err = conn.Write(response)
		serverErr <- err
	}()
	s := &Server{
		DNSResolver: "1.1.1.1",
		Dial: func(_, _ string) (net.Conn, error) { return net.Dial("tcp", listener.Addr().String()) },
	}
	got, err := s.forwardDNS(query)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, response) { t.Fatalf("response mismatch: %v", got) }
	if err := <-serverErr; err != nil { t.Fatal(err) }
}

func TestDNSOnlyModeAllowsSOCKSUDPWithoutUDPGW(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	s := &Server{DNSForward: true}
	go s.handleUDPAssociate(serverSide, "", 0)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil { t.Fatal(err) }
	if reply[0] != 5 || reply[1] != 0 { t.Fatalf("DNS-only UDP association rejected: %v", reply) }
}
