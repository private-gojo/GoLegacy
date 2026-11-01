package socks5

import (
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
