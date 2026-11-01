package udpgw

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestIPv4FrameEncoding(t *testing.T){
	remote:=&net.UDPAddr{IP:net.IPv4(1,2,3,4),Port:53}
	got,err:=encodeFrame(flagDNS|flagRebind,0x1234,remote,[]byte{0xaa,0xbb})
	if err!=nil{t.Fatal(err)}
	if binary.LittleEndian.Uint16(got[:2])!=11{t.Fatalf("length=%d",binary.LittleEndian.Uint16(got[:2]))}
	body:=got[2:]
	if body[0]!=(flagDNS|flagRebind){t.Fatalf("flags=%02x",body[0])}
	if binary.LittleEndian.Uint16(body[1:3])!=0x1234{t.Fatal("connection id byte order mismatch")}
	if !bytes.Equal(body[3:7],[]byte{1,2,3,4}){t.Fatalf("ip=%v",body[3:7])}
	if !bytes.Equal(body[7:9],[]byte{0,53}){t.Fatalf("port=%v",body[7:9])}
	if !bytes.Equal(body[9:],[]byte{0xaa,0xbb}){t.Fatal("payload mismatch")}
}

func TestIPv6FrameRoundTrip(t *testing.T){
	remote:=&net.UDPAddr{IP:net.ParseIP("2001:db8::1"),Port:5353}
	got,err:=encodeFrame(0,17,remote,[]byte("dns"))
	if err!=nil{t.Fatal(err)}
	flags,id,decoded,payload,err:=decodeDatagram(got[2:])
	if err!=nil{t.Fatal(err)}
	if flags&flagIPv6==0||id!=17||!decoded.IP.Equal(remote.IP)||decoded.Port!=remote.Port||string(payload)!="dns"{t.Fatalf("decoded %v %d %v %q",flags,id,decoded,payload)}
}

func TestKeepaliveFrame(t *testing.T){
	got,err:=encodeFrame(flagKeepalive,0,nil,nil)
	if err!=nil{t.Fatal(err)}
	if len(got)!=5||binary.LittleEndian.Uint16(got[:2])!=3||got[2]!=flagKeepalive{t.Fatalf("frame=%v",got)}
}
