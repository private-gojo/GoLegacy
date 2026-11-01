package udpgw

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"dev.go.core/internal/profile"
	"dev.go.core/internal/sshclient"
)

func TestUDPGWAgainstBadVPN(t *testing.T) {
	host:=os.Getenv("UDPGW_TEST_HOST")
	portText:=os.Getenv("UDPGW_TEST_SSH_PORT")
	username:=os.Getenv("SSH_TEST_USERNAME")
	password:=os.Getenv("SSH_TEST_PASSWORD")
	if host==""||portText==""||username==""||password==""{t.Skip("BadVPN integration environment not configured")}
	port,err:=strconv.Atoi(portText);if err!=nil{t.Fatal(err)}
	sshConn:=&sshclient.Client{}
	if err:=sshConn.Connect(profile.Profile{Mode:profile.ModeDirect,Host:host,Port:uint16(port),Username:username,Password:password});err!=nil{t.Fatalf("SSH connect: %v",err)}
	defer sshConn.Close()
	gateway:=New(sshConn,"127.0.0.1:7300")
	defer gateway.Close()
	reply:=make(chan []byte,1)
	remote:=&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:9999}
	if err:=gateway.Send("ci-udp-association",remote,[]byte("golegacy-udpgw-ok"),false,func(data []byte){select{case reply<-append([]byte(nil),data...):default:}});err!=nil{t.Fatalf("send UDPGW: %v",err)}
	select{
	case got:=<-reply:
		if string(got)!="golegacy-udpgw-ok"{t.Fatalf("unexpected UDP reply %q",got)}
	case<-time.After(8*time.Second):
		t.Fatal("timed out waiting for BadVPN UDPGW reply")
	}
}
