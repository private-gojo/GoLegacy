package sshclient

import (
	"os"
	"strconv"
	"testing"

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
