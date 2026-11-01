package profile

import "testing"

func TestAcceptAnyStatusDefaultsTrue(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u"}`)
	if err!=nil{t.Fatal(err)}
	if !p.AcceptAnyStatus{t.Fatal("acceptAnyStatus should default true")}
}

func TestAcceptAnyStatusCanBeDisabled(t *testing.T){
	p,err:=ParseJSON(`{"mode":"direct","host":"ssh.example","port":22,"username":"u","acceptAnyStatus":false}`)
	if err!=nil{t.Fatal(err)}
	if p.AcceptAnyStatus{t.Fatal("explicit false ignored")}
}

func TestSSLModeDoesNotRequireProxy(t *testing.T){
	p:=Profile{Mode:ModeSSL,Host:"ssh.example",Port:443,Username:"u"}
	if err:=p.Validate();err!=nil{t.Fatal(err)}
}

func TestPayloadSSLModeDoesNotRequireProxy(t *testing.T){
	p:=Profile{Mode:ModePayloadSSL,Host:"ssh.example",Port:443,Username:"u"}
	if err:=p.Validate();err!=nil{t.Fatal(err)}
}

func TestProxyModeRequiresProxyEndpoint(t *testing.T){
	p:=Profile{Mode:ModeProxy,Host:"ssh.example",Port:22,Username:"u"}
	if err:=p.Validate();err==nil{t.Fatal("expected proxy endpoint validation")}
}
