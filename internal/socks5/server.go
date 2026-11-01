package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

type DialFunc func(network,address string)(net.Conn,error)

type Server struct { Addr string; Dial DialFunc; listener net.Listener }

func (s *Server) Start() error {
	if s.Dial==nil { return errors.New("SOCKS5 dial function is required") }
	ln,err:=net.Listen("tcp",s.Addr); if err!=nil{return err}; s.listener=ln
	go func(){ for { c,e:=ln.Accept(); if e!=nil{return}; go s.handle(c) } }()
	return nil
}

func (s *Server) AddrString() string { if s.listener==nil{return ""}; return s.listener.Addr().String() }
func (s *Server) Close() error { if s.listener==nil{return nil}; return s.listener.Close() }

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30*time.Second))
	var h [2]byte
	if _,e:=io.ReadFull(c,h[:]); e!=nil || h[0]!=5 { return }
	methods:=make([]byte,int(h[1])); if _,e:=io.ReadFull(c,methods);e!=nil{return}
	found:=byte(255); for _,m:=range methods{if m==0{found=0;break}}
	_,_=c.Write([]byte{5,found}); if found==255{return}
	var req [4]byte; if _,e:=io.ReadFull(c,req[:]);e!=nil{return}
	if req[0]!=5 || req[1]!=1 { _,_=c.Write([]byte{5,7,0,1,0,0,0,0,0,0});return }
	var host string
	switch req[3] {
	case 1: b:=make([]byte,4);if _,e:=io.ReadFull(c,b);e!=nil{return};host=net.IP(b).String()
	case 3: var n [1]byte;if _,e:=io.ReadFull(c,n[:]);e!=nil{return};b:=make([]byte,int(n[0]));if _,e:=io.ReadFull(c,b);e!=nil{return};host=string(b)
	case 4: b:=make([]byte,16);if _,e:=io.ReadFull(c,b);e!=nil{return};host=net.IP(b).String()
	default: return
	}
	var pb [2]byte;if _,e:=io.ReadFull(c,pb[:]);e!=nil{return}
	dst:=net.JoinHostPort(host,strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))))
	up,e:=s.Dial("tcp",dst);if e!=nil{_,_=c.Write([]byte{5,5,0,1,0,0,0,0,0,0});return}
	defer up.Close()
	_,_=c.Write([]byte{5,0,0,1,0,0,0,0,0,0})
	_ = c.SetDeadline(time.Time{}); _=up.SetDeadline(time.Time{})
	done:=make(chan struct{},1)
	go func(){_,_=io.Copy(up,c);done<-struct{}{}}()
	_,_=io.Copy(c,up)
	<-done
}
