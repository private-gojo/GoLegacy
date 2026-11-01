package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type DialFunc func(network,address string)(net.Conn,error)

type UDPForwarder interface {
	Send(localID string,remote *net.UDPAddr,payload []byte,isDNS bool,reply func([]byte))error
	CloseAssociation(localID string)
}

type Server struct {
	Addr string
	Dial DialFunc
	UDP UDPForwarder
	DNSForward bool
	DNSResolver string
	UDPOnlyDNS bool
	listener net.Listener
	mu sync.Mutex
	udpConns map[string]*net.UDPConn
	nextAssociation uint64
}

func(s *Server)Start()error{
	if s.Dial==nil{return errors.New("SOCKS5 dial function is required")}
	ln,err:=net.Listen("tcp",s.Addr);if err!=nil{return err}
	s.listener=ln;s.udpConns=make(map[string]*net.UDPConn)
	go func(){for{c,e:=ln.Accept();if e!=nil{return};go s.handle(c)}}()
	return nil
}

func(s *Server)AddrString()string{if s.listener==nil{return ""};return s.listener.Addr().String()}

func(s *Server)Close()error{
	var err error
	if s.listener!=nil{err=s.listener.Close()}
	s.mu.Lock()
	for id,conn:=range s.udpConns{_=conn.Close();if s.UDP!=nil{s.UDP.CloseAssociation(id)};delete(s.udpConns,id)}
	s.mu.Unlock()
	return err
}

func(s *Server)handle(c net.Conn){
	defer c.Close()
	_=c.SetDeadline(time.Now().Add(30*time.Second))
	var h [2]byte
	if _,e:=io.ReadFull(c,h[:]);e!=nil||h[0]!=5{return}
	methods:=make([]byte,int(h[1]));if _,e:=io.ReadFull(c,methods);e!=nil{return}
	found:=byte(255);for _,m:=range methods{if m==0{found=0;break}}
	_,_=c.Write([]byte{5,found});if found==255{return}
	var req [4]byte;if _,e:=io.ReadFull(c,req[:]);e!=nil{return}
	if req[0]!=5{return}
	host,port,err:=readAddress(c,req[3]);if err!=nil{return}
	switch req[1]{
	case 1:s.handleConnect(c,host,port)
	case 3:s.handleUDPAssociate(c,host,port)
	default:_,_=c.Write([]byte{5,7,0,1,0,0,0,0,0,0})
	}
}

func(s *Server)handleConnect(c net.Conn,host string,port uint16){
	dst:=net.JoinHostPort(host,strconv.Itoa(int(port)))
	up,err:=s.Dial("tcp",dst);if err!=nil{_,_=c.Write([]byte{5,5,0,1,0,0,0,0,0,0});return}
	defer up.Close()
	_,_=c.Write([]byte{5,0,0,1,0,0,0,0,0,0})
	_=c.SetDeadline(time.Time{});_=up.SetDeadline(time.Time{})
	done:=make(chan struct{},1)
	go func(){_,_=io.Copy(up,c);done<-struct{}{}}()
	_,_=io.Copy(c,up)
	<-done
}

func(s *Server)handleUDPAssociate(control net.Conn,requestedHost string,requestedPort uint16){
	if s.UDP==nil&&!s.DNSForward{_,_=control.Write([]byte{5,7,0,1,0,0,0,0,0,0});return}
	udp,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{_,_=control.Write([]byte{5,1,0,1,0,0,0,0,0,0});return}
	id:=fmt.Sprintf("socks-udp-%d",atomic.AddUint64(&s.nextAssociation,1))
	s.mu.Lock();if s.udpConns==nil{s.udpConns=make(map[string]*net.UDPConn)};s.udpConns[id]=udp;s.mu.Unlock()
	bound:=udp.LocalAddr().(*net.UDPAddr)
	reply:=[]byte{5,0,0,1,127,0,0,1,0,0}
	binary.BigEndian.PutUint16(reply[8:10],uint16(bound.Port))
	if _,err:=control.Write(reply);err!=nil{s.closeUDPAssociation(id);return}
	_=control.SetDeadline(time.Time{})
	go s.udpLoop(id,udp,requestedHost,requestedPort)
	var one [1]byte
	for{if _,err:=control.Read(one[:]);err!=nil{break}}
	s.closeUDPAssociation(id)
}

func(s *Server)udpLoop(id string,udp *net.UDPConn,requestedHost string,requestedPort uint16){
	var clientAddr *net.UDPAddr
	var clientMu sync.Mutex
	if requestedPort!=0&&requestedHost!=""&&requestedHost!="0.0.0.0"&&requestedHost!="::"{
		if ip:=net.ParseIP(requestedHost);ip!=nil{clientAddr=&net.UDPAddr{IP:ip,Port:int(requestedPort)}}
	}
	buf:=make([]byte,65535)
	for{
		n,source,err:=udp.ReadFromUDP(buf);if err!=nil{return}
		clientMu.Lock()
		if clientAddr==nil{clientAddr=&net.UDPAddr{IP:append(net.IP(nil),source.IP...),Port:source.Port}}
		allowed:=sameUDP(clientAddr,source);target:=clientAddr
		clientMu.Unlock()
		if !allowed{continue}
		remote,payload,err:=parseUDPRequest(buf[:n]);if err!=nil{continue}
		isDNS:=s.DNSForward&&remote.Port==53
		replyFn:=func(data []byte){packet,e:=makeUDPResponse(remote,data);if e!=nil{return};_,_=udp.WriteToUDP(packet,target)}
		if isDNS {
			response, forwardErr := s.forwardDNS(payload)
			if forwardErr == nil { replyFn(response) }
			continue
		}
		if s.UDPOnlyDNS || s.UDP == nil { continue }
		_=s.UDP.Send(id,remote,payload,false,replyFn)
	}
}

func(s *Server)forwardDNS(query []byte)([]byte,error){
	if len(query)==0||len(query)>65535{return nil,errors.New("invalid DNS query length")}
	if s.DNSResolver==""{return nil,errors.New("DNS resolver is not configured")}
	conn,err:=s.Dial("tcp",net.JoinHostPort(s.DNSResolver,"53"))
	if err!=nil{return nil,err}
	defer conn.Close()
	_=conn.SetDeadline(time.Now().Add(10*time.Second))
	var length [2]byte
	binary.BigEndian.PutUint16(length[:],uint16(len(query)))
	if err=writeFull(conn,length[:]);err!=nil{return nil,err}
	if err=writeFull(conn,query);err!=nil{return nil,err}
	if _,err=io.ReadFull(conn,length[:]);err!=nil{return nil,err}
	n:=int(binary.BigEndian.Uint16(length[:]))
	if n==0{return nil,errors.New("empty DNS response")}
	response:=make([]byte,n)
	if _,err=io.ReadFull(conn,response);err!=nil{return nil,err}
	return response,nil
}

func writeFull(w io.Writer,data []byte)error{
	for len(data)>0{
		n,err:=w.Write(data)
		if err!=nil{return err}
		if n==0{return io.ErrShortWrite}
		data=data[n:]
	}
	return nil
}

func(s *Server)closeUDPAssociation(id string){
	s.mu.Lock();conn:=s.udpConns[id];delete(s.udpConns,id);s.mu.Unlock()
	if conn!=nil{_=conn.Close()}
	if s.UDP!=nil{s.UDP.CloseAssociation(id)}
}

func readAddress(r io.Reader,atyp byte)(string,uint16,error){
	var host string
	switch atyp{
	case 1:b:=make([]byte,4);if _,err:=io.ReadFull(r,b);err!=nil{return "",0,err};host=net.IP(b).String()
	case 3:var n [1]byte;if _,err:=io.ReadFull(r,n[:]);err!=nil{return "",0,err};b:=make([]byte,int(n[0]));if _,err:=io.ReadFull(r,b);err!=nil{return "",0,err};host=string(b)
	case 4:b:=make([]byte,16);if _,err:=io.ReadFull(r,b);err!=nil{return "",0,err};host=net.IP(b).String()
	default:return "",0,errors.New("unsupported SOCKS5 address type")
	}
	var p [2]byte;if _,err:=io.ReadFull(r,p[:]);err!=nil{return "",0,err}
	return host,binary.BigEndian.Uint16(p[:]),nil
}

func parseUDPRequest(packet []byte)(*net.UDPAddr,[]byte,error){
	if len(packet)<4||packet[0]!=0||packet[1]!=0||packet[2]!=0{return nil,nil,errors.New("invalid SOCKS5 UDP header")}
	offset:=4
	var ip net.IP
	switch packet[3]{
	case 1:
		if len(packet)<offset+6{return nil,nil,errors.New("short SOCKS5 IPv4 UDP header")}
		ip=net.IPv4(packet[offset],packet[offset+1],packet[offset+2],packet[offset+3]);offset+=4
	case 4:
		if len(packet)<offset+18{return nil,nil,errors.New("short SOCKS5 IPv6 UDP header")}
		ip=net.IP(append([]byte(nil),packet[offset:offset+16]...));offset+=16
	case 3:
		if len(packet)<offset+1{return nil,nil,errors.New("short SOCKS5 domain UDP header")}
		n:=int(packet[offset]);offset++
		if len(packet)<offset+n+2{return nil,nil,errors.New("short SOCKS5 domain UDP header")}
		host:=string(packet[offset:offset+n]);offset+=n
		port:=binary.BigEndian.Uint16(packet[offset:offset+2]);offset+=2
		resolved,err:=net.ResolveUDPAddr("udp",net.JoinHostPort(host,strconv.Itoa(int(port))))
		if err!=nil{return nil,nil,err}
		return resolved,packet[offset:],nil
	default:return nil,nil,errors.New("unsupported SOCKS5 UDP address type")
	}
	port:=binary.BigEndian.Uint16(packet[offset:offset+2]);offset+=2
	return &net.UDPAddr{IP:ip,Port:int(port)},packet[offset:],nil
}

func makeUDPResponse(source *net.UDPAddr,data []byte)([]byte,error){
	if source==nil{return nil,errors.New("missing UDP source address")}
	packet:=[]byte{0,0,0}
	if ip:=source.IP.To4();ip!=nil{packet=append(packet,1);packet=append(packet,ip...)}else if ip:=source.IP.To16();ip!=nil{packet=append(packet,4);packet=append(packet,ip...)}else{return nil,errors.New("invalid UDP source address")}
	var p [2]byte;binary.BigEndian.PutUint16(p[:],uint16(source.Port))
	packet=append(packet,p[:]...);packet=append(packet,data...)
	return packet,nil
}

func sameUDP(a,b *net.UDPAddr)bool{return a!=nil&&b!=nil&&a.Port==b.Port&&a.IP.Equal(b.IP)}
