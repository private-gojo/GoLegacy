package udpgw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	flagKeepalive byte = 1 << 0
	flagRebind byte = 1 << 1
	flagDNS byte = 1 << 2
	flagIPv6 byte = 1 << 3
)

type Dialer interface {
	Dial(network,address string)(net.Conn,error)
}

type ReplyHandler func(payload []byte)

type flow struct {
	id uint16
	localID string
	remote *net.UDPAddr
	reply ReplyHandler
	rebind bool
	lastUsed time.Time
}

type Client struct {
	dialer Dialer
	address string
	maxFlows int

	mu sync.Mutex
	connectMu sync.Mutex
	writeMu sync.Mutex
	conn net.Conn
	flowsByKey map[string]*flow
	flowsByID map[uint16]*flow
	nextID uint16
	closed bool
}

func New(d Dialer,address string)*Client {
	return &Client{dialer:d,address:address,maxFlows:1024,flowsByKey:make(map[string]*flow),flowsByID:make(map[uint16]*flow)}
}

func(c *Client)Send(localID string,remote *net.UDPAddr,data []byte,isDNS bool,reply ReplyHandler)error {
	if localID==""||remote==nil{return errors.New("UDP association and remote address are required")}
	if len(data)>65507{return errors.New("UDP datagram exceeds IPv4 payload limit")}
	if err:=c.ensureConnected();err!=nil{return err}
	key:=localID+"|"+remote.String()
	c.mu.Lock()
	if c.closed{c.mu.Unlock();return errors.New("UDPGW client is closed")}
	f:=c.flowsByKey[key]
	if f==nil{
		f=c.allocateFlowLocked(key,localID,remote,reply)
	}else{
		f.reply=reply
		f.lastUsed=time.Now()
	}
	flags:=byte(0)
	if f.rebind{flags|=flagRebind}
	if isDNS{flags|=flagDNS}
	if remote.IP.To4()==nil{flags|=flagIPv6}
	id:=f.id
	c.mu.Unlock()

	packet,err:=encodeFrame(flags,id,remote,data)
	if err!=nil{return err}
	c.writeMu.Lock()
	c.mu.Lock()
	conn:=c.conn
	c.mu.Unlock()
	if conn==nil{c.writeMu.Unlock();c.markRebind();return errors.New("UDPGW stream disconnected")}
	err=writeFull(conn,packet)
	c.writeMu.Unlock()
	if err!=nil{c.markRebind();_=conn.Close();return fmt.Errorf("write UDPGW packet: %w",err)}
	c.mu.Lock()
	if current:=c.flowsByID[id];current==f{current.rebind=false;current.lastUsed=time.Now()}
	c.mu.Unlock()
	return nil
}

func(c *Client)allocateFlowLocked(key,localID string,remote *net.UDPAddr,reply ReplyHandler)*flow{
	var id uint16
	if len(c.flowsByID)<c.maxFlows{
		for {
			id=c.nextID
			c.nextID++
			if _,used:=c.flowsByID[id];!used{break}
		}
	}else{
		var oldest *flow
		for _,candidate:=range c.flowsByID{if oldest==nil||candidate.lastUsed.Before(oldest.lastUsed){oldest=candidate}}
		id=oldest.id
		delete(c.flowsByKey,oldest.localID+"|"+oldest.remote.String())
		delete(c.flowsByID,id)
	}
	f:=&flow{id:id,localID:localID,remote:cloneUDPAddr(remote),reply:reply,rebind:true,lastUsed:time.Now()}
	c.flowsByKey[key]=f
	c.flowsByID[id]=f
	return f
}

func(c *Client)ensureConnected()error{
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	c.mu.Lock()
	if c.closed{c.mu.Unlock();return errors.New("UDPGW client is closed")}
	if c.conn!=nil{c.mu.Unlock();return nil}
	c.mu.Unlock()
	if c.dialer==nil{return errors.New("UDPGW SSH dialer is not configured")}
	conn,err:=c.dialer.Dial("tcp",c.address)
	if err!=nil{return fmt.Errorf("connect UDPGW %s: %w",c.address,err)}
	c.mu.Lock()
	if c.closed{c.mu.Unlock();_=conn.Close();return errors.New("UDPGW client is closed")}
	if c.conn!=nil{c.mu.Unlock();_=conn.Close();return nil}
	c.conn=conn
	for _,f:=range c.flowsByID{f.rebind=true}
	c.mu.Unlock()
	go c.readLoop(conn)
	go c.keepalive(conn)
	return nil
}

func(c *Client)readLoop(conn net.Conn){
	for{
		frame,err:=readFrame(conn)
		if err!=nil{
			c.mu.Lock()
			if c.conn==conn{c.conn=nil;for _,f:=range c.flowsByID{f.rebind=true}}
			c.mu.Unlock()
			_=conn.Close()
			return
		}
		flags,id,remote,data,err:=decodeDatagram(frame)
		if err!=nil||flags&flagKeepalive!=0{continue}
		c.mu.Lock()
		f:=c.flowsByID[id]
		if f==nil||!sameUDPAddr(f.remote,remote){c.mu.Unlock();continue}
		f.lastUsed=time.Now()
		reply:=f.reply
		c.mu.Unlock()
		if reply!=nil{reply(data)}
	}
}

func(c *Client)keepalive(conn net.Conn){
	t:=time.NewTicker(20*time.Second);defer t.Stop()
	for range t.C{
		c.mu.Lock();active:=!c.closed&&c.conn==conn;c.mu.Unlock()
		if !active{return}
		packet,_:=encodeFrame(flagKeepalive,0,nil,nil)
		c.writeMu.Lock();err:=writeFull(conn,packet);c.writeMu.Unlock()
		if err!=nil{_=conn.Close();return}
	}
}

func(c *Client)markRebind(){
	c.mu.Lock();defer c.mu.Unlock()
	for _,f:=range c.flowsByID{f.rebind=true}
}

func(c *Client)CloseAssociation(localID string){
	c.mu.Lock();defer c.mu.Unlock()
	for key,f:=range c.flowsByKey{
		if f.localID==localID{delete(c.flowsByKey,key);delete(c.flowsByID,f.id)}
	}
}

func(c *Client)Close()error{
	c.mu.Lock()
	if c.closed{c.mu.Unlock();return nil}
	c.closed=true
	conn:=c.conn;c.conn=nil
	c.flowsByKey=make(map[string]*flow);c.flowsByID=make(map[uint16]*flow)
	c.mu.Unlock()
	if conn!=nil{return conn.Close()}
	return nil
}

func encodeFrame(flags byte,id uint16,remote *net.UDPAddr,data []byte)([]byte,error){
	body:=make([]byte,3)
	body[0]=flags
	binary.LittleEndian.PutUint16(body[1:3],id)
	if flags&flagKeepalive==0{
		if remote==nil{return nil,errors.New("UDP remote address is required")}
		if ip:=remote.IP.To4();ip!=nil{
			body=append(body,ip...)
		}else if ip:=remote.IP.To16();ip!=nil{
			body[0]|=flagIPv6
			body=append(body,ip...)
		}else{return nil,errors.New("invalid UDP remote IP")}
		var port [2]byte
		binary.BigEndian.PutUint16(port[:],uint16(remote.Port))
		body=append(body,port[:]...)
		body=append(body,data...)
	}
	if len(body)>65535{return nil,errors.New("UDPGW frame too large")}
	out:=make([]byte,2+len(body))
	binary.LittleEndian.PutUint16(out[:2],uint16(len(body)))
	copy(out[2:],body)
	return out,nil
}

func decodeDatagram(body []byte)(byte,uint16,*net.UDPAddr,[]byte,error){
	if len(body)<3{return 0,0,nil,nil,errors.New("short UDPGW packet")}
	flags:=body[0]
	id:=binary.LittleEndian.Uint16(body[1:3])
	if flags&flagKeepalive!=0{return flags,id,nil,nil,nil}
	offset:=3
	var ip net.IP
	if flags&flagIPv6!=0{
		if len(body)<offset+18{return 0,0,nil,nil,errors.New("short UDPGW IPv6 packet")}
		ip=net.IP(append([]byte(nil),body[offset:offset+16]...));offset+=16
	}else{
		if len(body)<offset+6{return 0,0,nil,nil,errors.New("short UDPGW IPv4 packet")}
		ip=net.IPv4(body[offset],body[offset+1],body[offset+2],body[offset+3]);offset+=4
	}
	port:=int(binary.BigEndian.Uint16(body[offset:offset+2]));offset+=2
	return flags,id,&net.UDPAddr{IP:ip,Port:port},body[offset:],nil
}

func readFrame(r io.Reader)([]byte,error){
	var h [2]byte
	if _,err:=io.ReadFull(r,h[:]);err!=nil{return nil,err}
	n:=int(binary.LittleEndian.Uint16(h[:]))
	if n<3{return nil,errors.New("invalid UDPGW packet length")}
	body:=make([]byte,n)
	if _,err:=io.ReadFull(r,body);err!=nil{return nil,err}
	return body,nil
}

func writeFull(w io.Writer,b []byte)error{
	for len(b)>0{n,err:=w.Write(b);if err!=nil{return err};if n==0{return io.ErrShortWrite};b=b[n:]}
	return nil
}

func cloneUDPAddr(a *net.UDPAddr)*net.UDPAddr{return &net.UDPAddr{IP:append(net.IP(nil),a.IP...),Port:a.Port,Zone:a.Zone}}
func sameUDPAddr(a,b *net.UDPAddr)bool{return a!=nil&&b!=nil&&a.Port==b.Port&&a.IP.Equal(b.IP)}

func ParseEndpoint(value string)(string,error){
	host,port,err:=net.SplitHostPort(value);if err!=nil{return "",err}
	n,err:=strconv.Atoi(port);if err!=nil||n<1||n>65535{return "",errors.New("invalid UDPGW port")}
	if host==""{return "",errors.New("invalid UDPGW host")}
	return net.JoinHostPort(host,port),nil
}
