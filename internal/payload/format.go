package payload

import (
	"crypto/rand"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Context struct {
	Method string
	Host string
	Port uint16
	Protocol string
	SSH string
	UserAgent string
}

type Formatter struct {
	mu sync.Mutex
	lastPayload string
	rotateIndex map[int]int
}

var rotatePattern = regexp.MustCompile(`\[rotate=(.*?)\]`)
var randomPattern = regexp.MustCompile(`\[random=(.*?)\]`)

func NewFormatter()*Formatter{return &Formatter{rotateIndex:make(map[int]int)}}

func(f *Formatter)Format(src string,c Context)[]byte{
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rotateIndex==nil{f.rotateIndex=make(map[int]int)}
	hostPort:=c.Host+":"+strconv.Itoa(int(c.Port));if c.SSH!=""{hostPort=c.SSH}
	if c.Method==""{c.Method="CONNECT"};if c.Protocol==""{c.Protocol="HTTP/1.0"}
	if c.UserAgent==""{c.UserAgent="Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36"}
	out:=strings.NewReplacer(
		"[method]",c.Method,"[host]",c.Host,"[port]",strconv.Itoa(int(c.Port)),
		"[host_port]",hostPort,"[protocol]",c.Protocol,"[ssh]",hostPort,
		"[crlf]","\r\n","[cr]","\r","[lf]","\n","[lfcr]","\n\r",
		"\\n","\n","\\r","\r","[ua]",c.UserAgent,
	).Replace(src)
	if out!=f.lastPayload{clear(f.rotateIndex);f.lastPayload=out}
	for i,m:=range rotatePattern.FindAllStringSubmatch(out,-1){
		choices:=strings.Split(m[1],";");if len(choices)==0{continue}
		next:=0;if old,ok:=f.rotateIndex[i];ok{next=(old+1)%len(choices)}
		out=strings.ReplaceAll(out,m[0],choices[next]);f.rotateIndex[i]=next
	}
	for _,m:=range randomPattern.FindAllStringSubmatch(out,-1){
		choices:=strings.Split(m[1],";");if len(choices)==0{continue}
		n,err:=rand.Int(rand.Reader,big.NewInt(int64(len(choices))));if err==nil{out=strings.ReplaceAll(out,m[0],choices[n.Int64()])}
	}
	return []byte(out)
}

func Format(src string,c Context)([]byte,error){return NewFormatter().Format(src,c),nil}

type flushWriter interface{Write([]byte)(int,error);Flush()error}

func InjectSplitPayload(request string,out flushWriter)(bool,error){
	if strings.Contains(request,"[delay_split]"){
		parts:=javaSplit(request,"[delay_split]")
		for i,part:=range parts{
			handled,err:=injectSimpleSplit(part,out);if err!=nil{return true,err}
			if !handled{if _,err=out.Write(latin1(part));err!=nil{return true,err};if err=out.Flush();err!=nil{return true,err}}
			if i!=len(parts)-1{time.Sleep(time.Second)}
		}
		return true,nil
	}
	return injectSimpleSplit(request,out)
}

func injectSimpleSplit(request string,out flushWriter)(bool,error){
	if !strings.Contains(request,"[split]"){return false,nil}
	for _,part:=range javaSplit(request,"[split]"){
		if _,err:=out.Write(latin1(part));err!=nil{return true,err}
		if err:=out.Flush();err!=nil{return true,err}
	}
	return true,nil
}

func javaSplit(value,separator string)[]string{
	parts:=strings.Split(value,separator)
	for len(parts)>0&&parts[len(parts)-1]==""{parts=parts[:len(parts)-1]}
	return parts
}

func latin1(value string)[]byte{
	out:=make([]byte,0,len(value))
	for _,r:=range value{if r>255{out=append(out,'?')}else{out=append(out,byte(r))}}
	return out
}

func HostPort(host string,port uint16)string{return net.JoinHostPort(host,strconv.Itoa(int(port)))}
