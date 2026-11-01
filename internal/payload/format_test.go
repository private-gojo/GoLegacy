package payload

import (
	"bytes"
	"testing"
)

type flushBuffer struct { bytes.Buffer; flushes int }
func(b *flushBuffer)Flush()error{b.flushes++;return nil}

func TestLegacyPayloadTokens(t *testing.T){
	f:=NewFormatter()
	got:=string(f.Format("[method] [host_port] [protocol][crlf][ua]",Context{Host:"example.test",Port:443}))
	prefix:="CONNECT example.test:443 HTTP/1.0\r\n"
	if len(got)<len(prefix)||got[:len(prefix)]!=prefix{t.Fatalf("unexpected format: %q",got)}
}

func TestRotateAdvancesAndResetsOnPayloadChange(t *testing.T){
	f:=NewFormatter();ctx:=Context{Host:"h",Port:22}
	if got:=string(f.Format("[rotate=a;b]",ctx));got!="a"{t.Fatalf("first=%q",got)}
	if got:=string(f.Format("[rotate=a;b]",ctx));got!="b"{t.Fatalf("second=%q",got)}
	if got:=string(f.Format("[rotate=x;y]",ctx));got!="x"{t.Fatalf("reset=%q",got)}
}

func TestRandomSelectsChoice(t *testing.T){
	got:=string(NewFormatter().Format("[random=a;b;c]",Context{}))
	if got!="a"&&got!="b"&&got!="c"{t.Fatalf("invalid random selection %q",got)}
}

func TestSplitFlushBoundaries(t *testing.T){
	b:=&flushBuffer{}
	handled,err:=InjectSplitPayload("A[split]B",b)
	if err!=nil||!handled{t.Fatalf("handled=%v err=%v",handled,err)}
	if b.String()!="AB"||b.flushes!=2{t.Fatalf("body=%q flushes=%d",b.String(),b.flushes)}
}

func TestGeneratorOnlyMarkersRemainLiteral(t *testing.T){
	got:=string(NewFormatter().Format("[instant_split][raw]",Context{}))
	if got!="[instant_split][raw]"{t.Fatalf("markers changed: %q",got)}
}

func TestLatin1Encoding(t *testing.T){
	got:=EncodeLatin1("Aé€")
	want:=[]byte{65,233,'?'}
	if !bytes.Equal(got,want){t.Fatalf("got=%v want=%v",got,want)}
}
