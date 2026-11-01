package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

func TestDecryptLegacyAESGCM(t *testing.T) {
	plain := []byte("<properties><entry key=\"file.appVersionCode\">1</entry></properties>")
	salt := bytes.Repeat([]byte{0x31}, legacySaltBytes)
	nonce := bytes.Repeat([]byte{0x52}, legacyGCMNonceBytes)
	key := pbkdf2.Key([]byte(legacyAESPassword), salt, legacyIterations, legacyAESKeyBytes, sha256.New)
	block, err := aes.NewCipher(key); if err != nil { t.Fatal(err) }
	aead, err := cipher.NewGCM(block); if err != nil { t.Fatal(err) }
	ciphertext := aead.Seal(nil, nonce, plain, nil)
	raw := []byte(base64.StdEncoding.EncodeToString(salt)+"."+base64.StdEncoding.EncodeToString(nonce)+"."+base64.StdEncoding.EncodeToString(ciphertext))
	got, format, err := decryptLegacy(raw)
	if err != nil || format != "aes-gcm" || !bytes.Equal(got, plain) { t.Fatalf("format=%q err=%v", format, err) }
}

func TestDecryptLegacyDES(t *testing.T) {
	plain := []byte("<properties/>")
	key := []byte(legacyDESPassword)[:8]
	block, err := des.NewCipher(key); if err != nil { t.Fatal(err) }
	padding := des.BlockSize-len(plain)%des.BlockSize
	padded := append(append([]byte(nil),plain...),bytes.Repeat([]byte{byte(padding)},padding)...)
	ciphertext := make([]byte,len(padded))
	for i:=0;i<len(padded);i+=des.BlockSize { block.Encrypt(ciphertext[i:i+des.BlockSize],padded[i:i+des.BlockSize]) }
	got, format, err := decryptLegacy(ciphertext)
	if err != nil || format!="des-legacy" || !bytes.Equal(got,plain) { t.Fatalf("format=%q err=%v",format,err) }
}

func TestImportSKSLockedMetadata(t *testing.T) {
	props:=map[string]string{
		"file.appVersionCode":"644","file.proteger":"1","file.validade":"0","file.msg":"locked profile",
		"sshServer":"ssh.example.test","sshPort":"22","sshPortaLocal":"1080","sshUser":"account","sshPass":"secret",
		"tunnelType":"sshDirect","usarDefaultPayload":"1","dnsForward":"1","dnsResolver":"1.1.1.1",
		"udpForward":"1","udpResolver":"127.0.0.1:7300",
	}
	var b bytes.Buffer
	b.WriteString(xml.Header+"<properties>")
	for k,v:=range props { b.WriteString("<entry key=\""+k+"\">"+v+"</entry>") }
	b.WriteString("</properties>")
	salt:=bytes.Repeat([]byte{7},legacySaltBytes);nonce:=make([]byte,legacyGCMNonceBytes);if _,err:=rand.Read(nonce);err!=nil{t.Fatal(err)}
	key:=pbkdf2.Key([]byte(legacyAESPassword),salt,legacyIterations,legacyAESKeyBytes,sha256.New)
	block,_:=aes.NewCipher(key);aead,_:=cipher.NewGCM(block)
	encoded:=base64.StdEncoding.EncodeToString(salt)+"."+base64.StdEncoding.EncodeToString(nonce)+"."+base64.StdEncoding.EncodeToString(aead.Seal(nil,nonce,b.Bytes(),nil))
	got,err:=ImportSKS([]byte(encoded),644,time.UnixMilli(1))
	if err!=nil{t.Fatal(err)}
	if !got.Locked||got.Message!="locked profile"||got.Profile.Host!="ssh.example.test"||got.Profile.LocalSocksPort!=1080||!got.Profile.UDPForward{t.Fatalf("unexpected import: %+v",got)}
}

func TestImportSKSRejectsExpired(t *testing.T) {
	raw := encryptTestProperties(t, map[string]string{
		"file.appVersionCode":"644","file.proteger":"1","file.validade":"1000","file.msg":"expired",
		"sshServer":"ssh.example.test","sshPort":"22","sshPortaLocal":"1080","sshUser":"account","sshPass":"secret",
		"tunnelType":"sshDirect","usarDefaultPayload":"1","dnsForward":"1","dnsResolver":"1.1.1.1",
		"udpForward":"0","udpResolver":"127.0.0.1:7300",
	})
	if _, err := ImportSKS(raw, 644, time.UnixMilli(1000)); err == nil {
		t.Fatal("expired profile accepted")
	}
}

func encryptTestProperties(t *testing.T, props map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(xml.Header+"<properties>")
	for k, v := range props { b.WriteString("<entry key=\"" + k + "\">" + v + "</entry>") }
	b.WriteString("</properties>")
	salt := bytes.Repeat([]byte{7}, legacySaltBytes)
	nonce := make([]byte, legacyGCMNonceBytes)
	if _, err := rand.Read(nonce); err != nil { t.Fatal(err) }
	key := pbkdf2.Key([]byte(legacyAESPassword), salt, legacyIterations, legacyAESKeyBytes, sha256.New)
	block, err := aes.NewCipher(key); if err != nil { t.Fatal(err) }
	aead, err := cipher.NewGCM(block); if err != nil { t.Fatal(err) }
	encoded := base64.StdEncoding.EncodeToString(salt)+"."+base64.StdEncoding.EncodeToString(nonce)+"."+base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, b.Bytes(), nil))
	return []byte(encoded)
}
