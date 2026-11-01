package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"dev.go.core/internal/profile"
)

const (
	legacyAESPassword = "fubvx788b46v"
	legacyDESPassword = "cinbdf665$4"
	legacyIterations = 1000
	legacySaltBytes = 32
	legacyAESKeyBytes = 16
	legacyGCMNonceBytes = 12
)

type Imported struct {
	Profile profile.Profile `json:"profile"`
	Locked bool `json:"locked"`
	ExpiryUnixMilli int64 `json:"expiryUnixMilli"`
	Message string `json:"message"`
	BlockRoot bool `json:"blockRoot"`
	LegacyFormat string `json:"legacyFormat"`
}

type propertiesDocument struct {
	Entries []propertyEntry `xml:"entry"`
}

type propertyEntry struct {
	Key string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func ImportSKS(raw []byte, appVersionCode int, now time.Time) (Imported, error) {
	var result Imported
	plain, format, err := decryptLegacy(raw)
	if err != nil { return result, fmt.Errorf("decrypt .sks: %w", err) }
	var document propertiesDocument
	if err := xml.Unmarshal(plain, &document); err != nil { return result, fmt.Errorf("parse .sks XML: %w", err) }
	props := make(map[string]string, len(document.Entries))
	for _, entry := range document.Entries { props[entry.Key] = entry.Value }
	if len(props) == 0 { return result, errors.New("profile contains no properties") }
	for _, key := range []string{"file.proteger", "file.validade", "usarDefaultPayload", "sshPortaLocal"} {
		if _, ok := props[key]; !ok { return result, fmt.Errorf("missing required profile property %q", key) }
	}

	version, err := requiredInt(props, "file.appVersionCode")
	if err != nil { return result, err }
	if version > appVersionCode { return result, fmt.Errorf("profile requires app version code %d; current is %d", version, appVersionCode) }

	protected := props["file.proteger"] == "1"
	expiry := int64(0)
	if rawExpiry := props["file.validade"]; rawExpiry != "" {
		expiry, err = strconv.ParseInt(rawExpiry, 10, 64)
		if err != nil { return result, errors.New("invalid profile expiry") }
	} else if protected {
		return result, errors.New("locked profile is missing expiry")
	}
	if !protected || expiry < 0 { expiry = 0 }
	if protected && expiry > 0 && now.UnixMilli() >= expiry { return result, errors.New("profile has expired") }

	localPort, err := requiredInt(props, "sshPortaLocal")
	if err != nil || localPort < 1 || localPort > 65535 { return result, errors.New("invalid local SOCKS port") }

	host := props["sshServer"]
	port, err := parsePort(props["sshPort"])
	if err != nil { return result, fmt.Errorf("SSH port: %w", err) }
	username := props["sshUser"]
	if host == "" || username == "" { return result, errors.New("profile is missing SSH host or username") }

	mode := profile.ModeDirect
	switch props["tunnelType"] {
	case "sshProxy", "2": mode = profile.ModeProxy
	case "sshSslTunnel", "3": mode = profile.ModeSSL
	case "Payload+SSL", "4": mode = profile.ModePayloadSSL
	case "", "sshDirect", "1":
	default: return result, fmt.Errorf("unsupported legacy tunnel type %q", props["tunnelType"])
	}
	proxyPort := uint16(0)
	if props["proxyRemotoPorta"] != "" {
		proxyPort, err = parsePort(props["proxyRemotoPorta"])
		if err != nil { return result, fmt.Errorf("proxy port: %w", err) }
	}
	payloadText := props["proxyPayload"]
	if props["usarDefaultPayload"] == "1" { payloadText = "CONNECT [host_port] [protocol][crlf][crlf]" }
	dnsResolver := props["dnsResolver"]
	if dnsResolver == "" { dnsResolver = "1.1.1.1" }
	udpResolver := props["udpResolver"]
	if udpResolver == "" { udpResolver = "127.0.0.1:7300" }

	p := profile.Profile{
		Name: props["profileName"], Mode: mode, Host: host, Port: port,
		Username: username, Password: props["sshPass"],
		ProxyHost: props["proxyRemoto"], ProxyPort: proxyPort,
		SNI: props["sslSNI"], Payload: payloadText,
		AcceptAnyStatus: true,
		DisableDelaySSH: props["disableDelaySSH"] == "1",
		UDPForward: props["udpForward"] == "1", UDPResolver: udpResolver,
		DNSForward: props["dnsForward"] != "0", DNSResolver: dnsResolver,
	}
	if err := p.Validate(); err != nil { return result, fmt.Errorf("invalid imported profile: %w", err) }

	result = Imported{
		Profile: p, Locked: protected, ExpiryUnixMilli: expiry,
		Message: props["file.msg"], BlockRoot: props["bloquearRoot"] == "1",
		LegacyFormat: format,
	}
	return result, nil
}

func decryptLegacy(raw []byte) ([]byte, string, error) {
	encoded := strings.TrimSpace(string(raw))
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 { plain, err := decryptDES(raw); return plain, "des-legacy", err }
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil { plain, fallbackErr := decryptDES(raw); return plain, "des-legacy", fallbackErr }
	nonce, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil { plain, fallbackErr := decryptDES(raw); return plain, "des-legacy", fallbackErr }
	ciphertext, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil { plain, fallbackErr := decryptDES(raw); return plain, "des-legacy", fallbackErr }
	if len(salt) != legacySaltBytes || len(nonce) != legacyGCMNonceBytes {
		plain, fallbackErr := decryptDES(raw)
		return plain, "des-legacy", fallbackErr
	}
	key := pbkdf2.Key([]byte(legacyAESPassword), salt, legacyIterations, legacyAESKeyBytes, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil { return nil, "", err }
	aead, err := cipher.NewGCM(block)
	if err != nil { return nil, "", err }
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil { return nil, "aes-gcm", fmt.Errorf("AES-GCM authentication failed: %w", err) }
	return plain, "aes-gcm", nil
}

func decryptDES(raw []byte) ([]byte, error) {
	key := []byte(legacyDESPassword)
	if len(key) < 8 { return nil, errors.New("invalid legacy DES key") }
	block, err := des.NewCipher(key[:8])
	if err != nil { return nil, err }
	data := raw
	if len(data) == 0 || len(data)%des.BlockSize != 0 { return nil, errors.New("invalid legacy DES ciphertext length") }
	plain := make([]byte, len(data))
	for offset := 0; offset < len(data); offset += des.BlockSize {
		block.Decrypt(plain[offset:offset+des.BlockSize], data[offset:offset+des.BlockSize])
	}
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > des.BlockSize || padding > len(plain) { return nil, errors.New("invalid legacy DES padding") }
	for _, value := range plain[len(plain)-padding:] {
		if int(value) != padding { return nil, errors.New("invalid legacy DES padding") }
	}
	return plain[:len(plain)-padding], nil
}

func requiredInt(props map[string]string, key string) (int, error) {
	value := props[key]
	if value == "" { return 0, fmt.Errorf("missing required profile property %q", key) }
	n, err := strconv.Atoi(value)
	if err != nil { return 0, fmt.Errorf("invalid profile property %q", key) }
	return n, nil
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 { return 0, errors.New("must be between 1 and 65535") }
	return uint16(n), nil
}

var _ io.Reader = (*bytes.Reader)(nil)
