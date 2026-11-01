package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"dev.go.core/internal/profile"
)

const (
	lockedMagic = "GOLK"
	lockedVersion byte = 1
	lockedHeaderSize = 16
	lockedFlagEncrypted byte = 1
	lockedKDFArgon2id byte = 1
	lockedCipherAESGCM byte = 1
	lockedSaltSize = 16
	lockedNonceSize = 12
	lockedKeySize = 32
	lockedMaxPayload = 1 << 20
	lockedArgonTime uint32 = 2
	lockedArgonMemory uint32 = 32 * 1024
	lockedArgonThreads uint8 = 1
)

type LockedConfig struct {
	Profile profile.Profile `json:"profile"`
	Locked bool `json:"locked"`
	ExpiryUnixMilli int64 `json:"expiryUnixMilli,omitempty"`
	Message string `json:"message,omitempty"`
	BlockRoot bool `json:"blockRoot,omitempty"`
}

func EncodeLockedURI(config LockedConfig, passcode string) (string, error) {
	if err := config.Profile.Validate(); err != nil { return "", err }
	config.Locked = true
	plain, err := json.Marshal(config)
	if err != nil { return "", err }
	if len(plain) > lockedMaxPayload { return "", errors.New("locked profile exceeds 1 MiB") }

	flags, kdf, cipherID := byte(0), byte(0), byte(0)
	salt, nonce := []byte(nil), []byte(nil)
	payloadLength := len(plain)
	if passcode != "" {
		if len(passcode) < 8 { return "", errors.New("passcode must contain at least 8 characters") }
		flags, kdf, cipherID = lockedFlagEncrypted, lockedKDFArgon2id, lockedCipherAESGCM
		salt = make([]byte, lockedSaltSize)
		nonce = make([]byte, lockedNonceSize)
		if _, err := rand.Read(salt); err != nil { return "", err }
		if _, err := rand.Read(nonce); err != nil { return "", err }
		payloadLength += 16
	}
	header := make([]byte, lockedHeaderSize)
	copy(header[:4], lockedMagic)
	header[4], header[5], header[6], header[7] = lockedVersion, flags, kdf, cipherID
	header[8], header[9] = byte(len(salt)), byte(len(nonce))
	binary.BigEndian.PutUint32(header[12:16], uint32(payloadLength))

	payload := plain
	if passcode != "" {
		key := argon2.IDKey([]byte(passcode), salt, lockedArgonTime, lockedArgonMemory, lockedArgonThreads, lockedKeySize)
		block, err := aes.NewCipher(key); if err != nil { return "", err }
		aead, err := cipher.NewGCM(block); if err != nil { return "", err }
		aad := append(append(append([]byte(nil), header...), salt...), nonce...)
		payload = aead.Seal(nil, nonce, plain, aad)
	}
	blob := append(header, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, payload...)
	encoded := base64.RawURLEncoding.EncodeToString(blob)
	return "go-ssh://locked/" + encoded, nil
}

func DecodeLockedURI(uri, passcode string, now time.Time) (LockedConfig, error) {
	var result LockedConfig
	if len(uri) > 2*lockedMaxPayload { return result, errors.New("locked profile URI is too large") }
	u, err := url.Parse(uri)
	if err != nil { return result, err }
	if u.RawQuery != "" || u.Fragment != "" { return result, errors.New("unexpected locked profile URI parameters") }
	if u.Scheme != "go-ssh" || u.Host != "locked" { return result, errors.New("unsupported locked profile URI") }
	encoded := strings.TrimPrefix(u.EscapedPath(), "/")
	blob, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil { return result, fmt.Errorf("decode locked profile: %w", err) }
	if len(blob) < lockedHeaderSize || string(blob[:4]) != lockedMagic { return result, errors.New("invalid locked profile header") }
	header := blob[:lockedHeaderSize]
	if header[4] != lockedVersion { return result, fmt.Errorf("unsupported locked profile version %d", header[4]) }
	if header[5]&^lockedFlagEncrypted != 0 || header[10] != 0 || header[11] != 0 { return result, errors.New("invalid locked profile flags") }
	saltLen, nonceLen := int(header[8]), int(header[9])
	payloadLen := int(binary.BigEndian.Uint32(header[12:16]))
	if payloadLen < 1 || payloadLen > lockedMaxPayload+16 { return result, errors.New("invalid locked profile payload length") }
	if len(blob) != lockedHeaderSize+saltLen+nonceLen+payloadLen { return result, errors.New("locked profile length mismatch") }
	offset := lockedHeaderSize
	salt := blob[offset:offset+saltLen]; offset += saltLen
	nonce := blob[offset:offset+nonceLen]; offset += nonceLen
	payload := blob[offset:]
	var plain []byte

	if header[5]&lockedFlagEncrypted != 0 {
		if passcode == "" { return result, errors.New("locked profile requires a passcode") }
		if header[6] != lockedKDFArgon2id || header[7] != lockedCipherAESGCM || saltLen != lockedSaltSize || nonceLen != lockedNonceSize {
			return result, errors.New("unsupported locked profile encryption parameters")
		}
		key := argon2.IDKey([]byte(passcode), salt, lockedArgonTime, lockedArgonMemory, lockedArgonThreads, lockedKeySize)
		block, err := aes.NewCipher(key); if err != nil { return result, err }
		aead, err := cipher.NewGCM(block); if err != nil { return result, err }
		aad := append(append(append([]byte(nil), header...), salt...), nonce...)
		plain, err = aead.Open(nil, nonce, payload, aad)
		if err != nil { return result, errors.New("locked profile passcode is incorrect or data was modified") }
	} else {
		if header[6] != 0 || header[7] != 0 || saltLen != 0 || nonceLen != 0 { return result, errors.New("invalid plaintext locked profile parameters") }
		plain = payload
	}

	if err := json.Unmarshal(plain, &result); err != nil { return result, fmt.Errorf("parse locked profile: %w", err) }
	if !result.Locked { return result, errors.New("profile is not marked locked") }
	if result.ExpiryUnixMilli < 0 { return result, errors.New("invalid locked profile expiry") }
	if result.ExpiryUnixMilli > 0 && now.UnixMilli() >= result.ExpiryUnixMilli { return result, errors.New("profile has expired") }
	if err := result.Profile.Validate(); err != nil { return result, fmt.Errorf("invalid locked profile: %w", err) }
	return result, nil
}
