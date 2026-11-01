package payload

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Context struct {
	Method string
	Host string
	Port uint16
	Protocol string
	SSH string
	UserAgent string
}

func Format(src string, c Context) ([]byte, error) {
	hostPort := net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port)))
	repl := strings.NewReplacer(
		"[method]", c.Method, "[host]", c.Host, "[port]", strconv.Itoa(int(c.Port)),
		"[host_port]", hostPort, "[protocol]", c.Protocol, "[ssh]", c.SSH,
		"[ua]", c.UserAgent, "[crlf]", "\r\n", "[cr]", "\r", "[lf]", "\n", "[lfcr]", "\n\r",
		"\\n", "\n", "\\r", "\r",
	)
	out := repl.Replace(src)
	for {
		start := strings.Index(out, "[random=")
		if start < 0 { break }
		end := strings.IndexByte(out[start:], ']')
		if end < 0 { return nil, errors.New("unterminated random token") }
		end += start
		n, err := strconv.Atoi(out[start+8:end])
		if err != nil || n < 1 || n > 64 { return nil, fmt.Errorf("invalid random token at byte %d", start) }
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil { return nil, err }
		out = out[:start] + hex.EncodeToString(buf)[:n] + out[end+1:]
	}
	for {
		start := strings.Index(out, "[rotate=")
		if start < 0 { break }
		end := strings.IndexByte(out[start:], ']')
		if end < 0 { return nil, errors.New("unterminated rotate token") }
		end += start
		raw := strings.Split(out[start+8:end], "|")
		if len(raw) == 0 { return nil, errors.New("empty rotate token") }
		out = out[:start] + raw[0] + out[end+1:]
	}
	return []byte(out), nil
}

func EncodeQuery(value string) string { return url.QueryEscape(value) }
