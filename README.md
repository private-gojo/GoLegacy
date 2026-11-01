# Go

Standalone Android SSH tunneling client.

## Project status

Experimental port of `private-gojo/Legacy-Evolved`, baseline commit `3d0b1838c0978051fb779a18bab37ac7a21e701f`.

The repository now contains the Go SSH transport foundation, local SOCKS5 server, SSH UDPGW adapter, Android `VpnService`, HEV integration, profile import/export code, and CI integration tests. A successful CI build is not equivalent to a verified VPN session on a physical Android device. Treat this as an engineering build until device-level TCP, UDP, DNS, reconnect, and battery tests are completed.

## Architecture

- Android application: Kotlin, package `dev.go.core`
- Tunnel engine: Go
- SSH: `golang.org/x/crypto/ssh`
- TUN forwarding: official HEV SOCKS5 Tunnel AAR
- Android tunnel lifecycle: `VpnService`
- Go/Android bridge: one consolidated gomobile AAR
- UDP: SOCKS5 UDP ASSOCIATE to BadVPN UDPGW over the SSH connection

HEV is kept as a separate native AAR; it is not reimplemented in Go. The HEV Android build currently targets API 29, so the application minimum SDK is 29.

## Implemented

- SSH password and private-key authentication
- Legacy SSH client identification string
- Default accept-all SSH host-key behavior, with optional SHA-256 pinning
- Default trust-all TLS behavior, with optional certificate verification or SHA-256 pinning
- Direct SSH, HTTP proxy, TLS, and payload-over-TLS dial paths
- Payload tokens, split writes, delayed split writes, random and rotation tokens
- TCP_NODELAY profile control
- Local SOCKS5 TCP CONNECT and UDP ASSOCIATE
- SSH UDPGW framing, flow management, reconnect/rebind, and keepalive
- Android VPN permission and service lifecycle
- Legacy `.sks` import only
- `ssh://` profile URI import
- Versioned `go-ssh://locked/` profile import/export
- Optional Argon2id + AES-256-GCM passcode encryption for locked profiles
- Locked profile expiry and message metadata

## Deliberate compatibility defaults

- SSH host-key verification is disabled by default; configure a SHA-256 pin to enable it.
- TLS certificate verification is disabled by default; enable verification or configure a certificate fingerprint.
- Proxy status acceptance defaults to permissive mode to preserve legacy behavior.
- TCP_NODELAY defaults to enabled, matching the legacy setting default.
- UDP and DNS forwarding defaults are preserved by the profile parser; imported `.sks` values follow their stored settings.

These defaults preserve compatibility but are not the strongest security posture. Use trusted servers and configure pins where possible.

## Current gaps

- Physical-device validation has not been completed.
- IPv6 TUN routing, per-app routing, tethering routes, and detailed traffic statistics are not yet ported.
- Root-block metadata is preserved in locked profiles, but enforcement is not implemented.
- The optional active-VPN detection guard is not implemented.
- Locked profiles without a passcode hide fields in the app but are not confidential; the URI payload is readable.
- QR/Base45 export and issuer signatures are not implemented.
- Legacy SSH algorithm negotiation and all payload write/flush edge cases still require parity review against the baseline.

## CI

GitHub Actions runs:

- `go test ./...`
- `go vet ./...`
- OpenSSH, Dropbear, and BadVPN UDPGW integration tests
- gomobile Android AAR generation
- Android debug/release APK builds

The debug APK is intended for device testing. Release signing is enabled only when the repository secrets `GO_KEYSTORE_BASE64`, `GO_KEYSTORE_PASSWORD`, `GO_KEY_ALIAS`, and `GO_KEY_PASSWORD` are configured. No signing material belongs in source control.

## Source baseline

Legacy-Evolved: `3d0b1838c0978051fb779a18bab37ac7a21e701f`.

No owner-specific servers, owner login gates, remote-config service, ads, or anti-tamper components are included.
