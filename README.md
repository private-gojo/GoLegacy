# Go

Standalone Android SSH tunneling client ported from [Legacy-Evolved](https://github.com/private-gojo/Legacy-Evolved).

## Architecture

- **Go core:** SSH transport, payload formatting, local SOCKS5, UDPGW, and profile handling.
- **Android layer:** Kotlin UI and `VpnService`.
- **TUN engine:** Official HEV SOCKS5 Tunnel Android AAR, kept separate from the Go AAR.
- **Build:** GitHub Actions builds the consolidated Go mobile AAR and Android APKs.

## Transport modes

- Direct SSH, including optional direct payload injection.
- HTTP proxy with optional custom payload.
- TLS-wrapped SSH with configurable SNI.
- TLS-wrapped SSH with custom payload.

SSH password and private-key authentication are supported. Legacy Trilead client identification and compatible legacy algorithm fallbacks are retained for interoperability.

## VPN features

- IPv4 default routing with private, local TUN, DNS, and user-defined route exclusions.
- Per-app allow-list and bypass-list modes.
- Optional tethering subnet bypass.
- TCP and UDP forwarding through the local SOCKS5 endpoint.
- BadVPN UDPGW framing over the SSH connection.
- DNS and UDP forwarding settings compatible with the legacy profile defaults.
- Reconnect loop with exponential backoff.
- Android `VpnService.protect()` callback for tunnel sockets.

## Profiles

- SSH URI import.
- Go JSON profile import/export.
- Legacy `.sks` import only.
- Locked `go-ssh://locked/` profiles with optional Argon2id + AES-GCM encryption, expiry, message, and optional root restriction.
- Clipboard URI batch import and QR scan/display.
- Saved profiles are encrypted with an Android Keystore AES-GCM key.

A locked URI without a passcode is encoded, not confidential. Use a passcode when profile contents must be encrypted.

## Security compatibility

For legacy compatibility, TLS certificate verification and SSH host-key verification are permissive by default. Optional TLS certificate SHA-256 and SSH host-key SHA-256 pins are available. Enable verification or pinning when the endpoint supports it.

## Development

Go checks:

```sh
go test ./...
go vet ./...
```

Android build is performed by the **Go Mobile AAR** GitHub Actions workflow. It downloads the pinned HEV AAR, builds the gomobile AAR, and produces debug and release APK artifacts. Release signing is enabled only when the corresponding GitHub Actions secrets are configured.

## Validation status

CI covers unit tests, OpenSSH/Dropbear compatibility, legacy SSH algorithm negotiation, and BadVPN UDPGW framing/round-trip tests. Android APK compilation is validated in GitHub Actions. End-to-end TUN routing, DNS behavior, reconnects, app filtering, and throughput still require installation and testing on physical Android devices and real SSH/UDPGW servers.
