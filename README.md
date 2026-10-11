# tplink

Clients for the local protocols of TP-Link Kasa and Tapo smart-home devices in pure Go: the Kasa legacy protocol, KLAP v1 and v2, securePassthrough and the 20002 discovery; not affiliated with TP-Link.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/tplink.svg)](https://pkg.go.dev/github.com/cB-Sigma/tplink) [![test](https://github.com/cB-Sigma/tplink/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/tplink/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.22-00ADD8.svg)](go.mod)

It talks to devices on the LAN: the Kasa legacy protocol on port 9999
(TCP requests and UDP discovery), KLAP v1 and v2, the older Tapo
securePassthrough transport, Tapo hubs and power strips with their
children, and the UDP 20002 discovery probe. KLAP and securePassthrough
devices need the owner's TP-Link account, but no cloud connection.
Standard library and [lanbcast](https://github.com/cB-Sigma/lanbcast)
only, no cgo. It was written for SigmaM2M, a oneM2M platform, whose
TP-Link adapter is built on it.

## Features

| Feature | Status |
|---|---|
| Kasa legacy protocol over TCP 9999, UDP discovery on 9999 | yes |
| KLAP v2 (Tapo, some Kasa) and v1 (Kasa on newer firmware), with the legacy JSON inside for Kasa; the account and blank credentials tried from one handshake | yes |
| More accounts to try, such as a vendor setup account, from the caller (`KLAPAuthsWith`, `AESLoginsWith`) | yes; none is shipped |
| securePassthrough with login version 1 and 2 | yes |
| Tapo request family, hub and strip children (paging, control_child) | yes |
| UDP 20002 discovery probe and answer | yes; the answer's encrypted part is not decrypted |
| Colour-temperature ranges | Kasa by model table; Tapo from get_device_info |
| multipleRequest batching, component negotiation, per-model helpers | no; requests are sent one at a time and the caller reads the answers |
| HTTPS transports of the newest firmware (KLAP over TLS, the newer TPAP login), cameras (Tapo C-series), the cloud API, setting up new devices | no |

## Choosing a Go TP-Link library

Compared from each project's source at the version named, on
2026-10-11. Check the projects themselves before relying on a row.

| | this module | fabiankachlock/tapo-api v1.4.0 | kabukky/tapogo (2024-03-04) | cloudkucooland/go-kasa (2026-08-29) | python-kasa 0.11.0.1 (Python) |
|---|---|---|---|---|---|
| Kasa legacy protocol (9999) and its UDP discovery | yes | no | no | yes | yes |
| KLAP v2 (Tapo) | yes | yes | yes | no | yes |
| KLAP v1 (Kasa on newer firmware) | yes | no | no | no | yes |
| securePassthrough (older Tapo firmware) | yes, login v1 and v2 | no | no | no | yes |
| 20002 discovery | yes | no | no | no | yes, with the encrypted part |
| Hub and strip children | yes | yes, typed (T300, T31x) | no | Kasa strips | yes |
| multipleRequest, typed device models | no | yes | no | Kasa models | yes |
| Vendor setup accounts | caller-supplied | no | no | n/a | built in |
| Device simulators for tests | yes, separate module | no | no | no | in-process fakes from recorded fixtures |
| Interop evidence | against python-kasa both ways (below) | none stated | none stated | none stated | the reference, recorded fixtures |
| Go version, dependencies | 1.22; lanbcast | 1.20; none | 1.21; none | 1.25; a TUI and CLI stack | n/a |
| Licence | Apache-2.0 | MIT | Apache-2.0 | BSD-2-Clause | GPL-3.0 |

Pick this module when you need one client for every local transport a
mixed Kasa and Tapo home uses, including discovery and the older
firmware, under your own device model. Pick tapo-api for typed Tapo
models (lights, strips, hub sensors) when your devices all speak KLAP v2,
and go-kasa for Kasa legacy devices with its command-line tool. Use
python-kasa outside Go: it covers the most devices and firmware, and its
fixtures record real devices.

## Install

```
go get github.com/cB-Sigma/tplink@latest
```

Requires Go 1.22 or later.

## Quick start

```go
import "github.com/cB-Sigma/tplink"

found, _ := tplink.TapoDiscover(ctx, "255.255.255.255:20002", 3*time.Second)
c := &tplink.KLAPClient{Base: "http://" + found[0].Host, Auths: tplink.KLAPAuths(email, password),
	HTTP: &http.Client{Timeout: 5 * time.Second}}
info, err := c.Call(ctx, "get_device_info", nil)
_, err = c.Call(ctx, "set_device_info", map[string]any{"device_on": true})

// A Kasa device on the legacy protocol needs no account:
m, err := tplink.KasaRequest(ctx, "192.168.1.40:9999",
	map[string]any{"system": map[string]any{"get_sysinfo": map[string]any{}}}, 3*time.Second)
```

Use `TapoFound.Protocol()` to choose between `KLAPClient` and
`AESClient`. `Example` and `ExampleKasaRequest` in example_test.go show
the whole flow (they need devices, so they are not run); `ExampleEncrypt`
runs. [tplink-sim](https://github.com/cB-Sigma/tplink-sim) runs them
against simulated devices.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/tplink

| Package | What it does |
|---|---|
| `tplink` (module root) | Kasa: `KasaRequest`, `KasaDiscover`, `Encrypt`/`Decrypt`/`Frame`/`ReadFrame`, `KasaError`. KLAP: `KLAPClient` (`Call`, `KasaCall`, `Send`, `Handshake`, `Matched`, `BadSignatures`), `KLAPAuths`, `KLAPAuthsWith`, `Credential`, `AuthHash`, `AuthHashV1`, `NewSession`. securePassthrough: `AESClient`, `AESLogins`, `AESLoginsWith`. Tapo: `SmartCaller`, `ChildList`, `ControlChild`, `SmartError`, `IsUnsupported`. Discovery: `TapoDiscover`, `TapoProbe`, `CheckTapoProbe`, `ParseTapoAnswer`. Kelvin ranges: `KasaKelvinRange`, `TapoKelvinRange` |
| `interop` (nested module, tests only) | these clients against a device that answers from python-kasa's recorded fixtures with python-kasa's own crypto, in a container |

Changes per version are in [CHANGELOG.md](CHANGELOG.md).

## Testing

```
go test -race ./...
cd interop && SIGMA_TPLINK_INTEROP=1 go test -v ./...   # needs Docker
```

Tests carry `// Covers: SIG-...` comments: requirement IDs of the
SigmaM2M project's compliance report, with no meaning outside it. The
client tests against simulated devices are in tplink-sim.

`interop/` is a nested module with its own go.mod. Its tests build an
image from `interop/peer` (python:3.12.10-slim with python-kasa 0.11.0.1
from PyPI and the fixtures of its 0.11.0.1 tag) and are skipped unless
`SIGMA_TPLINK_INTEROP=1` is set and Docker answers.

### Interop tested against

- python-kasa 0.11.0.1 (2026-10-11, Docker Desktop on arm64; `interop`):
  these clients against a device that answers from python-kasa's
  recorded fixtures and encrypts with python-kasa's own transport code
  (`interop/peer/device.py`: XorEncryption, KlapEncryptionSession and the
  KLAP v1 and v2 hash functions, AesEncyptionSession and the login
  hashing of AesTransport; the HTTP handling is the script's). Passed:
  - legacy protocol against the HS110(EU) 1.2.5 fixture: get_sysinfo,
    set_relay_state (decoded by the device), the energy meter, an unknown
    method, UDP discovery;
  - KLAP v2 against P110(UK) 1.3.0: handshake, get_device_info,
    set_device_info, several requests on one session, get_energy_usage,
    an unknown method, answer signatures all valid, a wrong password
    refused;
  - KLAP v1 with the Kasa JSON against HS100(UK) hardware 4.1;
  - a P300(EU) strip's three children read page by page, and a request
    to one child;
  - securePassthrough with login version 2 and 1 against P100(US) 1.1.3,
    the login checked with python-kasa's hashing; a wrong password
    refused;
  - the 20002 probe passed the device's checks (header as python-kasa
    builds it, CRC); the answers recorded in the P110, P100 and HS100
    fixtures were read with their model, type and protocol.
- python-kasa 0.11.0.1's client against the simulators, in
  [tplink-sim](https://github.com/cB-Sigma/tplink-sim).
- Not yet: a real Kasa or Tapo device. No open-source network emulator
  of KLAP or securePassthrough devices was found; python-kasa tests with
  in-process fakes, so the device side here is a script on python-kasa's
  code.

## Related repositories

- [tplink-sim](https://github.com/cB-Sigma/tplink-sim): simulated Kasa
  and Tapo devices and a 20002 responder, as a Go package and a command.
- [lanbcast](https://github.com/cB-Sigma/lanbcast): the broadcast helper
  discovery uses.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. TP-Link, Kasa and Tapo are trademarks of their owner; the
names are used only to say which devices this module talks to.
