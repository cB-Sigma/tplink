# tplink

Clients for the local protocols of TP-Link Kasa and Tapo smart-home devices in pure Go: the Kasa legacy protocol, KLAP v1 and v2 over HTTP and HTTPS, securePassthrough, the camera and hub HTTPS transports and the 20002 discovery, with typed helpers for plugs, strips, dimmers, bulbs, light strips, hubs and cameras; not affiliated with TP-Link.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/tplink.svg)](https://pkg.go.dev/github.com/cB-Sigma/tplink) [![test](https://github.com/cB-Sigma/tplink/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/tplink/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.22-00ADD8.svg)](go.mod)

It talks to devices on the LAN: the Kasa legacy protocol on port 9999
(TCP requests and UDP discovery), KLAP v1 and v2 over HTTP and HTTPS, the
older Tapo securePassthrough transport, the HTTPS transport of Tapo
cameras, doorbells and the H200 hub, the Kasa camera transport, the plain
HTTPS transport of older robot vacuum firmware, Tapo hubs and power
strips with their children, and the UDP 20002 discovery probe. Typed
helpers cover what the devices do beyond switching. KLAP,
securePassthrough and camera devices need the owner's account (cameras:
the device's local user), but no cloud connection. Standard library and
[lanbcast](https://github.com/cB-Sigma/lanbcast) only, no cgo. It was
written for SigmaM2M, a oneM2M platform, whose TP-Link adapter is built
on it.

## Features

| Feature | Status |
|---|---|
| Kasa legacy protocol over TCP 9999, UDP discovery on 9999 | yes |
| KLAP v2 (Tapo, some Kasa) and v1 (Kasa on newer firmware), with the legacy JSON inside for Kasa; the account and blank credentials tried from one handshake | yes |
| KLAP over HTTPS (newer firmware, port 4433; `InsecureHTTP` for the self-signed certificate) | yes, since v0.2.0 |
| More accounts to try, such as a vendor setup account, from the caller (`KLAPAuthsWith`, `AESLoginsWith`) | yes; none is shipped |
| securePassthrough with login version 1 and 2 | yes |
| HTTPS transport of Tapo cameras, doorbells and the H200 hub: the nonce login with SHA-256 or MD5 password hashes, signed and numbered requests, the plain login of older firmware (`SSLAESClient`); camera requests (`CamGet`, `CamDeviceInfo`) and H200 children (`CamChildList`, `CamControlChild`) | yes, since v0.2.0 |
| Kasa cameras (KC series, port 10443, `LinkieClient`) and the plain HTTPS transport of older robot vacuum firmware (`SSLClient`) | yes, since v0.2.0 |
| Tapo request family, hub and strip children (paging, control_child) | yes |
| multipleRequest batching with the device's limits and fallbacks (`MultiCall`, `MultiCallChild`), component negotiation (`Components`, `ChildComponents`), paged lists (`SmartList`) | yes, since v0.2.0 |
| Kasa helpers (`KasaDevice`, for 9999, KLAP and camera transports, strip outlets by child ID): energy meter readings in both firmware units, day and month energy and runtime statistics, schedules, countdowns and away mode (add, edit, delete), dimmer transitions, fades and ramp rate, bulb and light-strip light state with transitions, light strip effects, LED, name, reboot, factory reset, cloud and firmware information, Wi-Fi scan and join | yes, since v0.2.0 |
| Tapo helpers (`TapoDevice`, a device or a child): typed device information (plugs, bulbs, hub sensors), switching, lights, transitions, presets, light effects of bulbs and strips, energy use, readings and hourly, daily and monthly history, device use, rule lists, auto-off, LED, firmware check, update and progress, automatic updates, Wi-Fi scan, set-up onto a network with the account (`WifiJoin`), account change, reboot, factory reset, button and sensor logs | yes, since v0.2.0 |
| UDP 20002 discovery probe and answer, with the answer's encrypted part decrypted (`TapoFound.Decrypted`) and the URL to use (`TapoFound.BaseURL`) | yes; the encrypted part since v0.2.0 |
| Colour-temperature ranges | Kasa by model table; Tapo from get_device_info |
| Changing Tapo schedules and countdowns, the TPAP login, local Kasa firmware flashing, camera-specific helpers, the cloud API | no; see "Not yet" |

## Choosing a Go TP-Link library

Compared from each project's source at the version named, on
2026-10-11. Check the projects themselves before relying on a row.

| | this module | fabiankachlock/tapo-api v1.4.0 | kabukky/tapogo (2024-03-04) | cloudkucooland/go-kasa (2026-08-29) | python-kasa 0.11.0.1 (Python) |
|---|---|---|---|---|---|
| Kasa legacy protocol (9999) and its UDP discovery | yes | no | no | yes | yes |
| KLAP v2 (Tapo) | yes, HTTP and HTTPS | yes | yes | no | yes, HTTP and HTTPS |
| KLAP v1 (Kasa on newer firmware) | yes | no | no | no | yes |
| securePassthrough (older Tapo firmware) | yes, login v1 and v2 | no | no | no | yes |
| Cameras, doorbells, H200 hub (HTTPS transport) | yes, transport and generic requests | no | no | no | yes, with camera modules |
| Kasa cameras, robot vacuums | transports | no | no | no | yes, with device modules |
| 20002 discovery | yes, with the encrypted part | no | no | no | yes, with the encrypted part |
| Hub and strip children | yes, typed sensors | yes, typed (T300, T31x) | no | Kasa strips | yes |
| multipleRequest, typed device helpers | yes | yes | no | Kasa models | yes |
| Energy history | Kasa day and month; Tapo hourly, daily, monthly | Tapo | no | Kasa | Kasa day and month |
| Schedules and countdowns | Kasa read and write; Tapo read | no | no | Kasa read | Kasa read and delete |
| Firmware update | Tapo check, update, progress; Kasa list | no | no | no | Tapo |
| Wi-Fi set-up | Kasa and Tapo | no | no | Kasa | Kasa, Tapo, cameras |
| Vendor setup accounts | caller-supplied | no | no | n/a | built in |
| Device simulators for tests | yes, separate module | no | no | no | in-process fakes from recorded fixtures |
| Interop evidence | against python-kasa both ways (below) | none stated | none stated | none stated | the reference, recorded fixtures |
| Go version, dependencies | 1.22; lanbcast | 1.20; none | 1.21; none | 1.25; a TUI and CLI stack | n/a |
| Licence | Apache-2.0 | MIT | Apache-2.0 | BSD-2-Clause | GPL-3.0 |

Pick this module when you need one Go client for every local transport
a mixed Kasa and Tapo home uses, including discovery, the older firmware,
cameras and hubs, with typed helpers and simulators to test against.
Pick tapo-api if you prefer its per-model Tapo types and need nothing
but KLAP v2 devices, and go-kasa for Kasa legacy devices with its
command-line tool. python-kasa is still ahead in camera-specific modules
(pan and tilt, detection settings, streams), robot vacuum modules,
built-in light effect definitions and the number of firmware versions
recorded from real devices; use it outside Go or when those matter.

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

// Typed helpers, on any transport:
plug := tplink.TapoDevice{Caller: c}
fw, _ := plug.LatestFirmware(ctx)
hours, _ := plug.EnergyData(ctx, dayStart, dayStart.Add(23*time.Hour), tplink.EnergyHourly)
kasa, _, _ := tplink.NewKasaDevice(ctx, tplink.KasaConn{Addr: "192.168.1.40:9999"})
days, _ := kasa.EmeterDays(ctx, 2026, 10)
id, _ := kasa.AddRule(ctx, tplink.KasaCountdown, tplink.KasaRule{Name: "off", Enable: true, Delay: 600, Action: tplink.KasaActionOff})
```

Use `TapoFound.Protocol()` and `TapoFound.HTTPS` to choose between
`KLAPClient`, `AESClient` and `SSLAESClient`, and `TapoFound.BaseURL()`
for the URL. `Example` and `ExampleKasaRequest` in example_test.go show
the whole flow (they need devices, so they are not run); `ExampleEncrypt`
runs. [tplink-sim](https://github.com/cB-Sigma/tplink-sim) runs them,
and every helper, against simulated devices.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/tplink

| Package | What it does |
|---|---|
| `tplink` (module root) | Kasa: `KasaRequest`, `KasaDiscover`, `Encrypt`/`Decrypt`/`Frame`/`ReadFrame`, `KasaError`, `KasaConn`, `KasaCaller`, `KasaDevice` (`NewKasaDevice`, `Query`, `Emeter`, `EmeterDays`, `EmeterMonths`, `RuntimeDays`, `Rules`, `AddRule`, `EditRule`, `DimTo`, `SetLight`, `SetLightingEffect`, `WifiJoin`, ...), `KasaRule`, `KasaModuleError`, `IsKasaUnsupported`. KLAP: `KLAPClient` (`Call`, `KasaCall`, `Send`, `Handshake`, `Matched`, `BadSignatures`), `KLAPAuths`, `KLAPAuthsWith`, `Credential`, `AuthHash`, `AuthHashV1`, `NewSession`, `KLAPHTTPSPort`, `InsecureHTTP`. securePassthrough: `AESClient`, `AESLogins`, `AESLoginsWith`. Cameras and H200: `SSLAESClient`, `CamGet`, `CamDeviceInfo`, `CamChildList`, `CamControlChild`, `SSLAESConfirm`, `SSLAESDigest`, `SSLAESKeys`, `SSLAESTag`. Kasa cameras and robot vacuums: `LinkieClient`, `SSLClient`. Tapo: `SmartCaller`, `MultiCall`, `MultiCallChild`, `SmartList`, `Components`, `ChildComponents`, `ChildList`, `ControlChild`, `TapoDevice` (`Info`, `SetLight`, `EnergyData`, `Rules`, `LatestFirmware`, `StartFirmwareUpdate`, `WifiJoin`, `Children`, `TriggerLogs`, ...), `SmartError`, `IsUnsupported`. Discovery: `TapoDiscover`, `TapoProbe`, `CheckTapoProbe`, `ParseTapoAnswer`, `DecryptTapoAnswer`, `SealTapoDiscovery`, `TapoFound.BaseURL`. Kelvin ranges: `KasaKelvinRange`, `TapoKelvinRange` |
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
- Added in v0.2.0, same image (python:3.12.10-slim, python-kasa 0.11.0.1
  and its fixtures), 2026-10-11, all passed:
  - Kasa helpers against recorded answers: the HS110(EU) 1.2.5 energy
    meter in the older units (V, A, W, kWh), the HS220(US) 1.5.7 dimmer
    parameters and its missing energy meter (a module-level error), the
    KL130(EU) 1.8.8 cloud information and firmware list, the KL430(US)
    hardware 2.0 light strip's module names (energy meter, light state and
    details, schedule rules, next action);
  - Tapo helpers against recorded answers: MultiCall with an unknown
    method in the batch and the rest of the batch asked one by one,
    component negotiation, typed information, energy readings, energy
    use, device use, firmware check and state, automatic updates,
    auto-off read and changed, schedule and countdown lists, Wi-Fi scan
    (P110(AU) 1.3.1); transitions, light effects and presets (L530E(EU)
    hardware 3.0 1.1.6); a light strip effect and presets paged to their
    end (L900-5(EU) 1.1.0); a hub's T315 sensor typed and the children's
    components (H100(EU) 1.5.5);
  - the 20002 answer's encrypted part: the peer seals it and first checks
    that python-kasa's own discovery decryption reads it, then
    `TapoDiscover` decrypts it;
  - the camera transport against a device whose confirm, digest, keys and
    request tags are computed with python-kasa's SslAesTransport
    functions: a recorded C210(EU) hardware 2.0 camera read, a setting
    read, changed and read again, every request's tag accepted, a wrong
    password refused; a recorded H200(EU) 1.3.6 hub's children;
  - KLAP v2 over HTTPS (P110(UK) 1.3.0), and a client that checks
    certificates refusing the self-signed one;
  - the Kasa camera transport with python-kasa's XorEncryption against a
    recorded EC60(US) camera (its sysinfo nested once more, read
    unnested; a module error passed through), a wrong password refused;
  - the plain HTTPS transport with python-kasa's login hashing against a
    recorded RV30 Max(US) robot vacuum, a wrong password refused;
  - the camera transport's hashes match values computed with
    python-kasa's functions (`TestSSLAESVectors`, a unit test).
- python-kasa 0.11.0.1's client against the simulators, in
  [tplink-sim](https://github.com/cB-Sigma/tplink-sim).
- `get_energy_data` (Tapo energy history) is not used by python-kasa, so
  it was checked only against the simulator; its request and answer
  fields follow tapo-api v1.4.0 and the tapo Rust crate (see
  PROVENANCE.md).
- Not yet: a real Kasa or Tapo device. No open-source network emulator
  of these devices was found; python-kasa tests with in-process fakes, so
  the device side here is a script on python-kasa's code.

## Not yet

| Item | Why |
|---|---|
| Changing Tapo schedules, countdowns and away rules (reading them is supported) | python-kasa 0.11.0.1 only reads them, so there is no open-source client to check the write requests against; `Call` reaches the device's methods |
| The TPAP login of the newest firmware | python-kasa 0.11.0.1 does not implement it (it only names it), and no other open description was found to build and check against |
| Flashing Kasa legacy firmware locally (download and flash requests) | no open-source client we checked does it, a wrong request can leave a device unusable, and it needs real hardware to test; `FirmwareList` reads what the cloud offers |
| Camera-specific helpers (pan and tilt, detection, recording, streams) and robot vacuum helpers | the transports and generic requests are supported (`CamGet`, `SSLClient`); typed helpers for these families are larger than this release, and video belongs outside this module |
| Built-in light strip effect definitions | python-kasa's tables are GPL-3.0 data and are not copied; callers pass the device's own effect description |
| The TP-Link cloud API | needs a TP-Link account and works against TP-Link's servers, not the LAN |
| Checks against real devices | needs hardware |

## Related repositories

- [tplink-sim](https://github.com/cB-Sigma/tplink-sim): simulated Kasa
  and Tapo devices, cameras and hubs, and a 20002 responder, as a Go
  package and a command.
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
