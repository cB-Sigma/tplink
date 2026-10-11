# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 the API may change in minor versions.

## v0.2.0 (2026-10-11)

Additions only; the v0.1.0 API is unchanged.

- Batching and negotiation: `MultiCall` (multipleRequest in batches,
  answers matched by method, missing answers and devices that refuse
  batches asked one by one), `MultiCallChild`, `SmartList` for paged
  lists, `Components` and `ChildComponents`.
- `TapoDevice`, typed helpers for a Tapo device or one child: device
  information (`TapoInfo`, `ParseTapoInfo`, `DecodeNickname`), switching,
  lights, transitions, presets, bulb and strip light effects, energy use,
  readings and history (`EnergyData`: hourly, daily, monthly), device
  use, rule lists, auto-off, LED, firmware check, update and progress,
  automatic updates, Wi-Fi scan, set-up (`WifiJoin`, `SetAccount`),
  reboot, factory reset, children and button and sensor logs.
- `KasaDevice`, typed helpers for a Kasa device or strip outlet on any
  transport (`KasaCaller`: `KasaConn`, `KLAPClient`, `LinkieClient`):
  energy meter readings in both firmware units, day and month energy and
  runtime statistics, schedules, countdowns and away mode (`KasaRule`,
  add, edit, delete, enable), dimmer transitions, fades and ramp rate,
  light state with transitions for bulbs and light strips, light strip
  effects, LED, name, reboot, factory reset, cloud information and
  firmware list, Wi-Fi scan and join; `KasaModuleError`,
  `IsKasaUnsupported`. The countdown module is tried as count_down, then
  countdown, as devices and clients differ. Kasa cameras' nested sysinfo
  is read unnested.
- HTTPS transports: `SSLAESClient` for Tapo cameras, doorbells and the
  H200 hub (nonce login with SHA-256 or MD5 password hashes, signed
  requests, the plain login of older firmware) with `CamGet`,
  `CamDeviceInfo`, `CamChildList`, `CamControlChild` and the hash
  functions; `LinkieClient` for Kasa cameras; `SSLClient` for the plain
  HTTPS transport of older robot vacuum firmware; KLAP over HTTPS through
  `KLAPClient` with `InsecureHTTP` and `KLAPHTTPSPort`.
- Discovery: the answer's encrypted part is decrypted (`TapoFound.Decrypted`,
  `DecryptTapoAnswer`; `SealTapoDiscovery` for simulators),
  `TapoFound.BaseURL`, and the login version and AES transport read from a
  top-level encrypt_type list (cameras).
- Interop tests extended to every addition, against python-kasa
  0.11.0.1's code and fixtures (python:3.12.10-slim); the peer image is
  now tagged `sigma-tplink-interop:python-kasa-0.11.0.1-r2`.

## v0.1.0 (2026-10-11)

First release as a module of its own, split from SigmaM2M: the Kasa
legacy protocol (`KasaRequest`, `KasaDiscover`), KLAP v1 and v2
(`KLAPClient`), securePassthrough (`AESClient`), Tapo children
(`ChildList`, `ControlChild`), the 20002 discovery (`TapoDiscover`) and
the Kelvin ranges.

- The module ships no vendor setup account. `KLAPAuths` tries the
  account and blank credentials and `AESLogins` the account; before the
  split both also tried two vendor setup accounts. `KLAPAuthsWith`,
  `AESLoginsWith` and `Credential` take further accounts from the caller.
- The simulators live in their own module,
  [tplink-sim](https://github.com/cB-Sigma/tplink-sim), with the tests
  that drive them.
- Interop tests against python-kasa 0.11.0.1's transport code and
  recorded fixtures in a nested test-only module, `interop`.
