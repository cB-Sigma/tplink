# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go. No code was ported or
copied from another implementation, and no source file of another
project was translated.

TP-Link publishes no documentation of its local protocols. The facts
this module uses come from public reverse-engineering descriptions,
chiefly python-kasa, which is licensed GPL-3.0. Because of that licence,
the rule for this code was facts only: port numbers, byte layouts, hash
and cipher choices, the order of handshake steps, method, field and
module names, error codes and model ranges were taken; code structure,
identifiers, comments and control flow were not. The Go types, the
session handling, retries and error reporting, and the simulators are
our own design.

History:

- The Kasa legacy protocol (kasa.go) and KLAP v2 (klap.go) came with
  SigmaM2M's first commit (2026-09-27), built from described facts.
- KLAP v1, Kasa JSON inside KLAP, blank credentials and the lenient
  answer signature were added on 2026-10-05, after reading python-kasa's
  kasa/transports/klaptransport.py and kasa/device_factory.py for the
  facts.
- The UDP 20002 discovery (tdp.go), securePassthrough (aes.go), the Tapo
  child requests and the Kelvin ranges (kelvin.go) were added on
  2026-10-05, with python-kasa's kasa/discover.py,
  kasa/transports/aestransport.py, kasa/protocols/smartprotocol.py,
  kasa/iot/iotbulb.py and several kasa/smart/modules files read for
  facts.
- doc.go, smart.go, util.go, the Handshake methods and the tests marked
  "Copyright 2026 Abhinav Gautam" were written for this module.
- 2026-10-11, before the first release: the simulators, their command
  and the tests that drive them moved to the tplink-sim module (with
  `git mv`). The two vendor setup accounts that `KLAPAuths` and
  `AESLogins` used to try were removed from the module; `KLAPAuthsWith`,
  `AESLoginsWith` and `Credential` take such accounts from the caller
  (SigmaM2M's adapter keeps supplying them). The interop module was
  added and run against python-kasa 0.11.0.1; it found no difference in
  the clients.
- 2026-10-11, v0.2.0: multi.go, tapodevice.go, kasadevice.go, sslaes.go
  and linkie.go were written for this module, and tdp.go gained the
  decryption of the answer's encrypted part. Facts were read from
  python-kasa 0.11.0.1 (installed in the interop image): its
  protocols/smartprotocol.py and smartcamprotocol.py (batching, the
  errors that end batching, paging), iot/ and smart/ device and module
  files (module and method names, parameters, rule fields, statistics
  fields, dimmer methods, light-strip service, Wi-Fi and set-up
  requests, firmware update states, component names) and its
  transports/sslaestransport.py, ssltransport.py and linkietransport.py
  (the HTTPS logins, hashes, key derivation, request tags, the Kasa camera
  form field). Tapo energy history (get_energy_data) is not in
  python-kasa: its request fields come from fabiankachlock/tapo-api
  v1.4.0 (MIT, pkg/api/request/energy_data.go) and its answer fields from
  mihai-dinculescu/tapo (MIT, tapo/src/responses/energy_data_result.rs),
  facts only. That count_down is the countdown module's name on devices
  was confirmed in cloudkucooland/go-kasa (BSD-2-Clause), facts only. No
  code, effect table or default credential was taken from any of them.
  Running the new interop tests found that a Kasa camera nests its
  sysinfo once more, which the helpers now read.

## Sources

| Area (files) | Followed | Read for facts only (no code taken) |
|---|---|---|
| Kasa legacy protocol (kasa.go) | none published | public descriptions and security write-ups of the port 9999 protocol; python-kasa (GPL-3.0): length prefix, autokey XOR starting at 171, UDP discovery with get_sysinfo, err_code in module answers |
| KLAP (klap.go) | none published | python-kasa (GPL-3.0) kasa/transports/klaptransport.py: handshake1/handshake2 paths, the v1 (MD5) and v2 (SHA-1 then SHA-256) auth hashes and their proofs, the key, IV and signature derivation, the sequence, the cookie and timeout; kasa/device_factory.py: which devices pair KLAP with the legacy JSON |
| securePassthrough (aes.go) | none published | python-kasa (GPL-3.0) kasa/transports/aestransport.py: the handshake with an RSA public key and PKCS#1 v1.5, login_device with SHA-1 hex usernames and password or password2, the token in the URL, base64 AES-128-CBC payloads, the error codes for expired sessions |
| Discovery probe (tdp.go) | none published | python-kasa (GPL-3.0) kasa/discover.py: the 16-byte header (version 2, op code 1, flags 0x11, serial, CRC-32 seeded with 0x5A6B7C8D), the rsa_key payload, the answer's fields |
| Tapo requests and children (smart.go) | none published | python-kasa (GPL-3.0) kasa/protocols/smartprotocol.py: get_child_device_list paging by start_index and sum, control_child with requestData and responseData |
| Colour-temperature ranges (kelvin.go) | none published | python-kasa (GPL-3.0) kasa/iot/iotbulb.py: the per-model Kasa ranges; colortemperature module: Tapo color_temp_range |
| Batching and components (multi.go) | none published | python-kasa (GPL-3.0) kasa/protocols/smartprotocol.py: multipleRequest shape, answers keyed by method, missing answers re-asked, batch size 5, start_index and sum paging; component_nego and get_child_device_component_list shapes |
| Tapo helpers (tapodevice.go) | none published | python-kasa (GPL-3.0) kasa/smart/smartdevice.py and kasa/smart/modules/*.py: method names and parameters (energy, firmware, auto-off, LED, transitions, presets, light effects, Wi-Fi, set_qs_info, reboot, reset); fixtures for answer fields; tapo-api v1.4.0 (MIT) and the tapo crate (MIT): get_energy_data fields |
| Kasa helpers (kasadevice.go) | none published | python-kasa (GPL-3.0) kasa/iot/*.py and kasa/iot/modules/*.py: module names per device type, statistics and rule methods and fields, dimmer methods, light-strip service and effect method, cloud and Wi-Fi methods; go-kasa (BSD-2-Clause): the count_down module name |
| HTTPS transports (sslaes.go, linkie.go) | none published | python-kasa (GPL-3.0) kasa/transports/sslaestransport.py, ssltransport.py, linkietransport.py, klaptransport.py and kasa/protocols/smartcamprotocol.py: login steps, hashes, key and tag derivation, error codes, paths and ports, the Kasa camera form field |
| Discovery decryption (tdp.go) | none published | python-kasa (GPL-3.0) kasa/discover.py and kasa/transports/aestransport.py: encrypt_info fields, RSA-OAEP with SHA-1, the AES-128-CBC data; the encrypt_type list |
| Interop peer (interop/peer) | our own script and Dockerfile | python-kasa 0.11.0.1's transport classes and recorded fixtures, at test time |

No specification or vendor text is reproduced.

## Notes for reviewers

The places closest to python-kasa, each a fact an implementation must
match to interoperate:

- `kasaKelvin` in kelvin.go: the model-prefix table of colour-temperature
  ranges (facts; the selection follows the devices python-kasa lists).
- `AESLoginsWith` in aes.go: the login_device parameter forms.
- `TapoProbe`, `CheckTapoProbe` and `ParseTapoAnswer` in tdp.go: the
  header layout and the answer fields.
- The KLAP key, IV, signature and sequence derivation in `NewSession`
  (klap.go).
- The securePassthrough error codes in aes.go and the "unsupported"
  codes in `IsUnsupported` (smart.go).
- `SSLAESConfirm`, `SSLAESDigest`, `SSLAESKeys` and `SSLAESTag` in
  sslaes.go: the order of the strings each hash takes.
- The module and method names and parameter fields in kasadevice.go and
  tapodevice.go.

The project owner decided on 2026-10-06 that no line-by-line comparison
with python-kasa is needed, the facts-only rule and these notes being the
record.

## Test vectors and where they come from

| Test | Source |
|---|---|
| proto_test.go TestKasaFraming, example_test.go ExampleEncrypt | the XOR rule worked by hand ('{' to 0xd0 with key 171) |
| proto_test.go TestKLAPSessionAndHandshake | sessions built by this module from fixed seeds; a changed byte |
| proto_test.go TestTapoProbeAndAnswer | a probe built by TapoProbe and checked with Go's CRC-32; the answer JSON is made up in the shape of a device's answer |
| proto_test.go TestKelvinRanges | the kelvin.go table |
| proto_test.go TestCredentialOrder | the order of the auth hashes and logins tried |
| devices_test.go | fakes written for the tests; the expected requests follow the facts above |
| sslaes_test.go TestSSLAESVectors | values printed by python-kasa 0.11.0.1's SslAesTransport functions in the interop image for made-up inputs (the password "demo-password" and two fixed nonces) |
| interop/ | python-kasa 0.11.0.1's code and fixtures, at test time |

All accounts, MAC addresses, device IDs and addresses are made-up demo
values.
