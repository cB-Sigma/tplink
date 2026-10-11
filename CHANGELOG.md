# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 the API may change in minor versions.

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
