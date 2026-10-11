// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package tplink speaks the local protocols of TP-Link Kasa and Tapo
// smart-home devices: the Kasa legacy protocol on port 9999 (KasaRequest,
// KasaDiscover), KLAP v1 and v2 over HTTP (KLAPClient, with KLAPAuths to
// try the account and blank credentials, and KLAPAuthsWith for more
// accounts the caller supplies), the older Tapo securePassthrough
// transport (AESClient), the Tapo request family with hub and strip
// children (ChildList, ControlChild), the UDP 20002 discovery probe
// (TapoDiscover), and the colour-temperature ranges of bulbs. It needs the
// owner's TP-Link account for KLAP and securePassthrough devices, and no
// cloud connection. It ships no vendor setup account.
//
// TP-Link does not publish these protocols; this package follows public
// descriptions (see PROVENANCE.md). Simulated devices for tests are in
// github.com/cB-Sigma/tplink-sim.
package tplink
