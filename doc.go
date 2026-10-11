// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package tplink speaks the local protocols of TP-Link Kasa and Tapo
// smart-home devices: the Kasa legacy protocol on port 9999 (KasaRequest,
// KasaDiscover), KLAP v1 and v2 over HTTP and HTTPS (KLAPClient, with
// KLAPAuths to try the account and blank credentials, and KLAPAuthsWith
// for more accounts the caller supplies), the older Tapo
// securePassthrough transport (AESClient), the TPAP login of newer
// firmware (TPAPClient, TPAPDiscover: SPAKE2+ and AES-128-CCM with the
// account password), the HTTPS transport of Tapo
// cameras, doorbells and the H200 hub (SSLAESClient), the Kasa camera
// transport (LinkieClient), the plain HTTPS transport of older robot
// vacuum firmware (SSLClient), the Tapo request family with batching
// (MultiCall), component negotiation (Components) and hub and strip
// children (ChildList, ControlChild), the UDP 20002 discovery probe with
// its encrypted part (TapoDiscover), and the colour-temperature ranges of
// bulbs.
//
// Typed helpers cover what the devices do beyond switching: KasaDevice
// (energy meter and runtime statistics, schedules, countdowns and away
// mode, dimmer transitions and fades, light state with transitions, light
// strip effects, LED, name, reboot, cloud and firmware information, Wi-Fi
// scan and join) and TapoDevice (lights, transitions, presets and effects,
// energy use, history and readings, schedules and countdowns read and
// changed, auto-off, LED, firmware update, Wi-Fi scan and set-up, hub
// sensors and button logs), TapoCamera (pan and tilt with presets,
// privacy, status light, ten detection settings, siren and alarm, night
// vision, clock, SD card, recordings list) and TapoVacuum (status,
// cleaning, suction and water, consumables, records, maps and rooms,
// dustbin, volume).
//
// It needs the owner's TP-Link account for KLAP, securePassthrough and
// TPAP devices (cameras: the device's local user), and no cloud connection. It
// ships no vendor setup account or default login.
//
// TP-Link does not publish these protocols; this package follows public
// descriptions (see PROVENANCE.md). Simulated devices for tests are in
// github.com/cB-Sigma/tplink-sim.
package tplink
