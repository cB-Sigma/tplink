# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# A TP-Link device for interop tests that answers from python-kasa's
# recorded device fixtures and encrypts with python-kasa's own code
# (kasa.transports: XorEncryption, KlapEncryptionSession and the KLAP v1
# and v2 hash functions, AesEncyptionSession and AesTransport's login
# hashing), so that a client is checked against python-kasa's reading of
# the protocols. The HTTP and socket handling and which request answers
# what are this script's. It is a test peer, not a device emulator.
#
#   python device.py xor <iot fixture>                  TCP and UDP 9999
#   python device.py klap1 <iot fixture> <user> <pass>  HTTP 80, KLAP v1, Kasa JSON
#   python device.py klap2 <smart fixture> <user> <pass> HTTP 80, KLAP v2, Tapo requests
#   python device.py aes <smart fixture> <user> <pass> <login version>  HTTP 80
#   python device.py tdp <fixture> [<fixture> ...]      UDP 20002 discovery
#
# Prints "PEER <event> <json>".

import asyncio
import base64
import copy
import json
import os
import socket
import struct
import sys
import zlib

from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

import kasa
from kasa.credentials import Credentials
from kasa.transports.aestransport import AesEncyptionSession, AesTransport
from kasa.transports.klaptransport import KlapEncryptionSession, KlapTransport, KlapTransportV2
from kasa.transports.xortransport import XorEncryption

FIXTURES = "/python-kasa/tests/fixtures/"


def say(event, obj=None):
    print("PEER " + event + ("" if obj is None else " " + json.dumps(obj, sort_keys=True, default=str)), flush=True)


def load(name):
    for sub in ("smart/", "iot/"):
        path = FIXTURES + sub + name
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    raise SystemExit("no fixture " + name)


# --- Answers ---------------------------------------------------------------

class IotState:
    """Legacy (IOT) answers from an iot fixture."""

    def __init__(self, fixture):
        self.f = fixture

    def handle(self, req):
        out = {}
        for mod, methods in req.items():
            if mod == "context":
                continue
            res = {}
            for meth, arg in (methods or {}).items():
                if mod == "system" and meth == "get_sysinfo":
                    res[meth] = self.f["system"]["get_sysinfo"]
                elif mod == "system" and meth == "set_relay_state":
                    self.f["system"]["get_sysinfo"]["relay_state"] = arg.get("state")
                    res[meth] = {"err_code": 0}
                elif mod in self.f and meth in self.f[mod]:
                    res[meth] = self.f[mod][meth]
                else:
                    res[meth] = {"err_code": -2, "err_msg": "member not support"}
            out[mod] = res
        return out


class SmartState:
    """Tapo answers from a smart fixture."""

    def __init__(self, fixture):
        self.f = fixture

    def handle(self, req):
        method, params = req.get("method"), req.get("params") or {}
        if method == "set_device_info":
            self.f["get_device_info"].update(params)
            return {"error_code": 0, "result": {}}
        if method == "get_child_device_list" and "get_child_device_list" in self.f:
            lst = self.f["get_child_device_list"]["child_device_list"]
            start = int(params.get("start_index", 0))
            return {"error_code": 0, "result": {"child_device_list": lst[start:start + 2], "start_index": start, "sum": len(lst)}}
        if method == "control_child":
            cid = params.get("device_id")
            rd = params.get("requestData") or {}
            for c in self.f.get("get_child_device_list", {}).get("child_device_list", []):
                if c.get("device_id") == cid:
                    if rd.get("method") == "get_device_info":
                        inner = {"error_code": 0, "result": c}
                    elif rd.get("method") == "set_device_info":
                        c.update(rd.get("params") or {})
                        inner = {"error_code": 0, "result": {}}
                    else:
                        inner = {"error_code": -1002}
                    return {"error_code": 0, "result": {"responseData": inner}}
            return {"error_code": -1003}
        if method in self.f and not method.startswith("discovery"):
            return {"error_code": 0, "result": self.f[method]}
        return {"error_code": -1002}


# --- Legacy protocol on 9999 -----------------------------------------------

async def serve_xor(state):
    async def tcp(reader, writer):
        try:
            hdr = await reader.readexactly(4)
            body = await reader.readexactly(struct.unpack(">I", hdr)[0])
            req = json.loads(XorEncryption.decrypt(body))
            say("request", req)
            writer.write(XorEncryption.encrypt(json.dumps(state.handle(req))))
            await writer.drain()
        finally:
            writer.close()

    class Udp(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, data, addr):
            req = json.loads(XorEncryption.decrypt(data))
            say("udp", req)
            # UDP carries the obscured JSON without the length prefix.
            self.t.sendto(XorEncryption.encrypt(json.dumps(state.handle(req)))[4:], addr)

    await asyncio.start_server(tcp, "0.0.0.0", 9999)
    await asyncio.get_running_loop().create_datagram_endpoint(Udp, local_addr=("0.0.0.0", 9999))


# --- KLAP --------------------------------------------------------------------

def klap_app(transport_cls, creds, handle):
    auth = transport_cls.generate_auth_hash(creds)
    sessions = {}

    async def h1(request):
        local = await request.read()
        remote = os.urandom(16)
        sid = base64.b16encode(os.urandom(8)).decode()
        sessions[sid] = {"local": local, "remote": remote, "ok": False}
        resp = web.Response(body=remote + transport_cls.handshake1_seed_auth_hash(local, remote, auth))
        resp.headers["Set-Cookie"] = f"TP_SESSIONID={sid};TIMEOUT=86400"
        say("handshake1")
        return resp

    async def h2(request):
        s = sessions.get(request.cookies.get("TP_SESSIONID"))
        body = await request.read()
        if s is None or body != transport_cls.handshake2_seed_auth_hash(s["local"], s["remote"], auth):
            say("handshake2-refused")
            return web.Response(status=403)
        s["ok"] = True
        s["session"] = KlapEncryptionSession(s["local"], s["remote"], auth)
        say("handshake2")
        return web.Response(status=200)

    async def req(request):
        s = sessions.get(request.cookies.get("TP_SESSIONID"))
        if s is None or not s["ok"]:
            return web.Response(status=403)
        seq = int(request.query["seq"])
        sess = s["session"]
        body = await request.read()
        # python-kasa's session decrypts with the cipher of its current
        # sequence number and encrypts with the next one.
        sess._seq = seq
        sess._generate_cipher()
        plain = json.loads(sess.decrypt(body))
        say("request", plain)
        sess._seq = seq - 1
        out, _ = sess.encrypt(json.dumps(handle(plain)))
        return web.Response(body=out)

    app = web.Application()
    app.router.add_post("/app/handshake1", h1)
    app.router.add_post("/app/handshake2", h2)
    app.router.add_post("/app/request", req)
    return app


# --- securePassthrough -------------------------------------------------------

def aes_app(creds, login_version, handle):
    v2 = login_version == 2
    un, pw = AesTransport.hash_credentials(v2, creds)
    sessions = {}

    async def app_handler(request):
        msg = await request.json()
        if msg.get("method") == "handshake":
            pub = serialization.load_pem_public_key(msg["params"]["key"].encode())
            key_iv = os.urandom(32)
            enc = pub.encrypt(key_iv, asym_padding.PKCS1v15())
            sid = base64.b16encode(os.urandom(8)).decode()
            sessions[sid] = {"aes": AesEncyptionSession(key_iv[:16], key_iv[16:]), "token": None}
            resp = web.json_response({"error_code": 0, "result": {"key": base64.b64encode(enc).decode()}})
            resp.headers["Set-Cookie"] = f"TP_SESSIONID={sid};TIMEOUT=1440"
            say("handshake")
            return resp
        if msg.get("method") != "securePassthrough":
            return web.json_response({"error_code": -1002})
        s = sessions.get(request.cookies.get("TP_SESSIONID"))
        if s is None:
            return web.json_response({"error_code": 9999})
        inner = json.loads(s["aes"].decrypt(msg["params"]["request"]))
        if inner.get("method") == "login_device":
            p = inner.get("params") or {}
            field = "password2" if v2 else "password"
            ok = p.get("username") == un and p.get(field) == pw
            say("login", {"ok": ok, "fields": sorted(p.keys())})
            if ok:
                s["token"] = base64.b16encode(os.urandom(8)).decode()
                answer = {"error_code": 0, "result": {"token": s["token"]}}
            else:
                answer = {"error_code": -1501}
        elif s["token"] is None or request.query.get("token") != s["token"]:
            return web.json_response({"error_code": 9999})
        else:
            say("request", inner)
            answer = handle(inner)
        return web.json_response({"error_code": 0, "result": {"response": s["aes"].encrypt(json.dumps(answer).encode()).decode()}})

    app = web.Application()
    app.router.add_post("/app", app_handler)
    return app


# --- Discovery on 20002 -------------------------------------------------------

def check_probe(data):
    """Check a probe as python-kasa builds one: version 2, op code 1,
    flags 0x11, the payload length, and the CRC-32 computed with the seed
    0x5A6B7C8D in the CRC field."""
    if len(data) < 16:
        return "short"
    version, msg_type, op, length, flags = data[0], data[1], struct.unpack(">H", data[2:4])[0], struct.unpack(">H", data[4:6])[0], data[6]
    crc = struct.unpack(">I", data[12:16])[0]
    seeded = data[:12] + struct.pack(">I", 0x5A6B7C8D) + data[16:]
    if (version, msg_type, op, flags) != (2, 0, 1, 0x11):
        return f"header {version} {msg_type} {op} {flags:#x}"
    if length != len(data) - 16:
        return "length"
    if zlib.crc32(seeded) & 0xFFFFFFFF != crc:
        return "crc"
    try:
        key = json.loads(data[16:])["params"]["rsa_key"]
        serialization.load_pem_public_key(key.encode())
    except Exception as e:
        return "payload " + repr(e)
    return None


async def serve_tdp(fixtures):
    answers = []
    for f in fixtures:
        body = json.dumps(f["discovery_result"]).encode()
        answers.append(b"\x02\x00\x00\x01" + struct.pack(">H", len(body)) + b"\x11\x00" + bytes(8) + body)
    # The header python-kasa sends, for comparison.
    from kasa.discover import _AesDiscoveryQuery
    q = _AesDiscoveryQuery.generate_query()
    say("kasa-probe-header", {"hex": q[:8].hex(), "check": check_probe(q)})

    class Tdp(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, data, addr):
            problem = check_probe(data)
            say("probe", {"ok": problem is None, "problem": problem, "header": data[:8].hex()})
            if problem is None:
                for a in answers:
                    self.t.sendto(a, addr)

    await asyncio.get_running_loop().create_datagram_endpoint(Tdp, local_addr=("0.0.0.0", 20002))


async def main():
    mode = sys.argv[1]
    if mode == "xor":
        await serve_xor(IotState(load(sys.argv[2])))
    elif mode == "tdp":
        await serve_tdp([load(n) for n in sys.argv[2:]])
    else:
        fixture = load(sys.argv[2])
        creds = Credentials(sys.argv[3], sys.argv[4])
        if mode == "klap1":
            app = klap_app(KlapTransport, creds, IotState(fixture).handle)
        elif mode == "klap2":
            app = klap_app(KlapTransportV2, creds, SmartState(fixture).handle)
        else:
            app = aes_app(creds, int(sys.argv[5]), SmartState(fixture).handle)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", 80).start()
    say("ready", {"python-kasa": kasa.__version__ if hasattr(kasa, "__version__") else "?", "mode": mode})
    await asyncio.Event().wait()


asyncio.run(main())
