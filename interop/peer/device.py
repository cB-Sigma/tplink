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
#                                                       ("enc:<fixture>": with encrypt_info)
#   python device.py sslaes <smartcam fixture> <user> <pass>   HTTPS 443, camera transport
#   python device.py klap2-https <smart fixture> <user> <pass> HTTPS 443, KLAP v2
#   python device.py linkie <iotcam fixture> <user> <pass>     HTTPS 443, Kasa camera
#   python device.py ssl <smart fixture> <user> <pass>         HTTPS 443, plain login
#
# Since v0.2.0 the Tapo answers also take multipleRequest, paged lists and
# set_<name> for any setting the fixture recorded; module-level errors of
# the legacy fixtures are answered as recorded. The HTTPS modes make a
# throwaway self-signed certificate.
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

import kasa
from kasa.credentials import Credentials
from kasa.transports.aestransport import AesEncyptionSession, AesTransport, KeyPair
from kasa.transports.klaptransport import KlapEncryptionSession, KlapTransport, KlapTransportV2
from kasa.transports.xortransport import XorEncryption

FIXTURES = "/python-kasa/tests/fixtures/"


def say(event, obj=None):
    print("PEER " + event + ("" if obj is None else " " + json.dumps(obj, sort_keys=True, default=str)), flush=True)


def load(name):
    for sub in ("smart/", "iot/", "smartcam/", "iotcam/"):
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
            fm = self.f.get(mod)
            if isinstance(fm, dict) and "err_code" in fm:
                # The fixture recorded the whole module as missing.
                out[mod] = fm
                continue
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
        if method == "multipleRequest":
            # Answered request by request, in order, each with its code.
            out = []
            for r in params.get("requests") or []:
                a = self.handle(r)
                one = {"method": r.get("method"), "error_code": a.get("error_code", 0)}
                if "result" in a:
                    one["result"] = a["result"]
                out.append(one)
            return {"error_code": 0, "result": {"responses": out}}
        if method == "set_device_info":
            self.f["get_device_info"].update(params)
            return {"error_code": 0, "result": {}}
        if method.startswith("set_") and isinstance(self.f.get("get_" + method[4:]), dict):
            # A setting the fixture recorded: merged and kept.
            self.f["get_" + method[4:]].update(params)
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
            res = self.f[method]
            if isinstance(res, int):
                return {"error_code": res}  # the fixture recorded an error
            if isinstance(res, dict) and "start_index" in res and "sum" in res:
                # A paged list: the recorded page from the asked start.
                lists = [k for k, v in res.items() if isinstance(v, list)]
                if lists:
                    start = int(params.get("start_index", 0))
                    res = dict(res, start_index=start, **{lists[0]: res[lists[0]][start:start + 10]})
            return {"error_code": 0, "result": res}
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


# --- HTTPS camera transport -----------------------------------------------------

class CamState:
    """Camera ("smartcam") answers from a smartcam fixture."""

    def __init__(self, fixture):
        self.f = fixture

    def one(self, method, params):
        if method.startswith("set") and isinstance(self.f.get("get" + method[3:]), dict):
            for k, v in (params or {}).items():
                self.f["get" + method[3:]].setdefault(k, {}).update(v)
            return {"method": method, "error_code": 0, "result": {}}
        if method in self.f and isinstance(self.f[method], dict) and not method.startswith("discovery"):
            return {"method": method, "error_code": 0, "result": self.f[method]}
        return {"method": method, "error_code": -40106}

    def handle(self, req):
        if req.get("method") == "multipleRequest":
            return {"error_code": 0, "result": {"responses": [self.one(r.get("method"), r.get("params")) for r in req["params"]["requests"]]}}
        a = self.one(req.get("method"), req.get("params"))
        a.pop("method")
        return a


def self_signed(path):
    """A throwaway self-signed certificate, as devices use."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tplink-interop")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    with open(path + ".key", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(path + ".crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(path + ".crt", path + ".key")
    return ctx


def sslaes_app(user, password, handle):
    """The camera transport's device side, computed with python-kasa's
    SslAesTransport functions (confirm, digest, keys, tag) and its
    AesEncyptionSession."""
    from kasa.transports.sslaestransport import SslAesTransport as T, _sha256_hash
    pwd_hash = _sha256_hash(password.encode())
    nonces, sessions = {}, {}

    async def root(request):
        msg = await request.json()
        p = msg.get("params") or {}
        if msg.get("method") != "login":
            return web.json_response({"error_code": -40401})
        if p.get("username") != user:
            say("login", {"ok": False, "step": 1})
            return web.json_response({"error_code": -40401, "result": {"data": {"code": -40411, "encrypt_type": ["3"]}}})
        cnonce = p.get("cnonce")
        if "digest_passwd" in p:
            nonce = nonces.pop(cnonce, None)
            ok = nonce is not None and p["digest_passwd"] == T.generate_digest_password(cnonce, nonce, pwd_hash)
            say("login", {"ok": ok, "step": 2})
            if not ok:
                return web.json_response({"error_code": -40413, "result": {"data": {"code": -40413}}})
            stok = os.urandom(8).hex()
            lsk = T.generate_encryption_token("lsk", cnonce, nonce, pwd_hash)
            ivb = T.generate_encryption_token("ivb", cnonce, nonce, pwd_hash)
            sessions[stok] = {"aes": AesEncyptionSession(lsk, ivb), "cnonce": cnonce, "seq": 7}
            return web.json_response({"error_code": 0, "result": {"stok": stok, "user_group": "root", "start_seq": 7}})
        nonce = os.urandom(8).hex().upper()
        nonces[cnonce] = nonce
        say("login", {"ok": True, "step": 1})
        return web.json_response({"error_code": -40413, "result": {"data": {"code": -40413, "encrypt_type": ["3"], "key": "",
                                  "nonce": nonce, "device_confirm": T.generate_confirm_hash(cnonce, nonce, pwd_hash)}}})

    async def ds(request):
        s = sessions.get(request.match_info["stok"])
        if s is None:
            return web.Response(status=401)
        body = (await request.read()).decode()
        seq = int(request.headers.get("Seq", "-1"))
        tag_ok = seq == s["seq"] and request.headers.get("Tapo_tag") == T.generate_tag(body, s["cnonce"], pwd_hash, seq)
        say("tag", {"ok": tag_ok, "seq": seq})
        if not tag_ok:
            return web.json_response({"error_code": -40401})
        s["seq"] += 1
        inner = json.loads(s["aes"].decrypt(json.loads(body)["params"]["request"]))
        say("request", inner)
        out = s["aes"].encrypt(json.dumps(handle(inner)).encode()).decode()
        return web.json_response({"error_code": 0, "result": {"response": out}})

    app = web.Application()
    app.router.add_post("/", root)
    app.router.add_post("/stok={stok}/ds", ds)
    return app


def linkie_app(user, password, handle):
    """The Kasa camera transport: basic authentication, the form field
    "content" with python-kasa's XorEncryption (without the length) in
    base64, answered the same way."""
    expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    async def data(request):
        if request.headers.get("Authorization") != expected:
            say("linkie-auth", {"ok": False})
            return web.Response(status=401)
        form = await request.post()
        req = json.loads(XorEncryption.decrypt(base64.b64decode(form["content"])))
        say("request", req)
        out = XorEncryption.encrypt(json.dumps(handle(req)))[4:]
        return web.Response(body=base64.b64encode(out))

    app = web.Application()
    app.router.add_post("/data/LINKIE2.json", data)
    return app


def ssl_app(user, password, handle):
    """The plain HTTPS transport: login with python-kasa's hashing
    (SslTransport.hash_credentials), then requests in clear."""
    from kasa.transports.ssltransport import SslTransport
    _, pw = SslTransport.hash_credentials(Credentials(user, password))
    tokens = set()

    async def app_handler(request):
        msg = await request.json()
        if msg.get("method") == "login":
            p = msg.get("params") or {}
            ok = p.get("username") == user and p.get("password") == pw
            say("login", {"ok": ok})
            if not ok:
                return web.json_response({"error_code": -1501})
            tok = os.urandom(8).hex()
            tokens.add(tok)
            return web.json_response({"error_code": 0, "result": {"token": tok}})
        if request.query.get("token") not in tokens:
            return web.json_response({"error_code": 9999})
        say("request", msg)
        return web.json_response(handle(msg))

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


SECRET = {"connect_ssid": "Demo-Home", "connect_type": "wireless"}


def seal(pub_pem, data):
    """encrypt_info for data, encrypted to a probe's key: a fresh AES-128
    key and IV with RSA OAEP (SHA-1), the JSON with python-kasa's
    AesEncyptionSession."""
    pub = serialization.load_pem_public_key(pub_pem.encode())
    key_iv = os.urandom(32)
    ek = pub.encrypt(key_iv, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
    return {"sym_schm": "AES", "key": base64.b64encode(ek).decode(),
            "data": AesEncyptionSession(key_iv[:16], key_iv[16:]).encrypt(json.dumps(data).encode()).decode()}


def check_seal():
    """python-kasa's own discovery decryption reads what seal() makes."""
    from kasa.discover import Discover, DiscoveryResult, _AesDiscoveryQuery
    _AesDiscoveryQuery.keypair = KeyPair.create_key_pair(key_size=2048)
    pem = _AesDiscoveryQuery.keypair.get_public_pem().decode()
    dr = DiscoveryResult.from_dict({"device_type": "SMART.TAPOPLUG", "device_model": "P110(EU)", "device_id": "X", "ip": "127.0.0.1",
                                    "mac": "00-00-00-00-00-00", "encrypt_info": seal(pem, SECRET)})
    Discover._decrypt_discovery_data(dr)
    return dr.decrypted_data == SECRET


async def serve_tdp(fixtures):
    answers = []
    for f in fixtures:
        answers.append(f["discovery_result"])
    say("seal-check", {"ok": check_seal()})

    def frame(result, pub_pem):
        res = copy.deepcopy(result)
        if res.get("result", {}).pop("_seal", False):
            res["result"]["encrypt_info"] = seal(pub_pem, SECRET)
        body = json.dumps(res).encode()
        return b"\x02\x00\x00\x01" + struct.pack(">H", len(body)) + b"\x11\x00" + bytes(8) + body
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
                pub = json.loads(data[16:])["params"]["rsa_key"]
                for a in answers:
                    self.t.sendto(frame(a, pub), addr)

    await asyncio.get_running_loop().create_datagram_endpoint(Tdp, local_addr=("0.0.0.0", 20002))


async def main():
    mode = sys.argv[1]
    if mode == "xor":
        await serve_xor(IotState(load(sys.argv[2])))
    elif mode == "tdp":
        # A name "enc:<fixture>" sends that answer with an encrypt_info
        # sealed to the probe's key.
        fixtures = []
        for n in sys.argv[2:]:
            f = load(n.removeprefix("enc:"))
            if n.startswith("enc:"):
                f = copy.deepcopy(f)
                f["discovery_result"]["result"]["_seal"] = True
            fixtures.append(f)
        await serve_tdp(fixtures)
    elif mode in ("sslaes", "klap2-https", "linkie", "ssl"):
        # HTTPS on 443 with a self-signed certificate.
        fixture = load(sys.argv[2])
        if mode == "sslaes":
            app = sslaes_app(sys.argv[3], sys.argv[4], CamState(fixture).handle)
        elif mode == "linkie":
            app = linkie_app(sys.argv[3], sys.argv[4], IotState(fixture).handle)
        elif mode == "ssl":
            app = ssl_app(sys.argv[3], sys.argv[4], SmartState(fixture).handle)
        else:
            app = klap_app(KlapTransportV2, Credentials(sys.argv[3], sys.argv[4]), SmartState(fixture).handle)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", 443, ssl_context=self_signed("/tmp/peer")).start()
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
