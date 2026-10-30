import os, sys, json, threading, http.server, socketserver, base64, secrets, http.client, hashlib, hmac as H
"""Regenerates the fixtures in this directory by running the PYTHON companion.

Usage: ARROWBRIDGE_PY_SRC=/path/to/arrowbridge-companion python3 gen_fixtures.py
Needs the Python companion checkout and its `cryptography` dependency. The Rust tests only
read the generated files; they never run Python."""
SRC = os.environ["ARROWBRIDGE_PY_SRC"]
OUT = os.path.dirname(os.path.abspath(__file__))
KEY = "fixture-pair-key-0123456789"
SYS = "You are a test."
import tempfile
_pf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False); _pf.write(SYS); _pf.close()

# ---- fake upstream
seen = []
class Up(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length","0")); b = json.loads(self.rfile.read(n) or b"{}")
        seen.append({"path": self.path, "body": b, "auth": self.headers.get("Authorization")})
        if self.path == "/v1/chat/completions":
            out = {"choices":[{"message":{"content":"Call 1-800-555-0100 or 911 now.  Thanks ."}}]}
        elif self.path == "/v1/messages":
            out = {"content":[{"type":"text","text":"Dial 613-555-0100 or 988 ok"},{"type":"tool_use"}],"stop_reason":"max_tokens","usage":{"input_tokens":3,"output_tokens":5}}
        elif self.path == "/v1/messages/count_tokens":
            out = {"input_tokens":7}
        else:
            self.send_response(404); self.end_headers(); return
        d = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(d))); self.end_headers(); self.wfile.write(d)
    def log_message(self,*a): pass
up = socketserver.ThreadingTCPServer(("127.0.0.1",0), Up); threading.Thread(target=up.serve_forever,daemon=True).start()
upport = up.server_address[1]

os.environ.update({"ARROWBRIDGE_PAIR_KEY":KEY,"ARROWBRIDGE_UPSTREAM_URL":"http://127.0.0.1:%d"%upport,
  "ARROWBRIDGE_UPSTREAM_MODEL":"m-default","ARROWBRIDGE_MODEL_MAP":"alpha=m-alpha,beta=m-beta@http://127.0.0.1:%d"%upport,
  "ARROWBRIDGE_SYSTEM_PROMPT_FILE":_pf.name,"ARROWBRIDGE_DEVICE_NAME":"fixture-box"})
sys.path.insert(0, SRC); sys.dont_write_bytecode = True
import companion_server as cs, tel_guard

srv = socketserver.ThreadingTCPServer(("127.0.0.1",0), cs.Handler); threading.Thread(target=srv.serve_forever,daemon=True).start()
port = srv.server_address[1]
def req(method, path, body=None, headers=None, raw=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    h = dict(headers or {})
    if data is not None: h.setdefault("Content-Type","application/json")
    c.request(method, path, body=data, headers=h); r = c.getresponse(); rb = r.read(); c.close()
    return r.status, r.getheader("Content-Type"), rb
K = {"X-ArrowBridge-Pair": KEY}
cases = []
def rec(name, method, path, body=None, headers=None, raw=None, text=False):
    seen.clear()
    st, ct, rb = req(method, path, body, headers, raw)
    e = {"name":name,"method":method,"path":path,"body":body,"raw":raw.decode() if raw is not None else None,"headers":headers or {},"status":st,"content_type":ct,
         "upstream_seen": list(seen)}
    if text: e["text"] = rb.decode()
    else: e["json"] = json.loads(rb)
    cases.append(e)
rec("unpaired_health","GET","/health")
rec("unpaired_chat","POST","/chat",{"message":"hi"})
rec("unpaired_unknown","GET","/nope")
rec("health","GET","/health",headers=K)
rec("health_bearer","GET","/health",headers={"Authorization":"Bearer "+KEY})
rec("unknown_paired_get","GET","/nope",headers=K)
rec("unknown_paired_post","POST","/nope",{"a":1},headers=K)
rec("chat_ok","POST","/chat",{"message":"hello","history":[{"role":"system","content":"x"},{"role":"user","content":"u1"},{"role":"assistant","content":"a1"},{"role":"user","content":""},"junk"]},headers=K)
rec("chat_no_message","POST","/chat",{"nope":1},headers=K)
rec("chat_bad_json","POST","/chat",headers=K,raw=b"{not json")
rec("msg_ok","POST","/v1/messages",{"model":"alpha","max_tokens":50,"system":"ignored","messages":[{"role":"user","content":"hi"},{"role":"system","content":"s"}]},headers=K)
rec("msg_default_model","POST","/v1/messages",{"messages":[{"role":"user","content":"hi"}]},headers=K)
rec("msg_unknown_model","POST","/v1/messages?beta=true",{"model":"zzz","messages":[{"role":"user","content":"hi"}]},headers=K)
rec("msg_beta_url_model","POST","/v1/messages",{"model":"beta","messages":[{"role":"user","content":"hi"}]},headers=K)
rec("msg_stream","POST","/v1/messages",{"stream":True,"messages":[{"role":"user","content":"hi"}]},headers=K,text=True)
rec("msg_empty","POST","/v1/messages",{"messages":[]},headers=K)
rec("msg_malformed","POST","/v1/messages",headers=K,raw=b"{x")
rec("count_tokens","POST","/v1/messages/count_tokens",{"model":"whatever","messages":[{"role":"user","content":"hi"}]},headers=K)
rec("count_tokens_bad","POST","/v1/messages/count_tokens",headers=K,raw=b"{x")
rec("pair_session_no_key","POST","/pair-session",{})
rec("pair_session_ok_shape","POST","/pair-session",{},headers=K)
# tokens are random: normalise in the test, keep shape
rec("pair_start_closed","POST","/pair-start",{"public_key":"AA==","commitment":"AA=="})
rec("pair_info_loopback","GET","/pair-info")
rec("pair_status_window_closed","GET","/pair-status")
rec("pair_test_page","GET","/pair-test",text=True)
# bad-content-length
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
c.putrequest("POST","/chat"); c.putheader("Content-Length","abc"); c.endheaders(); r=c.getresponse(); cases.append({"name":"bad_content_length","method":"POST","path":"/chat","status":r.status,"json":json.loads(r.read())}); c.close()
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
c.putrequest("POST","/chat"); c.putheader("Content-Length",str((1<<20)+1)); c.endheaders(); r=c.getresponse(); cases.append({"name":"oversized_content_length","method":"POST","path":"/chat","status":r.status,"json":json.loads(r.read())}); c.close()
# pair-info with a proxy header
rec("pair_info_proxy_header","GET","/pair-info",headers={"X-Forwarded-For":"1.2.3.4"})
json.dump({"key":KEY,"system_prompt":SYS,"cases":cases}, open(OUT+"/routes.json","w"), indent=1)

# ---- pair page, as the Python renders it with a LAN-shaped config (template only)

# ---- full handshake against the live Python server, fixed phone material
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
b64 = lambda x: base64.b64encode(x).decode()
priv = x25519.X25519PrivateKey.from_private_bytes(bytes(range(1,33)))
pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
pn = bytes(range(100,116))
assert req("POST","/pair-open",{})[0]==200
st,_,rb = req("POST","/pair-start",{"public_key":b64(pub),"commitment":b64(hashlib.sha256(pn+pub).digest())}); s=json.loads(rb)
hid=s["handshake_id"]; cpub=base64.b64decode(s["public_key"]); ccom=base64.b64decode(s["commitment"])
st,_,rb = req("POST","/pair-reveal",{"handshake_id":hid,"nonce":b64(pn)}); rv=json.loads(rb); cn=base64.b64decode(rv["companion_nonce"])
ss = priv.exchange(x25519.X25519PublicKey.from_public_bytes(cpub))
sk, code = cs._derive_pairing_material(ss, pn, cn, cpub, pub)
assert req("POST","/pair-confirm",{"handshake_id":hid})[0]==200
proof = H.new(sk, hid.encode(), "sha256").hexdigest()
st,_,rb = req("POST","/pair-finish",{"handshake_id":hid,"proof":proof}); fin=json.loads(rb)
cred = AESGCM(sk).decrypt(base64.b64decode(fin["credential_nonce"]), base64.b64decode(fin["credential_ciphertext"]), hid.encode()).decode()
hs = {"phone_priv":priv.private_bytes(Encoding.Raw,__import__("cryptography.hazmat.primitives.serialization",fromlist=["x"]).PrivateFormat.Raw,__import__("cryptography.hazmat.primitives.serialization",fromlist=["x"]).NoEncryption()).hex(),
 "phone_pub":pub.hex(),"phone_nonce":pn.hex(),"phone_commitment":hashlib.sha256(pn+pub).hexdigest(),"handshake_id":hid,
 "companion_pub":cpub.hex(),"companion_nonce":cn.hex(),"companion_commitment":ccom.hex(),"shared_secret":ss.hex(),
 "session_key":sk.hex(),"code":code,"proof":proof,"credential_nonce":fin["credential_nonce"],"credential_ciphertext":fin["credential_ciphertext"],"credential":cred}
# extra derivation vectors
vec=[]
for i in range(20):
    ssx=secrets.token_bytes(32); a=secrets.token_bytes(16); b=secrets.token_bytes(16); cp=secrets.token_bytes(32); pp=secrets.token_bytes(32)
    k,cd=cs._derive_pairing_material(ssx,a,b,cp,pp)
    vec.append({"shared":ssx.hex(),"phone_nonce":a.hex(),"comp_nonce":b.hex(),"comp_pub":cp.hex(),"phone_pub":pp.hex(),"key":k.hex(),"code":cd})
json.dump({"handshake":hs,"vectors":vec}, open(OUT+"/pairing.json","w"), indent=1)

# ---- tel guard corpus
corpus = ["Call 1-800-555-0100 now","(613) 555-0100 or 613.555.0100","Dial 911 now, not 988","Code 12345 and 123456 and 1234567","Plain text, nothing.","a  b   c .","x 555-0100 y","tel:+1 613 555 0100 end","Order 12-3456","call me at 6135550100","1 613 555 0100","613-555-01000","a 123-456-7890. b , c","", "line1  \n  line2 988 ;ok","9111","911911","year 20260 ok","Ligne 514 555 0199, merci","été 12345 à"]
tg=[]
for t in corpus:
    out,off = tel_guard.redact(t)
    tg.append({"in":t,"out":out,"offenders":off})
json.dump(tg, open(OUT+"/telguard.json","w"), indent=1)

# ---- SSE / payloads
sse=[]
for text,sr,usage,model in [("hi","end_turn",{"input_tokens":3,"output_tokens":5},"m1"),("x","max_tokens",None,None),("",  "end_turn",{},"m2")]:
    sse.append({"text":text,"stop_reason":sr,"usage":usage,"model":model,"body":cs._build_sse_body(text,sr,usage,model=model)})
json.dump(sse, open(OUT+"/sse.json","w"), indent=1)
print("ok", len(cases), "cases", "code", code)

# ---- the loopback pair page and the QR payload vectors
import html
os.environ["ARROWBRIDGE_DEVICE_NAME"] = "fixture-box"
open(OUT + "/pair_page_loopback.html", "w").write(cs._pair_page_html())
names = ["fixture-box", "Owner's <Box> & \"co\"", "caf\u00e9 \u2603 \U0001F600", "tab\tnew\nline \\ end"]
json.dump([{"address": "http://192.168.1.20:8788", "name": n,
            "payload": json.dumps(cs._pairing_qr_payload("http://192.168.1.20:8788", n), separators=(",", ":"), sort_keys=True)}
           for n in names], open(OUT + "/qr_payloads.json", "w"), indent=1)
json.dump([{"in": n, "out": html.escape(n)} for n in names], open(OUT + "/html_escape.json", "w"), indent=1)
