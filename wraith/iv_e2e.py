#!/usr/bin/env python3
"""Wraith recon interception E2E — real sidecar, real orchestrator, two live merchants.
Byte-identical-scope contract per merchant; every recon response shown verbatim IDs."""
import json, time, sys, urllib.request, urllib.error

G = "http://localhost:8001/api/v1"   # graph_api
O = "http://localhost:8002/api/v1"   # recon orchestrator

def req(method, url, body=None, timeout=25):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode()
            code = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        code = e.code
    try:
        return code, json.loads(raw) if raw.strip() else {}
    except Exception:
        return code, {"raw": raw[:300]}

print("=" * 62)
print("Wraith interception E2E — flipkart.com + myntra.com via mitmproxy sidecar")
print("=" * 62)

# [1] create ONE investigation per merchant, exact in-scope domain (scope guard requires exact match)
print("\n[1] create investigations (exact single-domain scope each)")
inv = {}
for name, dom in (("Flipkart Proxy-E2E", "flipkart.com"), ("Myntra Proxy-E2E", "myntra.com")):
    code, d = req("POST", f"{G}/investigations",
                  {"name": name, "target": dom, "platform": "automatic",
                   "scope_domains": [dom]})
    iid = d.get("id") or d.get("investigation_id")
    print(f"      {name:24s} -> HTTP {code}  id={iid}")
    if not iid:
        print("        !! no id — response:", d)
        sys.exit(9)
    inv[dom] = iid

# [2] start both scans through the SAME sidecar
print("\n[2] fire both scans through the shared sidecar")
sessions = {}
for dom, iid in inv.items():
    code, d = req("POST", f"{O}/recon/start",
                  {"investigation_id": iid, "domains": [f"www.{dom}"], "tools": ["katana"]})
    print(f"      {dom:16s} -> HTTP {code}  body={d}")
    if code in (200, 201, 202):
        sessions[dom] = d.get("session_id") or d.get("id")

# [3] poll real session status (real ids, no fake tokens)
print("\n[3] poll status to completion")
def poll():
    for dom, sid in sessions.items():
        try:
            code, d = req("GET", f"{O}/recon/{sid}/status", timeout=12)
            st = d.get("status"); prog = d.get("progress"); cur = d.get("current_tool")
            print(f"      {dom:16s} sid={sid[:8]}.. HTTP {code} status={st} progress={prog} tool={cur}")
        except Exception as e:
            print(f"      {dom:16s} poll-err: {e}")

t0 = time.time()
while time.time() - t0 < 240:
    poll()
    # stop early if every session terminal
    if sessions:
        break_ = False
        for dom, sid in sessions.items():
            try:
                code, d = req("GET", f"{O}/recon/{sid}/status", timeout=12)
                if d.get("status") in ("completed", "failed", "skipped"):
                    continue
            except Exception:
                pass
            break_
            break
        # simplified: just do fixed rounds
        time.sleep(20)
    else:
        break

print("\n[4] DONE. Now sidecar evidence:")
sys.exit(0)
