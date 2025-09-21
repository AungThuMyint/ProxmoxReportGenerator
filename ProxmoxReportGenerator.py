#!/usr/bin/env python3
import argparse
import datetime as dt
import io
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3
from fpdf import FPDF
from fpdf.enums import XPos, YPos

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_REALM = "pam"
VERIFY_SSL_DEFAULT = False
TIMEOUT = 20

LOGO_W_MM = 18
HEADER_GAP_MM = 6
LOGO_CLEAR_H_MM = 16

def parse_user_and_realm(user: str) -> Tuple[str, str]:
    if "@" in user:
        u, realm = user.split("@", 1)
        return f"{u}@{realm}", realm
    return f"{user}@{DEFAULT_REALM}", DEFAULT_REALM

def _to_gib(n: int) -> float:
    try:
        return float(n or 0) / (1024.0 ** 3)
    except Exception:
        return 0.0

def format_gib(n: int) -> str:
    g = _to_gib(n)
    if g < 10:
        return f"{g:.2f} GiB" if g < 1 else f"{g:.1f} GiB"
    return f"{g:.0f} GiB"

def pct(a: float, b: float) -> float:
    if not b:
        return 0.0
    return (a / b) * 100.0

def secs_to_hms(seconds: int) -> str:
    d = dt.timedelta(seconds=int(seconds or 0))
    days = d.days
    h, rem = divmod(d.seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{days}d {h:02d}:{m:02d}:{s:02d}" if days else f"{h:02d}:{m:02d}:{s:02d}"

def safe_get(d: Dict, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def clean_str(s: Optional[str]) -> str:
    return (s or "").strip().strip('"')

def load_logo_bytes(local_path: Optional[str]) -> bytes:
    if not local_path:
        raise SystemExit("[ERROR] --logo is required (path to PNG/JPG).")
    try:
        with open(local_path, "rb") as f:
            b = f.read()
            if not b:
                raise ValueError("file is empty")
            return b
    except Exception as e:
        raise SystemExit(f"[ERROR] Could not read logo file '{local_path}': {e}")

def join_nonempty(parts: List[str], sep=", ") -> str:
    return sep.join([p for p in parts if p])

def parse_bridge_from_netconf(val: str) -> List[str]:
    if not val:
        return []
    out = []
    for part in str(val).split(","):
        part = part.strip()
        if part.startswith("bridge="):
            br = part.split("=", 1)[1].strip()
            if br:
                out.append(br)
    return out

def parse_vlan_tag_from_netconf(val: str) -> Optional[str]:
    if not val:
        return None
    m = re.search(r"(?:^|,)\s*tag\s*=\s*(\d+)", str(val))
    return m.group(1) if m else None

def _parse_speed_to_mbps(val: Any) -> Optional[float]:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val) if val > 0 else None
    s = str(val).strip().lower()
    if not s:
        return None
    m = re.search(r"(\d+(?:\.\d+)?)", s)
    if not m:
        return None
    num = float(m.group(1))
    if "gb" in s or "gbit" in s or "g/s" in s:
        return num * 1000.0
    if "mb" in s or "m/s" in s or " m" in s:
        return num
    if "kb" in s or "k " in s:
        return num / 1000.0
    return num

def _mbps_to_text(mbps: Optional[float]) -> str:
    if not mbps or mbps <= 0:
        return "-"
    if mbps >= 1000:
        g = mbps / 1000.0
        return f"{g:.1f} Gbps" if abs(g - round(g)) > 1e-6 else f"{int(round(g))} Gbps"
    return f"{int(round(mbps))} Mbps"

def _extract_iface_speed_map_from_networks(networks: List[Dict[str, Any]]) -> Dict[str, float]:
    m: Dict[str, float] = {}
    for n in networks or []:
        name = n.get("iface") or n.get("ifname")
        if not name:
            continue
        cand = (
            n.get("speed") or n.get("speed_mbps") or n.get("link_speed") or
            n.get("rate") or n.get("speed-gbps") or n.get("speed_mbit")
        )
        mbps = _parse_speed_to_mbps(cand)
        if not mbps:
            c = n.get("comments") or ""
            mbps = _parse_speed_to_mbps(c)
            if not mbps:
                mobj = re.search(r"speed\s*=\s*([0-9.]+)\s*([gmk]?)", str(c).lower())
                if mobj:
                    num = float(mobj.group(1)); unit = mobj.group(2)
                    mbps = num*1000.0 if unit == "g" else num if unit in ("m","") else num/1000.0
        if mbps:
            m[name] = mbps
    return m

def _bond_speed_text(bond_obj: Dict[str, Any], speed_map: Dict[str, float]) -> str:
    slaves = bond_obj.get("slaves") or []
    spds = [speed_map.get(s) for s in slaves if speed_map.get(s)]
    if not spds:
        return "-"
    same = all(abs(spds[0] - v) < 1e-6 for v in spds)
    agg = sum(spds)
    if same and len(spds) > 1:
        per = _mbps_to_text(spds[0])
        return f"{len(spds)}×{per} (agg {_mbps_to_text(agg)})"
    return f"agg {_mbps_to_text(agg)}"

def collect_iface_speeds_via_ssh(host: str, user: str, password: Optional[str], keyfile: Optional[str], port: int = 22, timeout: int = 8) -> Dict[str, float]:
    try:
        import paramiko
    except Exception:
        sys.stderr.write("[WARN] paramiko not installed; NIC speeds will remain '-'. Install: pip install paramiko\n")
        return {}

    speeds: Dict[str, float] = {}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if keyfile:
            client.connect(host, port=port, username=user, key_filename=keyfile, timeout=timeout, allow_agent=True, look_for_keys=True)
        else:
            client.connect(host, port=port, username=user, password=password, timeout=timeout, allow_agent=True, look_for_keys=True)

        sh = r'''/bin/sh -lc '
for i in /sys/class/net/*; do n=$(basename "$i"); s=$(cat "$i/speed" 2>/dev/null || echo -1); echo "S:$n:$s"; done
for i in $(ls -1 /sys/class/net); do sp=$(ethtool "$i" 2>/dev/null | awk -F": " "/Speed:/ {print \$2; exit}"); if [ -n "$sp" ]; then echo "E:$i:$sp"; fi; done
' '''
        stdin, stdout, stderr = client.exec_command(sh, timeout=timeout)
        out = stdout.read().decode("utf-8", "ignore").splitlines()

        tmp_sys: Dict[str, float] = {}
        tmp_et: Dict[str, float] = {}
        for line in out:
            if not line.strip():
                continue
            if line.startswith("S:"):
                _, iface, val = line.split(":", 2)
                try:
                    v = float(val)
                    if v > 0:
                        tmp_sys[iface] = v
                except Exception:
                    pass
            elif line.startswith("E:"):
                _, iface, val = line.split(":", 2)
                mbps = _parse_speed_to_mbps(val)
                if mbps:
                    tmp_et[iface] = mbps
        for k, v in tmp_sys.items():
            speeds[k] = v
        for k, v in tmp_et.items():
            speeds.setdefault(k, v)

    except Exception as e:
        sys.stderr.write(f"[WARN] SSH speed collection failed for {host}: {e}\n")
        return {}
    finally:
        try:
            client.close()
        except Exception:
            pass

    return speeds

def ssh_lookup_ips_by_macs(host: str, user: str, password: Optional[str], keyfile: Optional[str], macs: List[str], port: int = 22, timeout: int = 8) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    if not macs:
        return result

    try:
        import paramiko
    except Exception:
        return result

    macs_l = [m.lower() for m in macs if m]
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if keyfile:
            client.connect(host, port=port, username=user, key_filename=keyfile, timeout=timeout, allow_agent=True, look_for_keys=True)
        else:
            client.connect(host, port=port, username=user, password=password, timeout=timeout, allow_agent=True, look_for_keys=True)

        sh = r"""/bin/sh -lc '
(ip -4 neigh show || true) | awk '"'"'/lladdr/{print tolower($1),tolower($5)}'"'"'
(cat /proc/net/arp 2>/dev/null || true) | awk "NR>1 {print tolower($1),tolower($4)}"
'"""
        _, stdout, _ = client.exec_command(sh, timeout=timeout)
        pairs = [ln.strip().split() for ln in stdout.read().decode("utf-8","ignore").splitlines() if ln.strip()]
        ip_by_mac: Dict[str, List[str]] = {}
        for parts in pairs:
            if len(parts) != 2:
                continue
            ip, mac = parts[0], parts[1]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                ip_by_mac.setdefault(mac, [])
                if ip not in ip_by_mac[mac]:
                    ip_by_mac[mac].append(ip)
        for m in macs_l:
            if m in ip_by_mac:
                result[m] = ip_by_mac[m]
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass
    return result

def extract_macs_from_netconf(val: str) -> List[str]:
    macs: List[str] = []
    for m in re.finditer(r"(?:^|,)\s*(?:virtio|e1000|rtl8139|vmxnet|hwaddr)\s*=\s*([0-9A-Fa-f:]{17})", str(val)):
        macs.append(m.group(1).lower())
    return macs

class ProxmoxAPI:
    def __init__(
        self,
        host: str,
        verify_ssl: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
        otp: Optional[str] = None,
        token_user: Optional[str] = None,
        token_id: Optional[str] = None,
        token_secret: Optional[str] = None,
        debug: bool = False,
    ):
        token_user = clean_str(token_user)
        token_id = clean_str(token_id)
        token_secret = clean_str(token_secret)
        username = clean_str(username)
        password = clean_str(password)
        otp = clean_str(otp)

        if token_id and "!" in token_id:
            left, right = token_id.split("!", 1)
            if not token_user:
                token_user = left
            token_id = right
        if token_user and token_user.endswith("!"):
            token_user = token_user[:-1]

        self.host = host.strip().rstrip("/")
        self.base = f"https://{self.host}:8006/api2/json"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.debug = debug

        self.username = None
        self.realm = None
        self.password = password
        self.otp = otp

        self.token_user = token_user
        self.token_id = token_id
        self.token_secret = token_secret
        self.ticket = None
        self.csrf = None

        if username:
            self.username, self.realm = parse_user_and_realm(username)
        self.use_token = all([self.token_user, self.token_id, self.token_secret])

        if self.use_token:
            if not re.match(r"^[^@]+@[A-Za-z0-9_.-]+$", self.token_user):
                raise SystemExit("[ERROR] --token-user must look like user@realm (e.g., root@pam)")
            if not re.match(r"^[A-Za-z0-9_.-]+$", self.token_id):
                raise SystemExit("[ERROR] --token-id may contain letters, digits, dot, dash, underscore]")
            if not self.token_secret or any(c.isspace() for c in self.token_secret):
                raise SystemExit("[ERROR] --token-secret empty or contains whitespace.")
        if not self.use_token and (not self.username or not self.password):
            raise SystemExit("[ERROR] Provide --username and --password, or use token auth flags].")

    def login(self):
        if self.use_token:
            return
        url = f"{self.base}/access/ticket"
        data = {"username": self.username, "password": self.password}
        if self.otp:
            data["otp"] = self.otp
        r = self.session.post(url, data=data, timeout=TIMEOUT)
        r.raise_for_status()
        j = r.json()["data"]
        self.ticket = j["ticket"]
        self.csrf = j.get("CSRFPreventionToken")
        self.session.cookies.set("PVEAuthCookie", self.ticket)

    def _headers(self):
        h = {"Accept": "application/json"}
        if not self.use_token and self.csrf:
            h["CSRFPreventionToken"] = self.csrf
        if self.use_token:
            h["Authorization"] = f"PVEAPIToken={self.token_user}!{self.token_id}={self.token_secret}"
        return h

    def get(self, path: str, params=None):
        url = f"{self.base}/{path.lstrip('/')}"
        r = self.session.get(url, headers=self._headers(), params=params or {}, timeout=TIMEOUT)
        if self.debug and r.status_code >= 400:
            sys.stderr.write(f"[DEBUG] GET {url} → {r.status_code}\n{r.text}\n")
        r.raise_for_status()
        return r.json()["data"]

    def cluster_status(self): return self.get("/cluster/status")
    def nodes(self): return self.get("/nodes")
    def node_status(self, node: str): return self.get(f"/nodes/{node}/status")
    def node_network(self, node: str): return self.get(f"/nodes/{node}/network")
    def cluster_vm_resources(self): return self.get("/cluster/resources", params={"type":"vm"})
    def cluster_storage_resources(self): return self.get("/cluster/resources", params={"type":"storage"})
    def version(self):
        url = f"https://{self.host}:8006/api2/json/version"
        r = self.session.get(url, timeout=TIMEOUT, verify=self.session.verify)
        r.raise_for_status()
        return r.json()["data"]
    def qemu_config(self, node: str, vmid: int): return self.get(f"/nodes/{node}/qemu/{vmid}/config")
    def lxc_config(self, node: str, vmid: int):  return self.get(f"/nodes/{node}/lxc/{vmid}/config")
    def qemu_agent_interfaces(self, node: str, vmid: int):
        return self.get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")

class ReportPDF(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logo_bytes = None
        self._logo_stream = None
        self._generated_by: Optional[str] = None

    def _latin1(self, s: str) -> str:
        if s is None:
            return ""
        repl = {
            "\u2013": "-",
            "\u2014": "-",
            "\u2012": "-",
            "\u2212": "-",
            "\u2018": "'",
            "\u2019": "'",
            "\u201C": '"',
            "\u201D": '"',
            "\u2026": "...",
            "\u00A0": " ",
            "\u200B": "",
        }
        out = "".join(repl.get(ch, ch) for ch in str(s))
        try:
            out.encode("latin-1")
            return out
        except Exception:
            return out.encode("latin-1", "replace").decode("latin-1")

    def set_logo(self, logo_bytes: bytes):
        self._logo_bytes = logo_bytes or b""
        self._logo_stream = io.BytesIO(self._logo_bytes)

    def set_generated_by(self, name: Optional[str]):
        self._generated_by = (name or "").strip() or None

    def header(self):
        left, top = self.l_margin, self.t_margin
        x_logo = self.w - self.r_margin - LOGO_W_MM
        if self._logo_bytes and len(self._logo_bytes) > 0:
            try:
                self._logo_stream.seek(0)
                self.image(self._logo_stream, x=x_logo, y=top, w=LOGO_W_MM)
            except Exception:
                pass
        title_w = self.w - self.l_margin - self.r_margin - (LOGO_W_MM + HEADER_GAP_MM)
        title_w = max(60, title_w)
        self.set_xy(left, top + 2)
        self.set_font("Helvetica", "B", 18)
        self.cell(title_w, 10, self._latin1("Proxmox Cluster & Nodes Summary"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        y_line = max(self.get_y(), top + LOGO_CLEAR_H_MM)
        self.set_line_width(0.2)
        self.line(left, y_line, x_logo - 2, y_line)
        self.set_y(y_line + 4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        left_text = (
            f"Generated By {self._generated_by}"
            if self._generated_by
            else f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.cell(0, 10, self._latin1(left_text), new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(0, 10, self._latin1(f"Page {self.page_no()}/{{nb}}"), align="R",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)

    def section_title(self, text: str):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 8, self._latin1(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def key_values(self, rows: List[Tuple[str, str]]):
        self.set_font("Helvetica", "", 11)
        key_w = 50
        for k, v in rows:
            self.cell(key_w, 7, self._latin1(f"{k}:"),
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(0, 7, self._latin1(str(v)),
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def _fit_text(self, text: str, max_width_mm: float) -> str:
        text = self._latin1(text)
        max_w = max_width_mm - 1.0
        if self.get_string_width(text) <= max_w:
            return text
        ell = "..."
        ell_w = self.get_string_width(ell)
        out = ""
        for ch in text:
            if self.get_string_width(out + ch) + ell_w > max_w:
                break
            out += ch
        return out + ell

    def table(self, headers: List[str], rows: List[List[str]],
              weights: Optional[List[float]] = None, min_widths: Optional[List[float]] = None):
        usable = self.w - self.l_margin - self.r_margin
        n = len(headers)
        weights = weights or [1]*n
        min_widths = min_widths or [0]*n

        pad = 2.5
        self.set_font("Helvetica","B",10)
        header_w = [self.get_string_width(self._latin1(h))+pad for h in headers]
        self.set_font("Helvetica","",9)
        body_w = [0.0]*n
        for row in rows:
            for i, cell in enumerate(row):
                body_w[i] = max(body_w[i], self.get_string_width(self._latin1(str(cell)))+pad)
        content_mins = [max(min_widths[i], header_w[i], body_w[i]) for i in range(n)]
        max_col_cap = usable*0.45
        content_mins = [min(w, max_col_cap) for w in content_mins]

        widths = [(usable*w/sum(weights)) for w in weights]
        widths = [max(w, content_mins[i]) for i, w in enumerate(widths)]

        total = sum(widths)
        if total > usable:
            def surplus(ws): return [max(0.0, w - content_mins[i]) for i, w in enumerate(ws)]
            excess = total - usable + 1e-6
            for _ in range(6):
                slacks = surplus(widths); slack_sum = sum(slacks)
                if slack_sum <= 1e-6: break
                for i in range(n):
                    if slacks[i] > 0:
                        cut = excess * (slacks[i]/slack_sum)
                        widths[i] = max(content_mins[i], widths[i] - cut)
                total = sum(widths); excess = total - usable
                if excess <= 1e-6: break
            if sum(widths) > usable:
                scale = usable/sum(widths)
                widths = [w*scale for w in widths]

        header_h = 8
        self.set_font("Helvetica","B",10)
        self.set_fill_color(229,112,0)
        self.set_text_color(255,255,255)
        for i, h in enumerate(headers):
            self.cell(widths[i], header_h, self._fit_text(h, widths[i]), border=1, align="C", fill=True)
        self.cell(0, header_h, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        row_h = 7
        self.set_font("Helvetica","",9)
        self.set_text_color(0,0,0)
        for row in rows:
            if self.get_y()+row_h > self.h - self.b_margin:
                self.add_page()
                self.set_font("Helvetica","B",10); self.set_fill_color(229,112,0); self.set_text_color(255,255,255)
                for i, h in enumerate(headers):
                    self.cell(widths[i], header_h, self._fit_text(h, widths[i]), border=1, align="C", fill=True)
                self.cell(0, header_h, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self.set_font("Helvetica","",9); self.set_text_color(0,0,0)

            for i, cell_txt in enumerate(row):
                raw = str(cell_txt).strip()
                align = "C" if raw == "-" else "L"
                self.cell(widths[i], row_h, self._fit_text(raw, widths[i]), border=1, align=align)
            self.cell(0, row_h, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def network_diagram(self, networks: List[Dict[str, Any]], guests_by_bridge: Dict[str, List[Dict[str, Any]]],
                         title: str = "Network Connectivity Diagram"):
        bonds: Dict[str, Dict[str, Any]] = {}
        bridges: Dict[str, Dict[str, Any]] = {}
        phys_info: Dict[str, Dict[str, Any]] = {}

        def _addr(n) -> str:
            a = n.get("cidr") or ((n.get("address") or "") + (" / " + (n.get("netmask") or "") if n.get("netmask") else ""))
            a = a.strip(" /")
            return a if a else "-"

        for n in networks or []:
            t = (n.get("type") or "").lower()
            name = n.get("iface") or n.get("ifname") or ""
            if not name or name == "lo":
                continue
            if t == "bond":
                slaves = n.get("slaves") or n.get("bond_slaves") or ""
                if isinstance(slaves, list):
                    slaves = " ".join(slaves)
                bonds[name] = {
                    "mode": n.get("bond_mode") or n.get("mode") or "-",
                    "slaves": [s for s in str(slaves).split() if s],
                }
            elif t == "bridge":
                ports = n.get("bridge_ports") or n.get("ports") or ""
                if isinstance(ports, list):
                    ports = " ".join(ports)
                bridges[name] = {
                    "ports": [p for p in str(ports).split() if p],
                    "addr": _addr(n),
                }
            else:
                phys_info[name] = {"addr": _addr(n), "active": bool(n.get("active"))}

        used_phys = set()
        for b in bonds.values():
            used_phys.update(b["slaves"])
        for br in bridges.values():
            for p in br["ports"]:
                if p not in bonds and p not in bridges:
                    used_phys.add(p)
        phys_list   = sorted([p for p in used_phys if p in phys_info])
        bond_list   = sorted(bonds.keys())
        bridge_list = sorted(bridges.keys())

        guests_items: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], Optional[str]]] = []
        for br, lst in (guests_by_bridge or {}).items():
            for g in lst:
                gname = g.get("name") if isinstance(g, dict) else str(g)
                vlan  = g.get("vlan") if isinstance(g, dict) else None
                ips   = g.get("ips") if isinstance(g, dict) else None
                kind  = (g.get("kind") if isinstance(g, dict) else None) or None
                vmid  = (str(g.get("vmid")) if isinstance(g, dict) and g.get("vmid") is not None else None)
                if (not kind or not vmid) and gname:
                    m = re.match(r"^(VM|CT)\s+(\d+)\s*-\s*(.+)$", gname, re.IGNORECASE)
                    if m:
                        kind = m.group(1).upper()
                        vmid = m.group(2)
                        gname = m.group(3)
                ip_s = ", ".join(ips) if isinstance(ips, list) and ips else (ips if isinstance(ips, str) else None)
                guests_items.append((br, gname, vlan, ip_s, kind, vmid))

        if title:
            self.section_title(title)
        start_y = self.get_y() + 6

        avail = self.w - self.l_margin - self.r_margin
        hgap  = max(8.0, min(14.0, avail * 0.04))
        cols  = 4
        box_w = max(40.0, (avail - (cols-1)*hgap) / cols)
        if box_w * cols + (cols-1)*hgap > avail:
            box_w = (avail - (cols-1)*hgap) / cols
        box_h = 16.0
        vgap  = 5.0

        col1_x = self.l_margin
        col2_x = col1_x + box_w + hgap
        col3_x = col2_x + box_w + hgap
        col4_x = col3_x + box_w + hgap

        max_rows = max(len(phys_list), len(bond_list), len(bridge_list), len(guests_items), 1)
        needed_h = 12 + max_rows * (box_h + vgap) + 12
        if start_y + needed_h > self.h - self.b_margin:
            self.add_page()
            start_y = self.get_y() + 2

        self.set_font("Helvetica", "B", 9)
        self.text(col1_x, start_y, self._latin1("Physical NICs"))
        self.text(col2_x, start_y, self._latin1("Bonds"))
        self.text(col3_x, start_y, self._latin1("Bridges"))
        self.text(col4_x, start_y, self._latin1("Guests"))
        y0 = start_y + 4

        shapes: List[Tuple[float,float,float,float,str,Optional[str],Tuple[int,int,int]]] = []
        pos: Dict[str, Tuple[float,float,float,float]] = {}
        guest_pos: Dict[str, Tuple[float,float,float,float]] = {}
        which_col: Dict[str,int] = {}

        def stage_box(x, y, w, h, label_top, label_bottom=None, fill_rgb=(240,240,240)):
            shapes.append((x, y, w, h, label_top, label_bottom, fill_rgb))

        cur_y = y0
        for name in phys_list:
            pos[name] = (col1_x, cur_y, box_w, box_h); which_col[name]=1
            stage_box(col1_x, cur_y, box_w, box_h, name, None, (242,242,242))
            cur_y += box_h + vgap

        cur_y = y0
        for name in bond_list:
            mode = bonds.get(name, {}).get("mode", "-")
            pos[name] = (col2_x, cur_y, box_w, box_h); which_col[name]=2
            stage_box(col2_x, cur_y, box_w, box_h, name, f"mode: {mode}", (236,236,236))
            cur_y += box_h + vgap

        cur_y = y0
        for name in bridge_list:
            addr = bridges.get(name, {}).get("addr") or "-"
            pos[name] = (col3_x, cur_y, box_w, box_h); which_col[name]=3
            stage_box(col3_x, cur_y, box_w, box_h, name, addr if addr != "-" else None, (236,236,236))
            cur_y += box_h + vgap

        cur_y = y0
        for br, gname, vlan, ips, kind, vmid in guests_items:
            key = f"G:{(kind or 'G')}-{(vmid or gname)}"
            id_line = (f"{kind} {vmid}".strip() if kind and vmid else (gname or "-"))
            bottom_lines = []
            if gname:
                bottom_lines.append(str(gname))
            if vlan:
                bottom_lines.append(f"VLAN {vlan}")
            if ips:
                bottom_lines.append(ips)
            bottom = "\n".join(bottom_lines) if bottom_lines else None

            posg = (col4_x, cur_y, box_w, box_h)
            guest_pos[key] = posg; which_col[key]=4
            stage_box(col4_x, cur_y, box_w, box_h, id_line, bottom, (241,241,241))
            cur_y += box_h + vgap

        edges: List[Tuple[str,str,Optional[str]]] = []
        for brname, brinfo in bridges.items():
            for p in brinfo.get("ports", []):
                if p in bond_list:
                    g = f"bond:{p}"
                    edges.append((p, brname, g))  
                    for s in bonds.get(p, {}).get("slaves", []):
                        if s in phys_info:
                            edges.append((s, p, g))  
                else:
                    if p in phys_info:
                        edges.append((p, brname, f"nic:{p}"))  

        upstream_groups_by_bridge: Dict[str,set] = {}
        for (src,dst,g) in edges:
            if dst in bridge_list:
                upstream_groups_by_bridge.setdefault(dst, set()).add(g)
        for br, gname, _vlan, _ips, kind, vmid in guests_items:
            key = f"G:{(kind or 'G')}-{(vmid or gname)}"
            gset = upstream_groups_by_bridge.get(br, set())
            g = list(gset)[0] if len(gset)==1 else None
            edges.append((br, key, g))

        palette = [
            (0,102,204), (229,112,0), (0,140,70),
            (163,73,164), (128,128,0), (200,0,0),
        ]
        group_color: Dict[str,Tuple[int,int,int]] = {}
        def color_for(group: Optional[str]) -> Tuple[int,int,int]:
            if group is None:
                return (100,100,100)
            if group not in group_color:
                group_color[group] = palette[len(group_color) % len(palette)]
            return group_color[group]

        def mid_right(x,y,w,h): return (x+w, y+h/2)
        def mid_left(x,y,w,h):  return (x,   y+h/2)

        bonds_top = y0
        bonds_bottom = y0 + (max(len(bond_list),1) * (box_h + 5.0)) - 5.0 + box_h

        def elbow_routed(src_name: str, dst_name: str, rgb: Tuple[int,int,int]):
            src_rect = pos.get(src_name) or guest_pos.get(src_name)
            dst_rect = pos.get(dst_name) or guest_pos.get(dst_name)
            if not src_rect or not dst_rect:
                return
            sx, sy, sw, sh = src_rect
            dx, dy, dw, dh = dst_rect
            s_col = which_col.get(src_name, 0)
            d_col = which_col.get(dst_name, 0)

            self.set_draw_color(*rgb)
            self.set_line_width(1.4)

            (sxr, syr) = mid_right(sx, sy, sw, sh)
            (dxl, dyl) = mid_left(dx, dy, dw, dh)

            elbow_x = ((sx + sw) + dx) / 2.0

            if s_col == 1 and d_col == 3:
                gutter_left  = (sx + sw) + 2.0
                gutter_right = dx - 2.0
                top_corridor    = max(self.t_margin + 4.0, bonds_top - 4.0)
                bottom_corridor = min(self.h - self.b_margin - 4.0, bonds_bottom + 4.0)
                corridor_y = top_corridor if abs(syr - top_corridor) <= abs(syr - bottom_corridor) else bottom_corridor
                self.line(sxr, syr, gutter_left, syr)
                self.line(gutter_left, syr, gutter_left, corridor_y)
                self.line(gutter_left, corridor_y, gutter_right, corridor_y)
                self.line(gutter_right, corridor_y, gutter_right, dyl)
                self.line(gutter_right, dyl, dxl, dyl)
                return

            self.line(sxr, syr, elbow_x, syr)
            self.line(elbow_x, syr, elbow_x, dyl)
            self.line(elbow_x, dyl, dxl, dyl)

        for (src, dst, g) in edges:
            elbow_routed(src, dst, color_for(g))

        def draw_box(x, y, w, h, label_top, label_bottom=None, fill_rgb=(240,240,240)):
            self.set_fill_color(*fill_rgb)
            self.set_draw_color(120,120,120)
            self.set_line_width(0.2)
            self.rect(x, y, w, h, style="DF")
            self.set_font("Helvetica","B",8)
            self.set_xy(x+1.5, y+1.4)
            self.cell(w-3, 3.5, self._fit_text(label_top, w-3), align="L")
            if label_bottom:
                self.set_font("Helvetica","",7)
                lines = str(label_bottom).splitlines()
                max_lines = 3
                lh = 3.0
                yy = y + 4.7
                for i, line in enumerate(lines[:max_lines]):
                    self.set_xy(x+1.5, yy + i*lh)
                    self.cell(w-3, lh, self._fit_text(line, w-3), align="L")

        for (x, y, w, h, lt, lb, rgb) in shapes:
            draw_box(x, y, w, h, lt, lb, rgb)

        self.set_y(max(self.get_y(), y0 + max_rows*(box_h+5.0)) + 6)
        self.set_draw_color(0,0,0); self.set_line_width(0.2)

def summarize_cluster_status(cluster_status: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = {"nodes": 0, "quorum": "-", "cluster_name": None}
    for item in cluster_status:
        t = item.get("type")
        if t == "node":
            out["nodes"] += 1
        elif t == "cluster":
            out["cluster_name"] = item.get("name")
            q = item.get("quorate")
            if q is not None:
                out["quorum"] = "Yes" if (q in (1, True, "1")) else "No"
        elif t == "quorum":
            q = item.get("quorate")
            if q is not None:
                out["quorum"] = "Yes" if (q in (1, True, "1")) else "No"
    return out

def summarize_vms(resources: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    by_node: Dict[str, Dict[str, int]] = {}
    for r in resources:
        node = r.get("node")
        if not node:
            continue
        by_node.setdefault(node, {"qemu": 0, "lxc": 0, "running": 0})
        if r.get("type") == "qemu":
            by_node[node]["qemu"] += 1
        elif r.get("type") == "lxc":
            by_node[node]["lxc"] += 1
        if r.get("status") == "running":
            by_node[node]["running"] += 1
    return by_node

def split_vm_and_lxc(resources: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    vms, lxc = [], []
    for r in resources or []:
        if r.get("type") == "qemu":
            vms.append(r)
        elif r.get("type") == "lxc":
            lxc.append(r)
    return vms, lxc

def pair_gib(used: int, total: int) -> str:
    return f"{format_gib(used)}/{format_gib(total)} ({pct(used, total):.1f}%)"

def _fmt_vcpu(v) -> str:
    if v is None:
        return "-"
    try:
        v = float(v)
        if v <= 0:
            return "unlimited"
        return f"{int(v) if abs(v-int(v))<1e-6 else v:g} vCPU"
    except Exception:
        return str(v)

def build_vm_like_list_rows(items: List[Dict[str, Any]]) -> List[List[str]]:
    rows = []
    for r in items:
        vmid = r.get("vmid", "-")
        kind = r.get("type")
        name = r.get("name") or f"{'VM' if kind=='qemu' else 'CT'} {vmid}"
        vcpus = r.get("maxcpu")
        if vcpus is None:
            vcpus = r.get("cpus") or r.get("maxcpus") or r.get("cpulimit")
        mem_total = r.get("maxmem") or 0
        disk_total = r.get("maxdisk") or 0
        rows.append([str(vmid), name, _fmt_vcpu(vcpus), format_gib(mem_total), format_gib(disk_total)])
    return rows

def build_vm_like_util_rows(items: List[Dict[str, Any]], ip_map: Dict[Tuple[str,str,int], str]) -> List[List[str]]:
    rows = []
    for r in items:
        kind = r.get("type")
        vmid = r.get("vmid", "-")
        name = r.get("name") or f"{'VM' if kind=='qemu' else 'CT'} {vmid}"
        node = r.get("node", "-")
        cpu_pct = (r.get("cpu") or 0.0) * 100.0
        mem_used, mem_max = r.get("mem") or 0, r.get("maxmem") or 0
        disk_used, disk_max = r.get("disk") or 0, r.get("maxdisk") or 0
        mem_pct  = pct(mem_used, mem_max)
        disk_pct = pct(disk_used, disk_max)
        ip_text = ip_map.get((kind, node, int(vmid) if vmid != "-" else -1), "-")
        uptime = r.get("uptime") or 0
        rows.append([str(vmid), name, f"{cpu_pct:.1f}%", f"{mem_pct:.1f}%", f"{disk_pct:.1f}%", ip_text, secs_to_hms(uptime)])
    return rows

def pick_node_ips(networks: List[Dict[str, Any]]) -> str:
    ipv4s = []; preferred = []
    for n in networks:
        ifname = n.get("iface") or n.get("ifname") or ""
        active = bool(n.get("active"))
        cidr = n.get("cidr"); addr = n.get("address")
        ip = cidr.split("/")[0] if (cidr and "/" in cidr) else addr
        if ip and ":" not in ip:
            (preferred if active and (ifname == "vmbr0" or n.get("gateway")) else ipv4s).append(ip)
    all_ips = preferred + ipv4s
    seen = set(); uniq = []
    for ip in all_ips:
        if ip not in seen:
            uniq.append(ip); seen.add(ip)
    return ", ".join(uniq) if uniq else "-"

def shape_bridges(networks: List[Dict[str, Any]]) -> List[List[str]]:
    rows = []
    for n in networks:
        if (n.get("type") or "").lower() != "bridge":
            continue
        ports = n.get("bridge_ports") or n.get("ports") or "-"
        vlan_aware = n.get("bridge_vlan_aware")
        addr = n.get("cidr") or join_nonempty([n.get("address"), n.get("netmask")], " / ")
        rows.append([
            n.get("iface") or n.get("ifname") or "-",
            ports if isinstance(ports, str) else " ".join(ports) if ports else "-",
            addr or "-",
            (n.get("method") or "-"),
            "Yes" if n.get("active") else "No",
            "Yes" if n.get("autostart") else "No",
            "Yes" if vlan_aware else "No",
        ])
    return rows

def shape_bonds(networks: List[Dict[str, Any]], ext_speed_map: Optional[Dict[str,float]] = None) -> List[List[str]]:
    speed_map = _extract_iface_speed_map_from_networks(networks)
    if ext_speed_map:
        speed_map.update(ext_speed_map)
    rows = []
    bond_objs: Dict[str, Dict[str, Any]] = {}
    for n in networks:
        if (n.get("type") or "").lower() != "bond":
            continue
        name = n.get("iface") or n.get("ifname") or "-"
        slaves = n.get("slaves") or n.get("bond_slaves") or "-"
        if isinstance(slaves, list):
            s_list = slaves
            slaves_s = " ".join(slaves)
        else:
            s_list = str(slaves).split()
            slaves_s = slaves if isinstance(slaves, str) else "-"
        bond_objs[name] = {"slaves": s_list}
        mode = n.get("bond_mode") or n.get("mode") or "-"
        addr = n.get("cidr") or join_nonempty([n.get("address"), n.get("netmask")], " / ")
        speed_txt = _bond_speed_text(bond_objs[name], speed_map) if name != "-" else "-"
        rows.append([
            name,
            slaves_s or "-",
            mode,
            addr or "-",
            (n.get("method") or "-"),
            "Yes" if n.get("active") else "No",
            speed_txt,
        ])
    return rows

def _resolve_lane_speed(name: str, net_map: Dict[str, float], networks: List[Dict[str, Any]]) -> Optional[float]:
    _memo: Dict[str, Optional[float]] = {}

    types: Dict[str, str] = {}
    bonds: Dict[str, List[str]] = {}
    bridges: Dict[str, List[str]] = {}
    for n in networks or []:
        t = (n.get("type") or "").lower()
        nm = n.get("iface") or n.get("ifname") or ""
        if not nm:
            continue
        types[nm] = t
        if t == "bond":
            slaves = n.get("slaves") or n.get("bond_slaves") or []
            if not isinstance(slaves, list):
                slaves = str(slaves).split()
            bonds[nm] = [s for s in slaves if s]
        elif t == "bridge":
            ports = n.get("bridge_ports") or n.get("ports") or []
            if not isinstance(ports, list):
                ports = str(ports).split()
            bridges[nm] = [p for p in ports if p]

    def _go(ifname: str) -> Optional[float]:
        if ifname in _memo:
            return _memo[ifname]

        t = types.get(ifname)

        if (t == "vlan" or "." in ifname) and "." in ifname:
            base = ifname.split(".", 1)[0]
            _memo[ifname] = _go(base)
            return _memo[ifname]

        if t == "bridge":
            cands = []
            for pif in bridges.get(ifname, []):
                sp = _go(pif)
                if sp:
                    cands.append(sp)
            _memo[ifname] = max(cands) if cands else None
            return _memo[ifname]

        if t == "bond":
            spds = []
            for s in bonds.get(ifname, []):
                sp = _go(s)
                if sp:
                    spds.append(sp)
            if spds:
                lane = min(spds)
            else:
                lane = None
            _memo[ifname] = lane
            return lane

        sp = net_map.get(ifname)
        _memo[ifname] = sp if (sp and sp > 0) else None
        return _memo[ifname]

    return _go(name)

def _resolve_vlan_speed(vlan_name: str, net_map: Dict[str,float], networks: List[Dict[str,Any]]) -> Optional[float]:
    if "." not in vlan_name:
        return _resolve_lane_speed(vlan_name, net_map, networks)

    base = vlan_name.split(".", 1)[0]

    types: Dict[str, str] = {}
    bonds: Dict[str, List[str]] = {}
    bridges: Dict[str, List[str]] = {}
    for n in networks or []:
        t = (n.get("type") or "").lower()
        nm = n.get("iface") or n.get("ifname") or ""
        if not nm:
            continue
        types[nm] = t
        if t == "bond":
            slaves = n.get("slaves") or n.get("bond_slaves") or []
            if not isinstance(slaves, list):
                slaves = str(slaves).split()
            bonds[nm] = [s for s in slaves if s]
        elif t == "bridge":
            ports = n.get("bridge_ports") or n.get("ports") or []
            if not isinstance(ports, list):
                ports = str(ports).split()
            bridges[nm] = [p for p in ports if p]

    if types.get(base) != "bridge":
        return _resolve_lane_speed(base, net_map, networks)

    br_ports = bridges.get(base, [])
    bond_ports = [p for p in br_ports if types.get(p) == "bond" or p.startswith("bond")]
    chosen = None
    if "bond0" in bond_ports:
        chosen = "bond0"
    elif bond_ports:
        chosen = bond_ports[0]

    if chosen:
        return _resolve_lane_speed(chosen, net_map, networks)

    return _resolve_lane_speed(base, net_map, networks)

def _bond_aggregate_speed(bond_name: str, net_map: Dict[str,float], networks: List[Dict[str,Any]]) -> Optional[float]:
    bonds: Dict[str, List[str]] = {}
    for n in networks or []:
        if (n.get("type") or "").lower() == "bond":
            nm = n.get("iface") or n.get("ifname") or ""
            slaves = n.get("slaves") or n.get("bond_slaves") or []
            if not isinstance(slaves, list):
                slaves = str(slaves).split()
            bonds[nm] = [s for s in slaves if s]
    slaves = bonds.get(bond_name, [])
    if not slaves:
        return None
    spds = [net_map.get(s) for s in slaves if net_map.get(s)]
    if not spds:
        return None
    return float(sum(spds))

def _resolve_vlan_speed(vlan_name: str, net_map: Dict[str,float], networks: List[Dict[str,Any]]) -> Optional[float]:
    if "." not in vlan_name:
        return _resolve_lane_speed(vlan_name, net_map, networks)

    base = vlan_name.split(".", 1)[0]

    types: Dict[str, str] = {}
    bridges: Dict[str, List[str]] = {}
    for n in networks or []:
        t = (n.get("type") or "").lower()
        nm = n.get("iface") or n.get("ifname") or ""
        if not nm:
            continue
        types[nm] = t
        if t == "bridge":
            ports = n.get("bridge_ports") or n.get("ports") or []
            if not isinstance(ports, list):
                ports = str(ports).split()
            bridges[nm] = [p for p in ports if p]

    if types.get(base) != "bridge":
        return _resolve_lane_speed(base, net_map, networks)

    br_ports = bridges.get(base, [])
    bond_ports = [p for p in br_ports if types.get(p) == "bond" or p.startswith("bond")]
    chosen = None
    if "bond0" in bond_ports:
        chosen = "bond0"
    elif bond_ports:
        chosen = bond_ports[0]

    if chosen:
        agg = _bond_aggregate_speed(chosen, net_map, networks)
        if agg:
            return agg
        return _resolve_lane_speed(chosen, net_map, networks)

    return _resolve_lane_speed(base, net_map, networks)

def shape_standard_ifaces(networks: List[Dict[str, Any]], ext_speed_map: Optional[Dict[str,float]] = None) -> List[List[str]]:
    net_map = _extract_iface_speed_map_from_networks(networks)
    if ext_speed_map:
        net_map.update(ext_speed_map)

    rows = []
    for n in networks:
        t = (n.get("type") or "").lower()
        if t in ("bridge", "bond"):
            continue
        name = n.get("iface") or n.get("ifname") or "-"
        if name == "lo":
            continue
        addr = n.get("cidr") or join_nonempty([n.get("address"), n.get("netmask")], " / ")

        if t == "vlan" and "." in name:
            spd_val = _resolve_vlan_speed(name, net_map, networks)
        else:
            spd_val = net_map.get(name)
            if not spd_val or spd_val <= 0:
                spd_val = _resolve_lane_speed(name, net_map, networks)

        spd_txt = _mbps_to_text(spd_val)
        rows.append([
            name,
            t or "interface",
            addr or "-",
            (n.get("gateway") or "-"),
            (n.get("method") or "-"),
            spd_txt,
            "Yes" if n.get("active") else "No",
            "Yes" if n.get("autostart") else "No",
        ])
    return rows

def get_qemu_ips_via_agent(api: ProxmoxAPI, node: str, vmid: int) -> List[str]:
    try:
        data = api.qemu_agent_interfaces(node, vmid)
        lst = data.get("result") if isinstance(data, dict) else data
        ips: List[str] = []
        for iface in lst or []:
            for addr in iface.get("ip-addresses", []) or []:
                ip = addr.get("ip-address")
                if ip and ip.count(".") == 3 and not ip.startswith("169.254.") and ip != "127.0.0.1":
                    ips.append(ip)
        return list(dict.fromkeys(ips))
    except Exception:
        return []

def get_qemu_ips_from_cfg(cfg: Dict[str, Any]) -> List[str]:
    ips: List[str] = []
    for k, v in (cfg or {}).items():
        if str(k).startswith("ipconfig"):
            for m in re.finditer(r"(?:^|,)\s*ip=([^,]+)", str(v)):
                token = m.group(1).strip()
                if token.lower() in ("dhcp", "manual", "auto"):
                    continue
                ip = token.split("/")[0].strip()
                if ip.count(".") == 3 and not ip.startswith("169.254.") and ip != "127.0.0.1":
                    ips.append(ip)
    return list(dict.fromkeys(ips))

def get_lxc_ips_from_cfg(cfg: Dict[str, Any]) -> List[str]:
    ips: List[str] = []
    for k, v in (cfg or {}).items():
        if str(k).startswith("net"):
            for m in re.finditer(r"(?:^|,)\s*ip=([^,]+)", str(v)):
                token = m.group(1).strip()
                if token.lower() in ("dhcp", "manual", "auto"):
                    continue
                ip = token.split("/")[0].strip()
                if ip.count(".") == 3 and not ip.startswith("169.254.") and ip != "127.0.0.1":
                    ips.append(ip)
    return list(dict.fromkeys(ips))

class PrettyArgumentParser(argparse.ArgumentParser):
    def format_usage(self):
        return super().format_usage().replace("usage:", "Usage:", 1)

    def format_help(self):
        text = super().format_help()
        text = text.replace("usage:", "Usage:", 1)
        text = text.replace("options:", "Options:", 1)
        return text

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "Error! Arguments are required.\n")

def main():
    p = PrettyArgumentParser(description="Generate a Proxmox Cluster & Nodes summary PDF.", add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40, width=110))
    p.add_argument("-h", "--help",action="help",help="Show this help message and exit")
    p.add_argument("--host", required=True, help="Add your Proxmox VE domain or IP address")
    p.add_argument("--outfile", default=None, help="Define your output PDF file name (e.g., report.pdf)")
    p.add_argument("--debug", action="store_true", help="Enable debug logging to troubleshoot PDF generation")
    p.add_argument("--insecure", action="store_true", help="Disable TLS/SSL verification (not recommended)")
    p.add_argument("--no-insecure", dest="no_insecure", action="store_true", help="Force TLS/SSL verification")
    p.add_argument("--username", help="Proxmox VE username (e.g., root@pam)")
    p.add_argument("--password", help="Proxmox VE user password")
    p.add_argument("--otp", help="Two-factor authentication code if required")
    p.add_argument("--token-user", help="API Token user (e.g., root@pam)")
    p.add_argument("--token-id", help="API Token ID")
    p.add_argument("--token-secret", help="API Token secret")
    p.add_argument("--logo", required=True, help="Path to a PNG/JPG logo to place in the PDF header")
    p.add_argument("--generateusername", help="Name to display as 'Generated by' in the PDF footer")
    p.add_argument("--ssh-user", help="SSH username for nodes (for NIC speeds / IP ARP fallback)")
    p.add_argument("--ssh-password", help="SSH password")
    p.add_argument("--ssh-key", help="SSH private key path")
    p.add_argument("--ssh-port", type=int, default=22, help="SSH port (Default: 22)")
    p.add_argument("--ssh-timeout", type=int, default=8, help="SSH connection timeout in seconds (Default: 8)")

    args = p.parse_args()

    verify = VERIFY_SSL_DEFAULT
    if args.no_insecure:
        verify = True
    elif args.insecure:
        verify = False

    try:
        api = ProxmoxAPI(
            host=args.host,
            verify_ssl=verify,
            username=args.username,
            password=args.password,
            otp=args.otp,
            token_user=args.token_user,
            token_id=args.token_id,
            token_secret=args.token_secret,
            debug=args.debug,
        )
        api.login()
    except Exception as e:
        print(f"[ERROR] Login failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        cl_status = api.cluster_status()
        nodes = api.nodes()
        vm_res = api.cluster_vm_resources()
        storage_res = api.cluster_storage_resources()
        ver = api.version()
    except Exception as e:
        print(f"[ERROR] Data fetch failed: {e}", file=sys.stderr)
        sys.exit(1)

    cluster_sum = summarize_cluster_status(cl_status)
    vms_by_node = summarize_vms(vm_res)

    node_rows_summary = []
    node_rows_details = []
    per_node_networks: Dict[str, List[Dict[str, Any]]] = {}
    node_to_hostname: Dict[str, str] = {}
    node_to_first_ip: Dict[str, Optional[str]] = {}

    for n in nodes:
        node = n.get("node") or n.get("name")
        status = n.get("status", "unknown")
        try:
            ns = api.node_status(node)
            cpu_usage_pct = (safe_get(ns, "cpu", default=0.0) or 0.0) * 100.0
            mem_total = safe_get(ns, "memory", "total", default=0) or 0
            mem_used  = safe_get(ns, "memory", "used",  default=0) or 0
            root_total = safe_get(ns, "rootfs", "total", default=0) or 0
            root_used  = safe_get(ns, "rootfs", "used",  default=0) or 0
            uptime = safe_get(ns, "uptime", default=0) or 0
            hostname = ns.get("hostname") or node
            cpuinfo = safe_get(ns, "cpuinfo", default={}) or {}
            cpus = cpuinfo.get("cpus")
            if not cpus:
                sockets = cpuinfo.get("sockets") or 0
                cores   = cpuinfo.get("cores") or 0
                threads = cpuinfo.get("threads") or 1
                prod = sockets * cores * threads
                cpus = prod if prod > 0 else "-"
        except Exception:
            cpu_usage_pct = 0.0; mem_total = mem_used = root_total = root_used = uptime = 0
            hostname = node; cpus = "-"

        node_to_hostname[node] = hostname

        try:
            net = api.node_network(node)
        except Exception:
            net = []

        ips_text = pick_node_ips(net)
        first_ip = ips_text.split(",")[0].strip() if ips_text and ips_text != "-" else None
        node_to_first_ip[node] = first_ip

        node_rows_summary.append([
            node, status, str(cpus), f"{cpu_usage_pct:.1f}%",
            f"{format_gib(mem_used)}/{format_gib(mem_total)} ({pct(mem_used, mem_total):.1f}%)",
            f"{format_gib(root_used)}/{format_gib(root_total)} ({pct(root_used, root_total):.1f}%)",
            secs_to_hms(uptime),
        ])

        node_rows_details.append([node, hostname, ips_text])
        per_node_networks[node] = net

    vm_list, lxc_list = split_vm_and_lxc(vm_res)

    guests_by_bridge_per_node: Dict[str, Dict[str, List[Dict[str, Any]]]] = {n.get("node"): {} for n in nodes}
    ip_map: Dict[Tuple[str,str,int], str] = {}

    for r in vm_list:
        if r.get("type") != "qemu": continue
        node = r.get("node"); vmid = int(r.get("vmid")); name = r.get("name") or f"VM {vmid}"
        ips_found: List[str] = []
        bridges_info: List[Tuple[str, Optional[str]]] = []
        macs: List[str] = []
        try:
            cfg = api.qemu_config(node, vmid)
            ips_found = (get_qemu_ips_via_agent(api, node, vmid) or get_qemu_ips_from_cfg(cfg))
            for k, v in cfg.items():
                if str(k).startswith("net"):
                    brs  = parse_bridge_from_netconf(str(v))
                    vlan = parse_vlan_tag_from_netconf(str(v))
                    macs.extend(extract_macs_from_netconf(str(v)))
                    for br in brs:
                        bridges_info.append((br, vlan))
        except Exception:
            pass

        if not ips_found and macs and node_to_first_ip.get(node) and args.ssh_user and (args.ssh_key or args.ssh_password):
            ip_by_mac = ssh_lookup_ips_by_macs(node_to_first_ip[node], args.ssh_user, args.ssh_password, args.ssh_key, macs, port=args.ssh_port, timeout=args.ssh_timeout)
            for m in macs:
                ips_found.extend(ip_by_mac.get(m.lower(), []))
            ips_found = list(dict.fromkeys(ips_found))

        ip_map[("qemu", node, vmid)] = ", ".join(ips_found) if ips_found else "-"

        for br, vlan in bridges_info or []:
            guests_by_bridge_per_node.setdefault(node, {}).setdefault(br, []).append(
                {"name": f"{name}", "ips": ips_found, "vlan": vlan, "kind": "VM", "vmid": vmid}
            )

    for r in lxc_list:
        if r.get("type") != "lxc": continue
        node = r.get("node"); vmid = int(r.get("vmid")); name = r.get("name") or f"CT {vmid}"
        ips_found: List[str] = []
        bridges_info: List[Tuple[str, Optional[str]]] = []
        macs: List[str] = []
        try:
            cfg = api.lxc_config(node, vmid)
            ips_found = get_lxc_ips_from_cfg(cfg)
            for k, v in cfg.items():
                if str(k).startswith("net"):
                    brs  = parse_bridge_from_netconf(str(v))
                    vlan = parse_vlan_tag_from_netconf(str(v))
                    macs.extend(extract_macs_from_netconf(str(v)))
                    for br in brs:
                        bridges_info.append((br, vlan))
        except Exception:
            pass

        if not ips_found and macs and node_to_first_ip.get(node) and args.ssh_user and (args.ssh_key or args.ssh_password):
            ip_by_mac = ssh_lookup_ips_by_macs(node_to_first_ip[node], args.ssh_user, args.ssh_password, args.ssh_key, macs, port=args.ssh_port, timeout=args.ssh_timeout)
            for m in macs:
                ips_found.extend(ip_by_mac.get(m.lower(), []))
            ips_found = list(dict.fromkeys(ips_found))

        ip_map[("lxc", node, vmid)] = ", ".join(ips_found) if ips_found else "-"

        for br, vlan in bridges_info or []:
            guests_by_bridge_per_node.setdefault(node, {}).setdefault(br, []).append(
                {"name": f"{name}", "ips": ips_found, "vlan": vlan, "kind": "CT", "vmid": vmid}
            )

    def build_storage_tables(storage_res: List[Dict[str, Any]]):
        shared_map: Dict[str, Dict[str, Any]] = {}; local_rows: List[List[str]] = []
        for r in storage_res:
            storage = r.get("storage") or "-"; node = r.get("node") or "-"
            total = r.get("maxdisk") or r.get("total") or 0
            used  = r.get("disk")    or r.get("used")  or 0
            active = r.get("active"); shared = bool(r.get("shared"))
            used_s = pair_gib(used, total)
            if shared:
                entry = shared_map.setdefault(storage, {"total": 0, "used": 0, "nodes": set()})
                entry["total"] = max(entry["total"], total); entry["used"] = max(entry["used"], used)
                if active: entry["nodes"].add(node)
            else:
                local_rows.append([node, storage, used_s, "Yes" if active else "No"])
        shared_rows = []
        for name, info in sorted(shared_map.items(), key=lambda kv: kv[0].lower()):
            shared_rows.append([name, pair_gib(info["used"], info["total"]),
                                ", ".join(sorted(info["nodes"])) if info["nodes"] else "-"])
        local_rows.sort(key=lambda x: (x[0].lower(), x[1].lower()))
        return shared_rows, local_rows

    shared_rows, local_rows = build_storage_tables(storage_res)

    ssh_speed_map_per_node: Dict[str, Dict[str, float]] = {}
    if args.ssh_user and (args.ssh_key or args.ssh_password):
        for node, nets in per_node_networks.items():
            target = node_to_first_ip.get(node) or node_to_hostname.get(node) or node
            if not target or target == "-":
                continue
            speeds = collect_iface_speeds_via_ssh(
                target,
                user=args.ssh_user,
                password=args.ssh_password,
                keyfile=args.ssh_key,
                port=args.ssh_port,
                timeout=args.ssh_timeout,
            )
            ssh_speed_map_per_node[node] = speeds

    pdf = ReportPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.alias_nb_pages()
    pdf.set_logo(load_logo_bytes(args.logo))
    pdf.set_generated_by(args.generateusername)
    pdf.add_page()

    pv_short = safe_get(ver, "version") or safe_get(ver, "release") or "-"
    if safe_get(ver, "version") and safe_get(ver, "release"):
        pv_short = f"{ver.get('version')}-{ver.get('release')}"

    pdf.section_title("Cluster Overview")
    cluster_rows = [
        ("Cluster Name", cluster_sum.get("cluster_name") or "-"),
        ("Proxmox Version", pv_short),
        ("Quorum", cluster_sum.get("quorum") if cluster_sum.get("quorum") is not None else "-"),
        ("Total Nodes", str(cluster_sum.get("nodes") or 0)),
        ("Report Time", dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("API Host", args.host),
        ("TLS Verify", "Enabled" if api.session.verify else "Disabled (insecure)"),
        ("Auth Mode", "API Token" if api.use_token else "Password"),
    ]
    pdf.key_values(cluster_rows)

    pdf.ln(2); pdf.section_title("Nodes")
    node_headers = ["Node", "Status", "CPUs", "CPU Usage", "Memory Used/Max", "Disk Used/Max", "Uptime"]
    pdf.table(node_headers, node_rows_summary, weights=[1.1,1.0,0.8,0.9,2.4,2.4,0.9])

    pdf.ln(2); pdf.section_title("Nodes Details (Hostname & IPs)")
    pdf.table(["Node", "Hostname", "IPs (IPv4)"], node_rows_details, weights=[1.2,2.0,3.2])

    pdf.ln(2); pdf.section_title("VM & Container Summary (By Node)")
    sum_rows = [[n, str(v.get("qemu",0)), str(v.get("lxc",0)), str(v.get("running",0))] for n, v in sorted(vms_by_node.items())] or [["-","0","0","0"]]
    pdf.table(["Node","QEMU VMs","LXC","Running"], sum_rows, weights=[2,1,1,1])

    vm_list_all, lxc_list_all = vm_list, lxc_list
    if vm_list_all:
        pdf.ln(2); pdf.section_title("Virtual Machines (QEMU) Lists")
        pdf.table(["VMID", "Name", "vCPU", "Memory", "Storage"],
                  [[str(r.get("vmid","-")),
                    (r.get("name") or f"VM {r.get('vmid')}"),
                    _fmt_vcpu(r.get("maxcpu") or r.get("cpus") or r.get("maxcpus") or r.get("cpulimit")),
                    format_gib(r.get("maxmem") or 0),
                    format_gib(r.get("maxdisk") or 0)] for r in vm_list_all],
                  weights=[0.9,2.2,1.0,1.0,1.0])

        pdf.ln(1); pdf.section_title("Virtual Machines (QEMU) Utilization")
        headers_u = ["VMID","Name","CPU Usage","Memory Usage","Storage Usage","IP","Uptime"]
        vm_util_rows = build_vm_like_util_rows(vm_list_all, ip_map)
        pdf.table(headers_u, vm_util_rows, weights=[0.9,2.2,1.1,1.2,1.2,1.6,1.1])

    if lxc_list_all:
        pdf.ln(2); pdf.section_title("Containers (LXC) Lists")
        pdf.table(["CTID", "Name", "vCPU", "Memory", "Storage"],
                  [[str(r.get("vmid","-")),
                    (r.get("name") or f"CT {r.get('vmid')}"),
                    _fmt_vcpu(r.get("maxcpu") or r.get("cpus") or r.get("maxcpus") or r.get("cpulimit")),
                    format_gib(r.get("maxmem") or 0),
                    format_gib(r.get("maxdisk") or 0)] for r in lxc_list_all],
                  weights=[0.9,2.2,1.0,1.0,1.0])

        pdf.ln(1); pdf.section_title("Containers (LXC) Utilization")
        headers_u = ["CTID","Name","CPU Usage","Memory Usage","Storage Usage","IP","Uptime"]
        lxc_util_rows = build_vm_like_util_rows(lxc_list_all, ip_map)
        pdf.table(headers_u, lxc_util_rows, weights=[0.9,2.2,1.1,1.2,1.2,1.6,1.1])

    pdf.ln(2); pdf.section_title("Shared Storage")
    if shared_rows:
        pdf.table(["Storage","Used/Total","Active On Nodes"], shared_rows, weights=[1.6,2.6,3.0])
    else:
        pdf.key_values([("Shared Storage","None detected")])

    pdf.ln(2); pdf.section_title("Local Storage (Per Node)")
    if local_rows:
        pdf.table(["Node","Storage","Used/Total","Active"], local_rows, weights=[1.2,1.6,2.8,0.8])
    else:
        pdf.key_values([("Local Storage","None detected")])

    for node in sorted(per_node_networks.keys()):
        networks = per_node_networks[node]
        hostname = node_to_hostname.get(node, node)
        ext_speeds = ssh_speed_map_per_node.get(node, {})

        pdf.add_page()
        pdf.section_title(f"Network Overview ({hostname})")

        pdf.section_title("Bridges")
        bridges_rows = shape_bridges(networks)
        if bridges_rows:
            pdf.table(["Name","Ports","Address","Method","Active","Autostart","VLAN Aware"],
                      bridges_rows, weights=[1.2,2.0,2.2,1.0,0.8,1.0,1.4])
        else:
            pdf.key_values([("Bridges","None")])

        pdf.ln(1); pdf.section_title("Bonds")
        bonds_rows = shape_bonds(networks, ext_speed_map=ext_speeds)
        if bonds_rows:
            pdf.table(["Name","Slaves","Mode","Address","Method","Active","Speed"],
                      bonds_rows, weights=[1.2,2.0,1.2,2.0,1.0,0.8,1.2])
        else:
            pdf.key_values([("Bonds","None")])

        pdf.ln(1); pdf.section_title("Standard Interfaces")
        ifaces_rows = shape_standard_ifaces(networks, ext_speed_map=ext_speeds)
        if ifaces_rows:
            pdf.table(["Name","Type","Address","Gateway","Method","Speed","Active","Autostart"],
                      ifaces_rows, weights=[1.2,1.1,2.1,1.4,0.9,1.0,0.8,0.9])
        else:
            pdf.key_values([("Interfaces","None")])

        pdf.ln(2)
        pdf.network_diagram(
            networks,
            guests_by_bridge_per_node.get(node, {}),
            title=f"Network Connectivity Diagram ({hostname})"
        )

    if not args.outfile:
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.outfile = f"Proxmox_Summary_{args.host}_{ts}.pdf"

    try:
        pdf.output(args.outfile)
    except Exception as e:
        print(f"[ERROR] Failed to write PDF: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[OK] Report saved to: {args.outfile}")

if __name__ == "__main__":
    main()
