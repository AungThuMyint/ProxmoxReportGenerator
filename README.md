# Proxmox Report Generator

Generate a clean, printable PDF that summarizes your **Proxmox VE** cluster and each node, Cluster health, nodes & resources, VM/LXC lists + utilization, storage, and detailed network tables (Bridges, Bonds, Standard Interfaces). With optional SSH, the script discovers NIC/Bond link speeds.

---

## Highlights

- **One‑Click PDF**: Overview Proxmox VE Cluster
- **Cluster Overview**: Status, Quorum, Proxmox VE Versions
- **Nodes**: CPU/Memory/Disk Usage & Uptime
- **VMs (QEMU) / Containers (LXC)**
  - Per‑Node Lists (Name, CPU, Memory, Storage, IP, Uptime)
  - Utilization Tables
- **Storage**: Shared & Per‑Node Local
- **Network (Per Node)**
  - Bridges (Ports, Address)
  - Bonds (Mode, Slaves)
  - Standard Interfaces
  - Network Speed
> With SSH enabled the report shows accurate physical NIC speeds. Without SSH it falls back to API-visible values.

---

## Requirements

- Python **3.8+**
- Packages:
  - `requests`
  - `urllib3`
  - `fpdf2`
  - `paramiko`

Install Dependencies:

```bash
pip install requests urllib3 fpdf2 paramiko
```

---

## Usage

```bash
python ProxmoxReportGenerator.py --host <pve-host> --logo <logo.png> [auth flags] [ssh flags] [other flags]
```

### Required
- `--host` – Proxmox API Host or IP
- `--logo` – Location Of PNG/JPG

### Authentication (Choose **One**)

**Username/Password (Optionally With OTP)**
```bash
--username root@pam --password <pass> [--otp <code>]
```

**API Token**
```bash
--token-user <user@realm> --token-id <id> --token-secret <secret>
```

### SSH (Optional But Recommended For Link Speeds)
```bash
--ssh-user <user> [--ssh-password <pass> | --ssh-key <path>] [--ssh-port 22] [--ssh-timeout 8]
```
> Used to read NIC speeds (via `ethtool`/`/sys`) and improve ARP/IP lookups. If SSH fails, the script falls back to API values.

### TLS
- `--insecure` – **Disable** Certificate Verification  
- `--no-insecure` – **Enable** Strict Certificate Verification

### Other
- `--outfile <path.pdf>` – Save PDF Location (Default: Current Directory)
- `--debug` – Verbose HTTP/SSH diagnostics to stderr

---

## Examples

**Password Login + SSH (Recommended)**
```bash
python ProxmoxReportGenerator.py --host pve.example.com --logo ./company.png --username root@pam --password '••••••' --ssh-user root --ssh-password '••••••'
```

**API Token + SSH Key**
```bash
python ProxmoxReportGenerator.py --host pve.example.com --logo ./company.png --token-user root@pam --token-id myreport --token-secret 'pve-xxxxx-xxxxx' --ssh-user root --ssh-key ~/.ssh/id_rsa --no-insecure
```

**Self‑Signed Lab**
```bash
python ProxmoxReportGenerator.py --host 10.0.0.20 --logo ./lab.png --username root@pam --password 'labpass' --ssh-user root --ssh-password 'labpass' --insecure
```

---

## Output PDF File

The PDF Includes:

- **Cluster Overview**
- **Nodes**
- **Nodes Details (Hostname & IPs)**
- **VM & Container Summary (By node)**
- **VM/LXC Utilization**
- **Shared/Local Storage**
- **Network Overview**

## Proxmox Generate PDF Sample

<p>
  📄 <strong>Sample Proxmox PDF Report</strong>
  <a href="https://github.com/AungThuMyint/ProxmoxReportGenerator/blob/main/Report/Proxmox_Summary.pdf">View</a>
</p>

<table>
  <tr>
    <td><img src="https://raw.githubusercontent.com/AungThuMyint/ProxmoxReportGenerator/refs/heads/main/Report/Page1.jpg" alt="Page1" width="260"></td>
    <td><img src="https://raw.githubusercontent.com/AungThuMyint/ProxmoxReportGenerator/refs/heads/main/Report/Page2.jpg" alt="Page2" width="260"></td>
    <td><img src="https://raw.githubusercontent.com/AungThuMyint/ProxmoxReportGenerator/refs/heads/main/Report/Page3.jpg" alt="Page3" width="260"></td>
  </tr>
  <tr>
    <td><img src="https://raw.githubusercontent.com/AungThuMyint/ProxmoxReportGenerator/refs/heads/main/Report/Page4.jpg" alt="Page4" width="260"></td>
    <td><img src="https://raw.githubusercontent.com/AungThuMyint/ProxmoxReportGenerator/refs/heads/main/Report/Page5.jpg" alt="Page5" width="260"></td>
    <td><img src="https://raw.githubusercontent.com/AungThuMyint/ProxmoxReportGenerator/refs/heads/main/Report/Page6.jpg" alt="Page6" width="260"></td>
  </tr>
</table>

---

## License

Add your preferred license (e.g., MIT/Apache‑2.0) in `LICENSE`. If unspecified, all rights reserved by default.
