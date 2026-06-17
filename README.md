# DNS Rebinding Verification Tool

A tool to verify whether a web application has correctly implemented IP pinning as a defence against DNS rebinding attacks and SSRF (Server-Side Request Forgery).

---

## How It Works

When a web application fetches a URL, it resolves the domain to an IP and (if not pinned) may resolve it again for the actual connection. This tool exploits that gap:

```
Request 1 (SSRF filter check) → DNS returns 8.8.8.8      → passes filter ✓
Request 2 (actual connection) → DNS returns 169.254.170.2 → hits metadata  ✗
```

If the application has correctly pinned the IP, the second DNS query never happens.

---

## Requirements

- A domain (GoDaddy, Namecheap, or Porkbun)
- A VPS with a public IP (DigitalOcean, Vultr, or Linode)
- Python 3.10+
- `dnslib` library

---

## Step 1 — Buy a Domain

Go to any of these registrars and purchase a cheap domain (~$1–3/year):

| Registrar | Cheapest TLD |
|-----------|-------------|
| [Porkbun](https://porkbun.com) | `.xyz` ~$1/year |
| [Namecheap](https://namecheap.com) | `.site` ~$1/year |
| [GoDaddy](https://godaddy.com) | `.com` ~$10/year |

Pick a neutral-sounding name (e.g. `sectest.xyz`, `apicheck.xyz`). You do not need hosting, just the domain.

---

## Step 2 — Create a VPS

1. Sign up at [DigitalOcean](https://digitalocean.com)
2. Click **Create → Droplets**
3. Select:
   - **OS**: Ubuntu 24.04 LTS
   - **Plan**: Basic → Shared CPU → Regular → $6/month (1GB RAM)
   - **Region**: Closest to your target
   - **Authentication**: Password
4. Click **Create Droplet** and wait ~1 minute
5. Note the public IP (e.g. `178.128.116.162`)

---

## Step 3 — Configure DNS Records

Go to your registrar's DNS management panel and add these two records:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | `ns1` | `<your VPS IP>` | 600 |
| NS | `rebind` | `ns1.yourdomain.com` | 600 |

> **Note for GoDaddy users:** Go to **My Products → your domain → DNS**. Do NOT change the nameservers — only add records inside the DNS management page.

What these records do:
- The `A` record tells the internet that `ns1.yourdomain.com` is your VPS
- The `NS` record delegates all queries for `rebind.yourdomain.com` to your VPS

Wait 5–30 minutes for propagation, then verify:

```bash
dig NS rebind.yourdomain.com
# Expected: rebind.yourdomain.com. 600 IN NS ns1.yourdomain.com.

dig A ns1.yourdomain.com
# Expected: ns1.yourdomain.com. 600 IN A <your VPS IP>
```

---

## Step 4 — Set Up the VPS

SSH into your VPS:

```bash
ssh root@<your-vps-ip>
```

Install dependencies:

```bash
apt update && apt install -y python3-pip
pip3 install dnslib
```

Copy the script to the VPS (run this from your local machine):

```bash
scp verify_ip_pinning.py root@<your-vps-ip>:/root/
```

---

## Step 5 — Run the Script

On the VPS:

```bash
python3 /root/verify_ip_pinning.py \
    --domain rebind.yourdomain.com \
    --real-ip 8.8.8.8 \
    --real-port 80 \
    --trap-ip 169.254.170.2 \
    --trap-port 8080 \
    --dns-port 53
```

| Flag | Description |
|------|-------------|
| `--domain` | The domain the client will resolve |
| `--real-ip` | IP returned on first DNS query (passes SSRF check) |
| `--real-port` | Port for the real HTTP server |
| `--trap-ip` | IP returned on all subsequent DNS queries (the target internal IP) |
| `--trap-port` | Port for the trap HTTP server |
| `--dns-port` | UDP port for the fake DNS server |

Common trap IPs to test:

| Target | IP |
|--------|----|
| AWS EC2 metadata | `169.254.169.254` |
| AWS ECS metadata | `169.254.170.2` |
| GCP metadata | `169.254.169.254` |
| localhost | `127.0.0.1` |

---

## Step 6 — Submit the URL to the Target Application

```
http://rebind.yourdomain.com/v2/metadata
```

Submit this as the URL to the application's SSRF endpoint and watch the terminal output.

---

## Step 7 — Read the Results

**Application is NOT pinned (vulnerable):**
```
[DNS]  query #1 → 8.8.8.8           ← SSRF filter resolved this
[DNS]  query #2 → 169.254.170.2     ← actual request re-resolved
[TRAP] *** connection from x.x.x.x  ← client followed the new IP
```

**Application IS pinned (secure):**
```
[DNS]  query #1 → 8.8.8.8           ← resolved once and pinned
                                     ← no further DNS queries
```

Press `Ctrl+C` for the full verification report.

---

## Step 8 — Tear Down After Testing

Stop the script with `Ctrl+C`, then exit the SSH session:

```bash
exit
```

Destroy the VPS on DigitalOcean to stop all billing:

**DigitalOcean → your droplet → Destroy → Destroy this Droplet**

---

## Understanding the Output

| Log Line | Meaning |
|----------|---------|
| `[DNS] query #1 → 8.8.8.8` | First DNS query — returning safe public IP |
| `[DNS] query #2 → 169.254.170.2` | Rebind triggered — returning internal IP |
| `[REAL] connection from x.x.x.x` | HTTP hit on real server (expected) |
| `[TRAP] connection from x.x.x.x` | HTTP hit on trap server — pinning failed |
| `non-A query (NS) from x.x.x.x` | Nameserver validation query — ignore these |

> **Note:** You may see random bots hitting your open ports (scanning for `.env` files, router exploits, etc.). These are normal internet background noise — ignore any hits that do not come from your target application's IP.

---

## Recommended Fix for Vulnerable Applications

After resolving a hostname to an IP, the application must validate that IP against blocked ranges including `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.0.0/16`, then connect directly to that validated IP without re-resolving the domain again for that request. Any redirects returned by the server must go through the same resolve-and-validate cycle before being followed, as blindly following redirects bypasses the IP validation entirely.

---

## Notes

- Using `8.8.8.8` as `--real-ip` means you do not need to run any server yourself — it just needs to be a public IP that passes the SSRF filter check
- The script only advances the DNS counter on `A` record queries — `NS` queries from your registrar's nameservers are ignored so they do not consume the first slot
- Both HTTP servers bind to `0.0.0.0` regardless of `--real-ip` and `--trap-ip` — those IPs are only used in DNS responses, not as bind addresses

---

## Credits

- DNS rebinding concept based on [taviso/rbndr](https://github.com/taviso/rbndr) by Tavis Ormandy
- Tool developed with assistance from [Claude](https://claude.ai) (Anthropic)
