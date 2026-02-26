# mod_sip_pcap

A FreeSWITCH module that captures SIP signaling packets to PCAP files using
**libpcap** — with zero impact on FreeSWITCH logging or performance.

---

## How it works

On load, the module scans all `sip_profiles/*.xml` files and looks for profiles
that have:

```xml
<param name="capture_signaling_packets" value="true"/>
```

For each matching profile it reads that profile's `sip-ip` and `sip-port`, then
starts a dedicated **libpcap capture thread** on that IP:port. A kernel-level
BPF filter (`udp port <sip-port>`) means unrelated traffic never reaches
userspace.

Captured SIP packets are written **as-is** (real IP/UDP headers intact) into
per-Call-ID PCAP files under the configured output directory:

```
/var/log/freeswitch/sip_pcap/<call-id>_<UTC-timestamp>.pcap
```

Files can be opened directly in Wireshark — SIP is decoded automatically.

No `sofia global siptrace on` required. No log hooks. No extra load on
FreeSWITCH's event or logging systems.

---

## Features

- **Zero FreeSWITCH overhead** — raw packet capture via libpcap, independent of FS logging
- **Per-profile control** — enable capture only on profiles that need it
- **Selective capture** — filter by message type via config flags:
  - `save-calls` — INVITE, BYE, ACK, CANCEL, UPDATE, etc. (default: **on**)
  - `save-registrations` — REGISTER transactions (default: **on**)
  - `save-options` — OPTIONS keepalives (default: **off**, usually noisy)
- **Real PCAP files** — actual captured Ethernet/IP/UDP frames with correct headers; Wireshark decodes them natively
- **Per-Call-ID files** — one `.pcap` file per SIP dialog, named by Call-ID
- **Multiple profiles** — one capture thread per enabled profile, each on its own port

---

## Requirements

- FreeSWITCH with development headers installed
- `libpcap-dev`
- `g++` with C++14 support
- The FreeSWITCH process must have `CAP_NET_RAW` capability (or run as root) to open a raw pcap socket

### Install build dependencies

```bash
sudo apt-get install -y libpcap-dev g++
```

---

## Build & Install

```bash
git clone <this-repo> mod_sip_pcap
cd mod_sip_pcap

make FREESWITCH_PREFIX=/usr/local/freeswitch
sudo make install FREESWITCH_PREFIX=/usr/local/freeswitch
```

If your FreeSWITCH is installed to a different prefix, adjust accordingly.

---

## Configuration

### 1. Module config — `autoload_configs/sip_pcap.conf.xml`

Copy `sip_pcap.conf.xml` to your FreeSWITCH autoload configs directory:

```bash
sudo cp sip_pcap.conf.xml /usr/local/freeswitch/conf/autoload_configs/
```

The file controls global settings:

```xml
<configuration name="sip_pcap.conf" description="SIP Signaling PCAP Capture">
  <settings>
    <!-- Master on/off switch -->
    <param name="enabled"              value="true"/>

    <!-- Directory where per-call .pcap files are written -->
    <param name="output-dir"           value="/var/log/freeswitch/sip_pcap"/>

    <!-- Which SIP message types to capture -->
    <param name="save-calls"           value="true"/>
    <param name="save-registrations"   value="true"/>
    <param name="save-options"         value="false"/>
  </settings>
</configuration>
```

Create the output directory and ensure it is writable by the FreeSWITCH process:

```bash
sudo mkdir -p /var/log/freeswitch/sip_pcap
sudo chown freeswitch:freeswitch /var/log/freeswitch/sip_pcap
```

### 2. Enable capture on a SIP profile

Add one line inside the `<settings>` block of any SIP profile you want to
capture (e.g. `conf/sip_profiles/internal.xml`):

```xml
<param name="capture_signaling_packets" value="true"/>
```

The module reads `sip-ip` and `sip-port` from the same profile automatically —
no need to configure them separately.

### 3. Enable module autoload — `autoload_configs/modules.conf.xml`

```xml
<load module="mod_sip_pcap"/>
```

### 4. Load the module

```bash
fs_cli -x "load mod_sip_pcap"
```

Or restart FreeSWITCH to autoload it.

---

## Verifying it works

Check which profiles were detected and that capture threads are running:

```bash
fs_cli -x "sip_pcap status"
```

Expected output:

```
mod_sip_pcap status:
  output-dir         : /var/log/freeswitch/sip_pcap
  save-calls         : yes
  save-registrations : yes
  save-options       : no
  capture threads    : 1
    [internal] port=5060 ip=any running=yes
  active pcap files  : 0
```

Make a test call, then:

```bash
fs_cli -x "sip_pcap list"
ls -lh /var/log/freeswitch/sip_pcap/
```

---

## Runtime API

From `fs_cli`:

| Command           | Description                                              |
|-------------------|----------------------------------------------------------|
| `sip_pcap status` | Show config, capture threads, and active file count      |
| `sip_pcap list`   | List all open PCAP files with Call-ID and packet count   |
| `sip_pcap flush`  | Close all open writers (useful for log rotation)         |

---

## Opening PCAP files in Wireshark

1. **File → Open** the `.pcap` file
2. Wireshark auto-detects SIP over UDP
3. Use display filter `sip` to show only SIP messages
4. Use **Telephony → VoIP Calls** for a full call flow diagram

---

## Notes

- **Reload behaviour** — if you add `capture_signaling_packets=true` to a profile after the module is loaded, run `reload mod_sip_pcap` to pick it up.
- **TLS SIP** — packets on port 5061 are captured at the network layer (encrypted). To capture decrypted SIP over TLS you would need a different approach (siptrace or SSLKEYLOGFILE).
- **High volume** — for busy servers consider pointing `output-dir` at a `tmpfs` mount and rotating files externally.
- **OPTIONS flood** — leave `save-options` as `false` unless you specifically need keepalive traffic; it generates a file per Call-ID which can be thousands per hour on a busy system.
