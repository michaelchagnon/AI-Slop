#!/bin/bash
# Tor Wi-Fi Hotspot Router Setup Script
# For Raspberry Pi OS Bookworm / Trixie (NetworkManager based) 32-bit lite
#
# Features:
# - Tor transparent proxy for Wi-Fi clients on wlan0
# - dnsmasq (DHCP/DNS) + unbound (DNS over Tor via DNSPort)
# - SSH over eth0 preserved
# - iptables firewall focused on wlan0 (no Pi self-lockout)
# - Pre-reboot DNS tests (Tor + Unbound)
# - Post-boot self-check service (runs once)
# - Auto-reboot with 10-second countdown at end

set -e

# ---------- CONFIGURATION ----------
WLAN_IFACE="wlan0"
WAN_IFACE="eth0"
WLAN_IP="10.0.0.1"
WLAN_NETMASK="24"
SSID_NAME="Tor_Onion_Pi"
WPA_PASS="ChangeMe1234!"   # CHANGE THIS BEFORE USING

TOR_TRANS_PORT="9040"
TOR_DNS_PORT="9053"    # Tor DNSPort
UNBOUND_PORT="5335"    # local validating-ish resolver, upstream = Tor DNSPort

# ---------- BASIC CHECKS ----------

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Please run this script as root."
  exit 1
fi

echo "[*] Checking OS compatibility..."
if grep -Eiq "bookworm|trixie" /etc/os-release; then
    echo "[+] Modern OS detected (Bookworm/Trixie)."
else
    echo "[!] Warning: This script is optimized for Bookworm/Trixie (NetworkManager)."
fi

# ---------- UPDATE & INSTALL ----------

echo "[*] Updating package index..."
apt update

echo "[*] Installing required packages..."
apt install -y tor dnsmasq hostapd unbound iptables dnsutils

# Stop services for clean reconfig
systemctl stop hostapd dnsmasq unbound tor || true

# ---------- NETWORKMANAGER: UNMANAGE wlan0 ----------

echo "[*] Configuring NetworkManager to ignore ${WLAN_IFACE}..."
if command -v nmcli >/dev/null 2>&1; then
    nmcli dev set "$WLAN_IFACE" managed no || true
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/99-unmanaged-${WLAN_IFACE}.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${WLAN_IFACE}
EOF
    systemctl restart NetworkManager || true
    sleep 2
    echo "[+] NetworkManager will ignore ${WLAN_IFACE}."
else
    echo "[!] nmcli not found; assuming legacy networking."
fi

# Ensure Wi-Fi not blocked
rfkill unblock wifi || true
rfkill unblock wlan || true

# ---------- STATIC IP ON wlan0 (SYSTEMD) ----------

echo "[*] Creating systemd unit for static IP on ${WLAN_IFACE}..."
cat > /etc/systemd/system/wlan-static.service <<EOF
[Unit]
Description=Set static IP on ${WLAN_IFACE} for Tor hotspot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip addr flush dev ${WLAN_IFACE}
ExecStart=/usr/sbin/ip addr add ${WLAN_IP}/${WLAN_NETMASK} dev ${WLAN_IFACE}
ExecStart=/usr/sbin/ip link set ${WLAN_IFACE} up
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wlan-static.service
systemctl start wlan-static.service
echo "[+] Static IP ${WLAN_IP}/${WLAN_NETMASK} set on ${WLAN_IFACE}."

# ---------- ENABLE IP FORWARDING ----------

echo "[*] Enabling IPv4 forwarding..."
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-tor-hotspot-forward.conf <<EOF
net.ipv4.ip_forward=1
EOF
sysctl -p /etc/sysctl.d/99-tor-hotspot-forward.conf >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null

# ---------- CONFIGURE TOR ----------

echo "[*] Configuring Tor..."
TORRC="/etc/tor/torrc"
mv "$TORRC" "${TORRC}.bak.$(date +%s)" 2>/dev/null || true

cat > "$TORRC" <<EOF
Log notice file /var/log/tor/notices.log
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit
ClientOnly 1

# Transparent proxy for TCP from clients
TransPort 0.0.0.0:${TOR_TRANS_PORT}

# DNS listener used by Unbound
DNSPort 127.0.0.1:${TOR_DNS_PORT}
EOF

# ---------- CONFIGURE UNBOUND (DNS over Tor, permissive DNSSEC) ----------

echo "[*] Configuring Unbound (DNS over Tor)..."
mkdir -p /etc/unbound/unbound.conf.d
UNBOUND_MAIN="/etc/unbound/unbound.conf"

# Ensure includes are enabled
if ! grep -q 'unbound.conf.d' "$UNBOUND_MAIN" 2>/dev/null; then
    echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >> "$UNBOUND_MAIN"
fi

UNBOUND_CONF="/etc/unbound/unbound.conf.d/pi-tor.conf"
cat > "$UNBOUND_CONF" <<EOF
server:
    verbosity: 1
    interface: 127.0.0.1
    port: ${UNBOUND_PORT}

    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse

    hide-identity: yes
    hide-version: yes

    do-not-query-localhost: no

    # Tor-friendly DNSSEC settings
    val-log-level: 2
    val-permissive-mode: yes
    module-config: "validator iterator"
    harden-dnssec-stripped: no
    trust-anchor-signaling: no
    qname-minimisation: no

    # Prevent trust-anchor priming (breaks over Tor)
    auto-trust-anchor-file: ""
    trust-anchor-file: ""

forward-zone:
    name: "."
    forward-addr: 127.0.0.1@${TOR_DNS_PORT}
EOF

# Disable resolvconf integration if present (avoid loops)
if [ -f /etc/default/unbound ]; then
    sed -i 's/RESOLVCONF="true"/RESOLVCONF="false"/' /etc/default/unbound || true
fi

# ---------- CONFIGURE DNSMASQ (DHCP/DNS on wlan0) ----------

echo "[*] Configuring dnsmasq..."
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak.$(date +%s) 2>/dev/null || true

cat > /etc/dnsmasq.conf <<EOF
# Listen on hotspot interface and loopback
interface=${WLAN_IFACE}
interface=lo
bind-interfaces

# DHCP range for Wi-Fi clients
dhcp-range=10.0.0.10,10.0.0.200,24h

# Default gateway and DNS server for clients
dhcp-option=3,${WLAN_IP}
dhcp-option=6,${WLAN_IP}

# Upstream DNS = Unbound
server=127.0.0.1#${UNBOUND_PORT}
no-resolv

log-queries
log-dhcp
EOF

# ---------- SYSTEM RESOLVER (Pi uses local DNS chain) ----------

echo "[*] Pointing system resolver at localhost..."
if [ -L /etc/resolv.conf ]; then
  RESOLV_TARGET="$(readlink -f /etc/resolv.conf)"
  printf 'nameserver 127.0.0.1\n' > "$RESOLV_TARGET"
else
  printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
fi

# ---------- CONFIGURE HOSTAPD (Wi-Fi AP) ----------

echo "[*] Configuring hostapd..."
cat > /etc/hostapd/hostapd.conf <<EOF
interface=${WLAN_IFACE}
driver=nl80211
ssid=${SSID_NAME}
hw_mode=g
channel=7
country_code=US
ieee80211d=1
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${WPA_PASS}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

DAEMON_CONF="/etc/default/hostapd"
if [ -f "$DAEMON_CONF" ]; then
    sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' "$DAEMON_CONF"
fi
systemctl unmask hostapd || true

# ---------- FIREWALL: TOR HOTSPOT RULES (iptables) ----------

echo "[*] Writing Tor firewall script..."
cat > /usr/local/sbin/tor_firewall.sh <<EOF
#!/bin/bash
_wlan="${WLAN_IFACE}"
_wan="${WAN_IFACE}"
_tor_trans="${TOR_TRANS_PORT}"

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -X

# Default policies:
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT   # Pi itself can use Internet normally

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow already-established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (any interface, especially eth0)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow DHCP from Wi-Fi clients
iptables -A INPUT -i \$_wlan -p udp --dport 67:68 -j ACCEPT

# Allow DNS from Wi-Fi clients to this Pi
iptables -A INPUT -i \$_wlan -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i \$_wlan -p tcp --dport 53 -j ACCEPT

# Redirect all TCP from Wi-Fi clients to Tor TransPort
iptables -t nat -A PREROUTING -i \$_wlan -p tcp --syn -j REDIRECT --to-ports \$_tor_trans

# Allow Wi-Fi clients to reach the redirected Tor port on this box
iptables -A INPUT -i \$_wlan -p tcp --dport \$_tor_trans -j ACCEPT

# Drop/Reject any other unsolicited traffic from Wi-Fi side
iptables -A INPUT  -i \$_wlan -j REJECT
iptables -A FORWARD -i \$_wlan -j REJECT
EOF

chmod +x /usr/local/sbin/tor_firewall.sh

# Run firewall once now
echo "[*] Applying firewall rules now..."
/usr/local/sbin/tor_firewall.sh

# ---------- SYSTEMD SERVICE FOR FIREWALL ----------

echo "[*] Creating systemd service for firewall..."
cat > /etc/systemd/system/tor-firewall.service <<EOF
[Unit]
Description=Tor Hotspot Firewall Rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/tor_firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tor-firewall.service

# ---------- ENABLE & START CORE SERVICES ----------

echo "[*] Enabling and restarting services..."
systemctl enable tor dnsmasq hostapd unbound
systemctl restart tor
sleep 3
systemctl restart unbound
sleep 2
systemctl restart dnsmasq
systemctl restart hostapd

# ---------- PRE-REBOOT TESTS (Tor + Unbound DNS) ----------

echo
echo "==================== PRE-REBOOT TESTS ===================="

echo "[*] Testing Tor DNSPort on 127.0.0.1:${TOR_DNS_PORT}..."
if dig @127.0.0.1 -p "${TOR_DNS_PORT}" check.torproject.org A +short >/dev/null 2>&1; then
    echo "  [OK] Tor DNSPort is responding."
else
    echo "  [!!] Tor DNSPort test FAILED. Check Tor logs. Aborting before reboot."
    exit 1
fi

echo "[*] Testing Unbound on 127.0.0.1:${UNBOUND_PORT}..."
if dig @127.0.0.1 -p "${UNBOUND_PORT}" duckduckgo.com A +short >/dev/null 2>&1; then
    echo "  [OK] Unbound is resolving via Tor."
else
    echo "  [!!] Unbound DNS test FAILED. Check unbound/dnsmasq logs. Aborting before reboot."
    exit 1
fi

echo "=========================================================="

# ---------- POST-BOOT SELF-CHECK SCRIPT (runs once) ----------

echo "[*] Installing post-boot self-check service..."
mkdir -p /usr/local/sbin /var/lib/tor-hotspot

cat > /usr/local/sbin/tor_hotspot_postcheck.sh << 'EOF'
#!/bin/bash
LOGFILE="/var/log/tor-hotspot-postcheck.log"
STATE_FILE="/var/lib/tor-hotspot/firstboot_done"
TOR_DNS_PORT=9053
UNBOUND_PORT=5335

echo "==== Tor Hotspot Post-Boot Check $(date) ====" >> "$LOGFILE"

if [ -f "$STATE_FILE" ]; then
  echo "Postcheck already completed previously; exiting." >> "$LOGFILE"
  exit 0
fi

# Ensure core services are up
systemctl restart tor unbound dnsmasq hostapd >/dev/null 2>&1

check_dns() {
  local name="$1"
  local server="$2"
  local port="$3"
  if dig @"$server" -p "$port" check.torproject.org A +short >/dev/null 2>&1; then
    echo "[OK] $name DNS working" | tee -a "$LOGFILE"
    return 0
  else
    echo "[!!] $name DNS FAILED" | tee -a "$LOGFILE"
    return 1
  fi
}

check_dns "Tor" 127.0.0.1 "$TOR_DNS_PORT"
check_dns "Unbound" 127.0.0.1 "$UNBOUND_PORT"

touch "$STATE_FILE"
exit 0
EOF

chmod +x /usr/local/sbin/tor_hotspot_postcheck.sh

cat > /etc/systemd/system/tor-hotspot-postcheck.service << 'EOF'
[Unit]
Description=Tor Hotspot Post-Boot Self-Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/tor_hotspot_postcheck.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tor-hotspot-postcheck.service

# ---------- FINAL STATUS OUTPUT ----------

echo
echo "==================== QUICK STATUS ===================="
echo "[*] IP addresses:"
ip -4 addr show "${WAN_IFACE}" | sed 's/^/  /'
ip -4 addr show "${WLAN_IFACE}" | sed 's/^/  /'

echo
echo "[*] Service states:"
for svc in hostapd dnsmasq tor unbound ssh tor-firewall tor-hotspot-postcheck; do
    if systemctl is-active --quiet "$svc"; then
        echo "  [OK] $svc running"
    else
        echo "  [!!] $svc NOT running"
    fi
done

echo
echo "[*] iptables summary (INPUT & nat PREROUTING):"
iptables -L INPUT -v -n | sed 's/^/  /' | head -n 20
echo
iptables -t nat -L PREROUTING -v -n | sed 's/^/  /'

echo
echo "Wi-Fi hotspot SSID: ${SSID_NAME}"
echo "Wi-Fi password:     ${WPA_PASS}"
echo "Gateway/DNS (AP):   ${WLAN_IP}"
echo "======================================================"

# ---------- AUTO-REBOOT COUNTDOWN ----------

echo
echo "[*] Rebooting in 10 seconds so all settings persist..."
for i in 10 9 8 7 6 5 4 3 2 1; do
    echo "  Rebooting in $i..."
    sleep 1
done

echo "[*] Rebooting now..."
reboot
