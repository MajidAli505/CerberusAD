#!/usr/bin/env bash
# ============================================================
#  Cerberus Collector - launcher for Linux / Kali
#  Asks 3 questions, then runs the full scan and builds the
#  dashboard package. Usage:  ./start-linux.sh
# ============================================================
set -e
cd "$(dirname "$0")"

echo
echo "  CERBERUS COLLECTOR - Active Directory security scan"
echo "  ---------------------------------------------------"
echo

python3 -m pip install -q ldap3 2>/dev/null || pip3 install -q ldap3 2>/dev/null || true

read -rp "1) Domain Controller IP or name (e.g. 192.168.1.10): " DC
read -rp "2) Domain user (e.g. DOMAIN\\user): " USR
echo "3) The password is asked next - it will NOT be shown or stored."
read -rp "Include per-machine session data? Slower, needs impacket (Y/N, Enter = No): " REMOTE

FLAGS=""
if [[ "$REMOTE" =~ ^[Yy]$ ]]; then
  python3 -m pip install -q impacket 2>/dev/null || pip3 install -q impacket 2>/dev/null || true
else
  FLAGS="--skip-remote"
fi

echo
echo "Scanning - this can take a few minutes..."
python3 cerberus.py --dc "$DC" --user "$USR" $FLAGS
echo
echo "Done. Upload the CerberusScan-*.json file in the dashboard: Clients - Add Scan."
