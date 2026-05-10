#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo bash "$0" "$@"
fi

cd "$(dirname "$0")"

LABDIR="wireguard_practice"

echo "[1] Cleaning old WireGuard lab state"
ip netns del wg_server 2>/dev/null || true
ip netns del wg_client 2>/dev/null || true
rm -rf "$LABDIR"
mkdir -p "$LABDIR"

echo "[2] Generating real WireGuard keys"
wg genkey | tee "$LABDIR/server_private.key" | wg pubkey > "$LABDIR/server_public.key"
wg genkey | tee "$LABDIR/client_private.key" | wg pubkey > "$LABDIR/client_public.key"

chmod 600 "$LABDIR/"*_private.key

SERVER_PRIV=$(cat "$LABDIR/server_private.key")
SERVER_PUB=$(cat "$LABDIR/server_public.key")
CLIENT_PRIV=$(cat "$LABDIR/client_private.key")
CLIENT_PUB=$(cat "$LABDIR/client_public.key")

echo "[3] Creating WireGuard configuration files"

cat > "$LABDIR/wg_server.conf" <<CONF
[Interface]
PrivateKey = $SERVER_PRIV
Address = 10.11.0.1/24
ListenPort = 51820

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.11.0.2/32
CONF

cat > "$LABDIR/wg_client.conf" <<CONF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.11.0.2/24
ListenPort = 51821

[Peer]
PublicKey = $SERVER_PUB
Endpoint = 192.168.100.1:51820
AllowedIPs = 10.11.0.1/32
PersistentKeepalive = 25
CONF

echo "[4] Creating two isolated Linux network namespaces"
ip netns add wg_server
ip netns add wg_client

echo "[5] Creating underlay network between namespaces"
ip link add veth_server type veth peer name veth_client

ip link set veth_server netns wg_server
ip link set veth_client netns wg_client

ip netns exec wg_server ip addr add 192.168.100.1/24 dev veth_server
ip netns exec wg_client ip addr add 192.168.100.2/24 dev veth_client

ip netns exec wg_server ip link set lo up
ip netns exec wg_client ip link set lo up
ip netns exec wg_server ip link set veth_server up
ip netns exec wg_client ip link set veth_client up

echo "[6] Creating WireGuard interfaces inside namespaces"
ip netns exec wg_server ip link add wg_srv type wireguard
ip netns exec wg_client ip link add wg_cli type wireguard

echo "[7] Configuring WireGuard server and client"
ip netns exec wg_server wg set wg_srv private-key "$LABDIR/server_private.key" listen-port 51820 peer "$CLIENT_PUB" allowed-ips 10.11.0.2/32
ip netns exec wg_client wg set wg_cli private-key "$LABDIR/client_private.key" listen-port 51821 peer "$SERVER_PUB" allowed-ips 10.11.0.1/32 endpoint 192.168.100.1:51820 persistent-keepalive 25

ip netns exec wg_server ip addr add 10.11.0.1/24 dev wg_srv
ip netns exec wg_client ip addr add 10.11.0.2/24 dev wg_cli

ip netns exec wg_server ip link set wg_srv up
ip netns exec wg_client ip link set wg_cli up

echo
echo "========== SERVER CONFIG =========="
cat "$LABDIR/wg_server.conf"

echo
echo "========== CLIENT CONFIG =========="
cat "$LABDIR/wg_client.conf"

echo
echo "========== WG SHOW BEFORE PING =========="
echo "--- server ---"
ip netns exec wg_server wg show
echo "--- client ---"
ip netns exec wg_client wg show

echo
echo "========== PING THROUGH WIREGUARD TUNNEL =========="
ip netns exec wg_client ping -c 4 10.11.0.1

echo
echo "========== WG SHOW AFTER PING =========="
echo "--- server ---"
ip netns exec wg_server wg show
echo "--- client ---"
ip netns exec wg_client wg show

echo
echo "[SUCCESS] WireGuard lab stand is working"
echo "Server namespace: wg_server"
echo "Client namespace: wg_client"
echo "VPN addresses: 10.11.0.1 <-> 10.11.0.2"
