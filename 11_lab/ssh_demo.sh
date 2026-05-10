#!/bin/bash

set -e

echo "[1] Removing old demo files"
rm -f demo_id_ed25519 demo_id_ed25519.pub message.txt message.txt.sig allowed_signers

echo "[2] Generating ed25519 key pair"
ssh-keygen -t ed25519 -N "" -f demo_id_ed25519

echo "[3] Creating test message"
echo "Test message for Lab 11" > message.txt

echo "[4] Signing message"
ssh-keygen -Y sign -f demo_id_ed25519 -n file message.txt

echo "[5] Creating allowed_signers file"
SIGNER="student@example.com"
PUBKEY=$(cat demo_id_ed25519.pub)
echo "$SIGNER namespaces=\"file\" $PUBKEY" > allowed_signers

echo "[6] Verifying signature"
ssh-keygen -Y verify -f allowed_signers -I "$SIGNER" -n file -s message.txt.sig < message.txt

echo "[7] OpenSSH demo completed successfully"