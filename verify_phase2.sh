# 1. Clear Session Keyring (optional, harmless)
# sudo keyctl clear @s

# 2. Add Key to Root's Session Keyring (@s)
# This keyring is inherited by the loader process started from this script.
echo "[Setup] Adding 'sentinel:pubkey' to Session Keyring..."
sudo keyctl add user sentinel:pubkey "$(cat pub.pem)" @s > /dev/null

# 3. Retrieve Key ID reliably
KEY_ID=$(sudo keyctl search @s user sentinel:pubkey)
echo "[Setup] Key ID: $KEY_ID"

# 4. Set Permissions (View, Read, Write, Search, Link, SetAttr for All)
# 0x3f3f3f3f = Possessor, User, Group, Other all get full access.
echo "[Setup] Setting Permissions..."
sudo keyctl setperm $KEY_ID 0x3f3f3f3f

# 5. Verify Permissions
echo "[Setup] Key Description:"
sudo keyctl describe $KEY_ID

echo ""
echo "[Run] Launching Loader..."
sudo ./loader ./victim_phase2
