# WireGuard Module for MADMIN

A comprehensive WireGuard VPN management module with per-client firewall groups and granular access control.

## 🌟 Features

- **Multi-Instance Support** - Run multiple WireGuard VPN servers on different ports
- **Client Management** - Create, revoke clients with QR code and config download
- **Firewall Groups** - Group clients and apply specific firewall rules
- **Default Policy** - ACCEPT or DROP policy for non-grouped clients
- **Automatic IP Allocation** - Sequential IP assignment from instance subnet
- **Live Status** - Real-time instance running/stopped status

## 📁 Module Structure

```
wireguard/
├── __init__.py          # Module metadata (name, version, permissions)
├── models.py            # Database models (WgInstance, WgClient, WgGroup, etc.)
├── router.py            # FastAPI routes
├── service.py           # Business logic & iptables management
└── static/
    └── views/
        ├── main.js      # Instance listing and management
        └── firewall.js  # Group and rule management
```

## 🔥 Firewall Architecture

### Chain Hierarchy

```
FORWARD
└── MADMIN_FORWARD (machine rules, highest priority)
└── MOD_WG_FORWARD (module chain)
    └── WG_{instance}_FWD (per-instance)
        └── WG_GRP_{group} (per-group rules)
            └── Individual rules
            └── RETURN (to check next group)
        └── -o wg_interface -j ACCEPT (responses)
        └── Default Policy (ACCEPT/DROP)
```

### Rule Processing Flow

1. Traffic from VPN client enters `FORWARD` chain
2. Jumps to `MADMIN_FORWARD` (machine-level rules)
3. Jumps to `MOD_WG_FORWARD` (WireGuard module)
4. Jumps to instance chain `WG_{instance}_FWD`
5. If client IP matches a group → jumps to group chain
6. Group rules are applied in order
7. If no match, returns and checks next group
8. Finally, default policy (ACCEPT/DROP) is applied

## 🛠️ Installation

### From MADMIN UI

1. Go to **Modules** page
2. Find "WireGuard" in **Staging** tab
3. Click **Install**
4. Module chains are automatically registered

### Manual Installation

```bash
# Copy from staging to modules
cp -r backend/staging/wireguard backend/modules/

# Restart application to load module
```

## 📡 API Endpoints

### Instances

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/instances` | List all instances |
| POST | `/instances` | Create new instance |
| GET | `/instances/{id}` | Get instance details |
| DELETE | `/instances/{id}` | Delete instance |
| POST | `/instances/{id}/start` | Start instance |
| POST | `/instances/{id}/stop` | Stop instance |

### Clients

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/instances/{id}/clients` | List clients |
| POST | `/instances/{id}/clients` | Create client |
| DELETE | `/instances/{id}/clients/{name}` | Revoke client |
| GET | `/instances/{id}/clients/{name}/config` | Download config |
| GET | `/instances/{id}/clients/{name}/qr` | Get QR code |

### Groups & Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/instances/{id}/groups` | List groups |
| POST | `/instances/{id}/groups` | Create group |
| DELETE | `/instances/{id}/groups/{gid}` | Delete group |
| GET | `/instances/{id}/groups/{gid}/members` | List members |
| POST | `/instances/{id}/groups/{gid}/members/{cid}` | Add member |
| DELETE | `/instances/{id}/groups/{gid}/members/{cid}` | Remove member |
| GET | `/instances/{id}/groups/{gid}/rules` | List rules |
| POST | `/instances/{id}/groups/{gid}/rules` | Create rule |
| PATCH | `/instances/{id}/groups/{gid}/rules/{rid}` | Update rule |
| DELETE | `/instances/{id}/groups/{gid}/rules/{rid}` | Delete rule |
| PUT | `/instances/{id}/groups/{gid}/rules/order` | Reorder rules |

## 💡 Usage Examples

### Create an Instance

```bash
curl -X POST /api/modules/wireguard/instances \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "office",
    "port": 51820,
    "subnet": "10.8.0.0/24",
    "dns_servers": "1.1.1.1, 8.8.8.8",
    "tunnel_mode": "full"
  }'
```

### Create a Client

```bash
curl -X POST /api/modules/wireguard/instances/wg_office/clients \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "john-laptop"}'
```

### Create a Firewall Group

```bash
# Create group
curl -X POST /api/modules/wireguard/instances/wg_office/groups \
  -d '{"name": "restricted", "description": "Limited internet access"}'

# Add rule to block social media
curl -X POST /api/modules/wireguard/instances/wg_office/groups/wg_office_restricted/rules \
  -d '{"action": "DROP", "protocol": "all", "destination": "157.240.0.0/16", "description": "Block Facebook"}'

# Add client to group
curl -X POST /api/modules/wireguard/instances/wg_office/groups/wg_office_restricted/members/john-laptop
```

## ⚙️ Configuration

### Instance Options

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `name` | string | Instance identifier | required |
| `port` | int | UDP listening port | 51820 |
| `subnet` | string | VPN subnet CIDR | 10.8.0.0/24 |
| `dns_servers` | string | DNS for clients | 1.1.1.1, 8.8.8.8 |
| `tunnel_mode` | enum | `full` or `split` | full |
| `firewall_default_policy` | enum | `ACCEPT` or `DROP` | ACCEPT |

### Rule Options

| Field | Type | Description |
|-------|------|-------------|
| `action` | enum | `ACCEPT`, `DROP`, `REJECT` |
| `protocol` | enum | `all`, `tcp`, `udp`, `icmp` |
| `destination` | string | IP/CIDR (e.g., `8.8.8.8/32`) |
| `port` | string | Port number (tcp/udp only) |
| `description` | string | Rule description |

## 🔐 Permissions

| Permission | Description |
|------------|-------------|
| `wireguard.view` | View instances and clients |
| `wireguard.manage` | Create/delete instances |
| `wireguard.clients` | Create/revoke clients |

## 📋 Requirements

- Linux with WireGuard kernel module
- Root access (for iptables and wg commands)
- `wg` and `wg-quick` utilities installed

```bash
# Debian/Ubuntu
apt install wireguard wireguard-tools

# RHEL/CentOS
yum install wireguard-tools
```

## 🔧 Troubleshooting

### Interface won't start
```bash
# Check if WireGuard module is loaded
lsmod | grep wireguard

# Check systemd service status
systemctl status wg-quick@wg_instance
```

### Firewall rules not applied
```bash
# View current iptables rules
iptables -L -n -v

# Check specific chains
iptables -L MOD_WG_FORWARD -n -v
```

### Client can't connect
1. Verify port is open: `ss -ulnp | grep 51820`
2. Check client config has correct endpoint
3. Verify NAT masquerade rule exists

---

Made with ❤️ for the MADMIN project.
