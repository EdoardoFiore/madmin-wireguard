"""
WireGuard Module - Service Layer

Business logic for WireGuard operations: key generation, config management,
interface control, IP allocation, QR code generation.
"""
import subprocess
import logging
import urllib.request
from typing import Tuple, List, Optional
from pathlib import Path
from ipaddress import ip_network
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .models import WgInstance, WgClient

logger = logging.getLogger(__name__)
WIREGUARD_CONFIG_DIR = Path("/etc/wireguard")

# Cached public IP
_cached_public_ip = None


def get_public_ip() -> Optional[str]:
    """
    Get server's public IP address.
    Tries multiple services, caches result.
    """
    global _cached_public_ip
    if _cached_public_ip:
        return _cached_public_ip
    
    services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip"
    ]
    
    for url in services:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                ip = response.read().decode('utf-8').strip()
                if ip:
                    _cached_public_ip = ip
                    logger.info(f"Detected public IP: {ip}")
                    return ip
        except Exception as e:
            logger.debug(f"Failed to get IP from {url}: {e}")
            continue
    
    logger.warning("Could not detect public IP from any service")
    return None


class WireGuardService:
    """Service class for WireGuard operations."""
    
    @staticmethod
    def _run_wg_command(args: List[str], input_data: str = None) -> str:
        """Execute a 'wg' command."""
        try:
            result = subprocess.run(
                ['wg'] + args,
                capture_output=True, text=True, check=True,
                input=input_data
            )
            return result.stdout.strip()
        except FileNotFoundError:
            raise RuntimeError("WireGuard non installato")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Comando WireGuard fallito: {e.stderr}")
    
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate WireGuard key pair."""
        private_key = WireGuardService._run_wg_command(['genkey'])
        public_key = WireGuardService._run_wg_command(['pubkey'], input_data=private_key)
        return private_key, public_key
    
    @staticmethod
    def generate_psk() -> str:
        """Generate preshared key."""
        return WireGuardService._run_wg_command(['genpsk'])
    
    @staticmethod
    def create_server_config(interface: str, port: int, private_key: str, address: str) -> str:
        """Generate server interface config."""
        return f"""[Interface]
Address = {address}
ListenPort = {port}
PrivateKey = {private_key}
SaveConfig = false
"""
    
    @staticmethod
    def add_peer_to_config(config_path: Path, public_key: str, psk: str, 
                           allowed_ips: str, comment: str = "") -> None:
        """Append peer to config file."""
        peer_block = f"""
[Peer]
# {comment}
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {allowed_ips}
"""
        with open(config_path, "a") as f:
            f.write(peer_block)
    
    @staticmethod
    def remove_peer_from_config(config_path: Path, public_key: str) -> None:
        """Remove peer from config by public key."""
        with open(config_path, "r") as f:
            lines = f.readlines()
        
        new_lines = []
        current_block = []
        block_contains_target = False
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[Peer]") or stripped.startswith("[Interface]"):
                if current_block and not block_contains_target:
                    new_lines.extend(current_block)
                current_block = [line]
                block_contains_target = False
            else:
                current_block.append(line)
                if f"PublicKey = {public_key}" in stripped:
                    block_contains_target = True
        
        if current_block and not block_contains_target:
            new_lines.extend(current_block)
        
        with open(config_path, "w") as f:
            f.writelines(new_lines)
    
    @staticmethod
    def start_interface(interface: str) -> bool:
        """Start WireGuard interface."""
        try:
            subprocess.run(['wg-quick', 'up', interface], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    @staticmethod
    def stop_interface(interface: str) -> bool:
        """Stop WireGuard interface."""
        try:
            subprocess.run(['wg-quick', 'down', interface], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    @staticmethod
    def hot_reload_interface(interface: str) -> bool:
        """Apply config changes without restart."""
        config_path = WIREGUARD_CONFIG_DIR / f"{interface}.conf"
        try:
            stripped = subprocess.run(
                ['wg-quick', 'strip', str(config_path)],
                check=True, capture_output=True, text=True
            )
            subprocess.run(
                ['wg', 'syncconf', interface, '/dev/stdin'],
                input=stripped.stdout, check=True, capture_output=True, text=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    @staticmethod
    def get_interface_status(interface: str) -> bool:
        """Check if interface is running."""
        try:
            subprocess.run(['wg', 'show', interface], check=True, capture_output=True)
            return True
        except:
            return False
    
    @staticmethod
    def get_peer_status(interface: str) -> dict:
        """
        Get status of all peers on an interface.
        
        Parses 'wg show {interface} dump' output.
        
        Returns:
            dict mapping public_key -> {
                'endpoint': str or None,
                'allowed_ips': str,
                'latest_handshake': int (unix timestamp or 0),
                'last_seen': str (ISO format or None),
                'is_connected': bool (handshake < 180 seconds),
                'rx_bytes': int,
                'tx_bytes': int
            }
        """
        import time
        from datetime import datetime, timezone
        
        peers = {}
        
        try:
            result = subprocess.run(
                ['wg', 'show', interface, 'dump'],
                capture_output=True, text=True, check=True
            )
            
            lines = result.stdout.strip().split('\n')
            # First line is interface info, skip it
            # Subsequent lines are peers
            # Format: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, rx_bytes, tx_bytes, persistent_keepalive
            
            for line in lines[1:]:  # Skip interface line
                parts = line.split('\t')
                if len(parts) >= 7:
                    public_key = parts[0]
                    endpoint = parts[2] if parts[2] != '(none)' else None
                    allowed_ips = parts[3]
                    latest_handshake = int(parts[4]) if parts[4] else 0
                    rx_bytes = int(parts[5]) if parts[5] else 0
                    tx_bytes = int(parts[6]) if parts[6] else 0
                    
                    # Calculate connection status
                    now = int(time.time())
                    handshake_age = now - latest_handshake if latest_handshake > 0 else float('inf')
                    is_connected = handshake_age < 180  # Connected if handshake < 3 minutes
                    
                    # Format last seen as ISO timestamp
                    last_seen = None
                    if latest_handshake > 0:
                        last_seen = datetime.fromtimestamp(latest_handshake, tz=timezone.utc).isoformat()
                    
                    peers[public_key] = {
                        'endpoint': endpoint,
                        'allowed_ips': allowed_ips,
                        'latest_handshake': latest_handshake,
                        'last_seen': last_seen,
                        'is_connected': is_connected,
                        'rx_bytes': rx_bytes,
                        'tx_bytes': tx_bytes
                    }
            
        except subprocess.CalledProcessError:
            # Interface might not be running
            pass
        except Exception as e:
            logger.warning(f"Could not get peer status for {interface}: {e}")
        
        return peers
    
    @staticmethod
    def get_physical_interfaces() -> List[dict]:
        """
        List physical network interfaces.
        Returns interfaces suitable for routing (eth*, ens*, enp*, etc.)
        Excludes: lo, wg*, veth*, docker*, br*, virbr*
        """
        interfaces = []
        excluded_prefixes = ('lo', 'wg', 'veth', 'docker', 'br-', 'virbr', 'tun', 'tap')
        
        try:
            # Use /sys/class/net to list interfaces
            import os
            net_dir = Path('/sys/class/net')
            if net_dir.exists():
                for iface in net_dir.iterdir():
                    name = iface.name
                    # Skip excluded interfaces
                    if name.startswith(excluded_prefixes):
                        continue
                    
                    # Get interface info
                    operstate_path = iface / 'operstate'
                    state = 'unknown'
                    if operstate_path.exists():
                        state = operstate_path.read_text().strip()
                    
                    interfaces.append({
                        'name': name,
                        'state': state
                    })
            
            # Sort: up interfaces first, then by name
            interfaces.sort(key=lambda x: (x['state'] != 'up', x['name']))
            
        except Exception as e:
            logger.warning(f"Could not list interfaces: {e}")
            # Fallback to default
            interfaces = [{'name': 'eth0', 'state': 'unknown'}]
        
        return interfaces
    
    @staticmethod
    async def allocate_client_ip(session: AsyncSession, instance: WgInstance) -> str:
        """Allocate next available IP for client."""
        network = ip_network(instance.subnet, strict=False)
        
        result = await session.execute(
            select(WgClient.allocated_ip).where(WgClient.instance_id == instance.id)
        )
        allocated = {row[0].split('/')[0] for row in result.fetchall()}
        allocated.add(str(list(network.hosts())[0]))  # Server IP
        
        for host in network.hosts():
            if str(host) not in allocated:
                return f"{host}/32"
        
        raise RuntimeError("Nessun IP disponibile nella subnet")
    
    @staticmethod
    def generate_client_config(instance: WgInstance, client: WgClient, endpoint: str) -> str:
        """Generate client config file content."""
        if instance.tunnel_mode == "full":
            allowed_ips = "0.0.0.0/0"
        else:
            routes = [r.get('network', '') for r in instance.routes if r.get('network')]
            routes.append(instance.subnet)
            allowed_ips = ", ".join(routes)
        
        dns = ", ".join(instance.dns_servers) if instance.dns_servers else "8.8.8.8"
        
        return f"""[Interface]
PrivateKey = {client.private_key}
Address = {client.allocated_ip}
DNS = {dns}

[Peer]
PublicKey = {instance.public_key}
PresharedKey = {client.preshared_key}
AllowedIPs = {allowed_ips}
Endpoint = {endpoint}:{instance.port}
PersistentKeepalive = 25
"""
    
    @staticmethod
    def generate_qr_code(config: str) -> bytes:
        """Generate QR code PNG for config."""
        try:
            result = subprocess.run(
                ['qrencode', '-t', 'PNG', '-o', '-'],
                input=config.encode('utf-8'), capture_output=True, text=False, check=True
            )
            return result.stdout
        except FileNotFoundError:
            raise RuntimeError("qrencode non installato")
    
    # --- Firewall Integration ---
    # 
    # Chain hierarchy:
    # INPUT → MADMIN_INPUT → WG_INPUT → WG_{id}_INPUT
    # FORWARD → MADMIN_FORWARD → WG_FORWARD → WG_{id}_FWD
    # POSTROUTING (nat) → WG_NAT → WG_{id}_NAT
    #
    
    # Module-level main chain names (MOD_ prefix for module chains)
    WG_INPUT_CHAIN = "MOD_WG_INPUT"
    WG_FORWARD_CHAIN = "MOD_WG_FORWARD"
    WG_NAT_CHAIN = "MOD_WG_NAT"
    
    @staticmethod
    def _run_iptables(table: str, args: List[str], suppress_errors: bool = False) -> bool:
        """Execute an iptables command."""
        cmd = ["iptables", "-t", table] + args
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            if not suppress_errors:
                logger.error(f"iptables error: {e.stderr.strip()} cmd: {' '.join(cmd)}")
            return False
        except FileNotFoundError:
            logger.error("iptables command not found")
            return False
    
    @staticmethod
    def _get_default_interface() -> str:
        """Detect the default network interface."""
        try:
            result = subprocess.run(
                ["/usr/sbin/ip", "-o", "-4", "route", "show", "default"],
                capture_output=True, text=True, check=True
            )
            if result.stdout:
                parts = result.stdout.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
        except Exception as e:
            logger.warning(f"Could not detect default interface: {e}")
        return "eth0"
    
    @staticmethod
    def _create_or_flush_chain(chain_name: str, table: str = "filter") -> bool:
        """Create chain if doesn't exist, or flush it."""
        # Try to create
        if not WireGuardService._run_iptables(table, ["-N", chain_name], suppress_errors=True):
            # Creation failed (likely exists), flush it
            return WireGuardService._run_iptables(table, ["-F", chain_name])
        return True
    
    @staticmethod
    def _create_chain_if_not_exists(chain_name: str, table: str = "filter") -> bool:
        """Create chain only if it doesn't exist (don't flush)."""
        return WireGuardService._run_iptables(table, ["-N", chain_name], suppress_errors=True) or \
               WireGuardService._run_iptables(table, ["-L", chain_name, "-n"], suppress_errors=True)
    
    @staticmethod
    def _ensure_jump_rule(source_chain: str, target_chain: str, table: str = "filter") -> bool:
        """Ensure a jump rule exists from source to target chain (append, don't duplicate)."""
        # Check if jump already exists
        success, output = WireGuardService._run_iptables_with_output(
            table, ["-L", source_chain, "-n"]
        )
        if success and target_chain in output:
            return True  # Already exists
        # Add the jump
        return WireGuardService._run_iptables(table, ["-A", source_chain, "-j", target_chain])
    
    @staticmethod
    def _run_iptables_with_output(table: str, args: List[str], suppress_errors: bool = False) -> tuple:
        """Execute an iptables command and return (success, output)."""
        cmd = ["iptables", "-t", table] + args
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            if not suppress_errors:
                logger.error(f"iptables error: {e.stderr.strip()} cmd: {' '.join(cmd)}")
            return False, e.stderr
        except FileNotFoundError:
            logger.error("iptables command not found")
            return False, ""
    
    @staticmethod
    def _remove_jump_rule(source_chain: str, target_chain: str, table: str = "filter") -> bool:
        """Remove a jump rule."""
        return WireGuardService._run_iptables(table, ["-D", source_chain, "-j", target_chain], suppress_errors=True)
    
    @staticmethod
    def _delete_chain(chain_name: str, table: str = "filter") -> bool:
        """Flush and delete a chain."""
        WireGuardService._run_iptables(table, ["-F", chain_name], suppress_errors=True)
        return WireGuardService._run_iptables(table, ["-X", chain_name], suppress_errors=True)
    
    @staticmethod
    def initialize_module_firewall_chains() -> bool:
        """
        Initialize WireGuard module-level firewall chains (iptables only).
        Should be called on module load/application startup.
        
        Creates:
        - MOD_WG_INPUT: Main input chain for all WireGuard instances
        - MOD_WG_FORWARD: Main forward chain for all WireGuard instances  
        - MOD_WG_NAT: Main NAT chain for all WireGuard instances
        
        Note: For database registration, use register_module_chains() instead.
        """
        logger.info("Initializing WireGuard module firewall chains...")
        
        # 1. Create module main chains (don't flush - preserve existing instance rules)
        WireGuardService._create_chain_if_not_exists(WireGuardService.WG_INPUT_CHAIN, "filter")
        WireGuardService._create_chain_if_not_exists(WireGuardService.WG_FORWARD_CHAIN, "filter")
        WireGuardService._create_chain_if_not_exists(WireGuardService.WG_NAT_CHAIN, "nat")
        
        # 2. Cleanup old jumps
        WireGuardService._run_iptables("filter", ["-D", "INPUT", "-j", WireGuardService.WG_INPUT_CHAIN], suppress_errors=True)
        WireGuardService._run_iptables("filter", ["-D", "FORWARD", "-j", WireGuardService.WG_FORWARD_CHAIN], suppress_errors=True)
        WireGuardService._run_iptables("nat", ["-D", "POSTROUTING", "-j", WireGuardService.WG_NAT_CHAIN], suppress_errors=True)
        WireGuardService._run_iptables("filter", ["-D", "MADMIN_INPUT", "-j", WireGuardService.WG_INPUT_CHAIN], suppress_errors=True)
        WireGuardService._run_iptables("filter", ["-D", "MADMIN_FORWARD", "-j", WireGuardService.WG_FORWARD_CHAIN], suppress_errors=True)
        WireGuardService._run_iptables("filter", ["-D", "MADMIN_INPUT", "-j", "WG_INPUT"], suppress_errors=True)
        WireGuardService._run_iptables("filter", ["-D", "MADMIN_FORWARD", "-j", "WG_FORWARD"], suppress_errors=True)
        
        # 3. Add jumps to main chains (after MADMIN)
        WireGuardService._run_iptables("filter", ["-A", "INPUT", "-j", WireGuardService.WG_INPUT_CHAIN])
        WireGuardService._run_iptables("filter", ["-A", "FORWARD", "-j", WireGuardService.WG_FORWARD_CHAIN])
        WireGuardService._run_iptables("nat", ["-A", "POSTROUTING", "-j", WireGuardService.WG_NAT_CHAIN])
        
        logger.info("WireGuard iptables chains created")
        logger.info(f"  Added jumps: INPUT→{WireGuardService.WG_INPUT_CHAIN}, FORWARD→{WireGuardService.WG_FORWARD_CHAIN}")
        return True
    
    @staticmethod
    async def register_module_chains(db) -> bool:
        """
        Register WireGuard module chains with the core firewall orchestrator.
        This enables chain priority management via the UI.
        
        Should be called after module installation or on startup.
        """
        from core.firewall.orchestrator import firewall_orchestrator
        
        logger.info("Registering WireGuard module chains with orchestrator...")
        
        # First ensure iptables chains exist
        WireGuardService.initialize_module_firewall_chains()
        
        # Register with orchestrator (this creates DB entries and manages jump rules)
        await firewall_orchestrator.register_module_chain(
            db,
            module_id="wireguard",
            chain_name=WireGuardService.WG_INPUT_CHAIN,
            parent_chain="INPUT",
            priority=50,
            table_name="filter"
        )
        
        await firewall_orchestrator.register_module_chain(
            db,
            module_id="wireguard",
            chain_name=WireGuardService.WG_FORWARD_CHAIN,
            parent_chain="FORWARD",
            priority=50,
            table_name="filter"
        )
        
        # NAT chain - register for POSTROUTING
        # Note: NAT chains are in nat table, need separate handling
        await firewall_orchestrator.register_module_chain(
            db,
            module_id="wireguard",
            chain_name=WireGuardService.WG_NAT_CHAIN,
            parent_chain="POSTROUTING",
            priority=50,
            table_name="nat"
        )
        
        logger.info("WireGuard module chains registered successfully")
        return True
    
    @staticmethod
    def apply_instance_firewall_rules(instance_id: str, port: int, interface: str, subnet: str) -> bool:
        """
        Apply firewall rules for a WireGuard instance.
        
        Creates instance-specific chains:
        - WG_{id}_INPUT: Allows UDP port and interface traffic
        - WG_{id}_FWD: Allows forwarding to/from VPN interface
        - WG_{id}_NAT: Masquerades traffic from VPN subnet
        
        And links them to the module main chains (WG_INPUT, WG_FORWARD, WG_NAT).
        """
        # Ensure module chains are initialized first
        WireGuardService.initialize_module_firewall_chains()
        
        # Instance chain names - strip wg_ prefix if present to avoid WG_wg_name redundancy
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        input_chain = f"WG_{chain_id}_INPUT"
        forward_chain = f"WG_{chain_id}_FWD"
        nat_chain = f"WG_{chain_id}_NAT"
        
        wan_interface = WireGuardService._get_default_interface()
        
        logger.info(f"Applying firewall rules for WireGuard instance {instance_id}")
        
        # 1. Create/flush instance chains
        WireGuardService._create_or_flush_chain(input_chain, "filter")
        WireGuardService._create_or_flush_chain(forward_chain, "filter")
        WireGuardService._create_or_flush_chain(nat_chain, "nat")
        
        # 2. Add rules to INPUT chain
        # Allow UDP traffic on WireGuard port
        WireGuardService._run_iptables("filter", [
            "-A", input_chain, "-p", "udp", "--dport", str(port), "-j", "ACCEPT"
        ])
        # Allow all traffic from WireGuard interface
        WireGuardService._run_iptables("filter", [
            "-A", input_chain, "-i", interface, "-j", "ACCEPT"
        ])
        # Return to continue processing
        WireGuardService._run_iptables("filter", [
            "-A", input_chain, "-j", "RETURN"
        ])
        
        # 3. Add rules to FORWARD chain
        # NOTE: We DON'T add blanket -i interface ACCEPT here because:
        # - Traffic FROM VPN clients should go through group rules → default policy
        # - Only traffic TO VPN clients (responses) should be allowed unconditionally
        WireGuardService._run_iptables("filter", [
            "-A", forward_chain, "-o", interface, "-j", "ACCEPT"
        ])
        
        # 4. Add default policy at end (ACCEPT by default, can be changed per-instance)
        # This ensures connectivity even before groups are configured
        WireGuardService._run_iptables("filter", [
            "-A", forward_chain, "-j", "ACCEPT"
        ])
        
        # 4. Add rules to NAT chain
        # Masquerade traffic from VPN subnet going to WAN
        WireGuardService._run_iptables("nat", [
            "-A", nat_chain, "-s", subnet, "-o", wan_interface, "-j", "MASQUERADE"
        ])
        WireGuardService._run_iptables("nat", [
            "-A", nat_chain, "-j", "RETURN"
        ])
        
        # 5. Link instance chains to module main chains
        WireGuardService._ensure_jump_rule(WireGuardService.WG_INPUT_CHAIN, input_chain, "filter")
        WireGuardService._ensure_jump_rule(WireGuardService.WG_FORWARD_CHAIN, forward_chain, "filter")
        WireGuardService._ensure_jump_rule(WireGuardService.WG_NAT_CHAIN, nat_chain, "nat")
        
        logger.info(f"Firewall rules applied for WireGuard instance {instance_id}")
        logger.info(f"  Chains created: {input_chain}, {forward_chain}, {nat_chain}")
        logger.info(f"  Linked to: WG_INPUT, WG_FORWARD, WG_NAT")
        return True
    
    @staticmethod
    def remove_instance_firewall_rules(instance_id: str) -> bool:
        """
        Remove firewall rules for a WireGuard instance.
        """
        # Instance chain names - strip wg_ prefix if present
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        input_chain = f"WG_{chain_id}_INPUT"
        forward_chain = f"WG_{chain_id}_FWD"
        nat_chain = f"WG_{chain_id}_NAT"
        
        logger.info(f"Removing firewall rules for WireGuard instance {instance_id}")
        
        # Remove jumps from module main chains
        WireGuardService._remove_jump_rule(WireGuardService.WG_INPUT_CHAIN, input_chain, "filter")
        WireGuardService._remove_jump_rule(WireGuardService.WG_FORWARD_CHAIN, forward_chain, "filter")
        WireGuardService._remove_jump_rule(WireGuardService.WG_NAT_CHAIN, nat_chain, "nat")
        
        # Delete instance chains
        WireGuardService._delete_chain(input_chain, "filter")
        WireGuardService._delete_chain(forward_chain, "filter")
        WireGuardService._delete_chain(nat_chain, "nat")
        
        logger.info(f"Firewall rules removed for WireGuard instance {instance_id}")
        return True
    
    @staticmethod
    async def remove_all_group_chains(instance_id: str, db) -> bool:
        """
        Remove all group chains for an instance.
        Should be called before deleting an instance.
        """
        from sqlalchemy import select
        from .models import WgGroup
        
        logger.info(f"Removing group chains for instance {instance_id}")
        
        # Get all groups for this instance
        result = await db.execute(select(WgGroup).where(WgGroup.instance_id == instance_id))
        groups = result.scalars().all()
        
        for group in groups:
            group_chain = f"WG_GRP_{group.id.replace(instance_id + '_', '')}"
            WireGuardService._delete_chain(group_chain, "filter")
            logger.info(f"  Deleted chain: {group_chain}")
        
        return True
    
    @staticmethod
    async def apply_group_firewall_rules(instance_id: str, db) -> bool:
        """
        Apply firewall rules for all groups in an instance.
        
        Chain hierarchy:
        WG_{instance}_FWD → WG_GRP_{group_id} → rules → default policy
        
        For each group member, traffic from their IP is matched and jumped
        to the group's chain where rules are applied.
        """
        from sqlalchemy import select
        from .models import WgInstance, WgGroup, WgGroupMember, WgGroupRule, WgClient
        
        logger.info(f"Applying group firewall rules for instance {instance_id}")
        
        # Get instance
        result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
        instance = result.scalar_one_or_none()
        if not instance:
            logger.error(f"Instance {instance_id} not found")
            return False
        
        # Instance forward chain name - strip wg_ prefix if present
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        instance_fwd_chain = f"WG_{chain_id}_FWD"
        
        # Get all groups for this instance
        result = await db.execute(select(WgGroup).where(WgGroup.instance_id == instance_id))
        groups = result.scalars().all()
        
        for group in groups:
            group_chain = f"WG_GRP_{group.id.replace(instance_id + '_', '')}"  # Shorter name
            
            # Create group chain
            WireGuardService._create_or_flush_chain(group_chain, "filter")
            
            # Get rules for this group (ordered)
            result = await db.execute(
                select(WgGroupRule)
                .where(WgGroupRule.group_id == group.id)
                .order_by(WgGroupRule.order)
            )
            rules = result.scalars().all()
            
            # Add rules to group chain
            for rule in rules:
                args = ["-A", group_chain]
                
                # Protocol
                if rule.protocol and rule.protocol != "all":
                    args.extend(["-p", rule.protocol])
                
                # Destination
                if rule.destination and rule.destination != "0.0.0.0/0":
                    args.extend(["-d", rule.destination])
                
                # Port (only for tcp/udp)
                if rule.port and rule.protocol in ("tcp", "udp"):
                    args.extend(["--dport", rule.port])
                
                # Action
                args.extend(["-j", rule.action])
                
                WireGuardService._run_iptables("filter", args)
            
            # Group chain ends with RETURN - default policy is at instance level
            WireGuardService._run_iptables("filter", [
                "-A", group_chain, "-j", "RETURN"
            ])
            
            # Get members of this group
            result = await db.execute(
                select(WgGroupMember, WgClient)
                .join(WgClient, WgGroupMember.client_id == WgClient.id)
                .where(WgGroupMember.group_id == group.id)
            )
            members = result.all()
            
            # For each member, add a jump rule from instance chain to group chain
            for member, client in members:
                client_ip = client.allocated_ip.split('/')[0]  # Remove /32
                
                # Add jump rule matching source IP at beginning of instance chain
                # First remove any existing rule for this IP
                WireGuardService._run_iptables("filter", [
                    "-D", instance_fwd_chain, "-s", client_ip, "-j", group_chain
                ], suppress_errors=True)
                
                # Insert at position 1 (before the default ACCEPT rules)
                WireGuardService._run_iptables("filter", [
                    "-I", instance_fwd_chain, "1", "-s", client_ip, "-j", group_chain
                ])
                
                logger.info(f"  Added rule: {client_ip} -> {group_chain}")
        
        # After processing all groups, update the instance forward chain to use the default policy
        # Remove old generic rules (they'll be at the end)
        WireGuardService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-j", "ACCEPT"
        ], suppress_errors=True)
        WireGuardService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-j", "RETURN"
        ], suppress_errors=True)
        WireGuardService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-j", "DROP"
        ], suppress_errors=True)
        
        # Add the instance default policy at the end (for non-grouped clients)
        WireGuardService._run_iptables("filter", [
            "-A", instance_fwd_chain, "-j", instance.firewall_default_policy
        ])
        
        logger.info(f"Group firewall rules applied for instance {instance_id}")
        logger.info(f"  Default policy for non-grouped clients: {instance.firewall_default_policy}")
        return True
    
    @staticmethod
    async def remove_group_firewall_rules(instance_id: str, group_id: str, db) -> bool:
        """Remove firewall rules for a specific group."""
        from sqlalchemy import select
        from .models import WgGroupMember, WgClient
        
        instance_fwd_chain = f"WG_{instance_id}_FWD"
        group_chain = f"WG_GRP_{group_id.replace(instance_id + '_', '')}"
        
        # Get members to remove their jump rules
        result = await db.execute(
            select(WgGroupMember, WgClient)
            .join(WgClient, WgGroupMember.client_id == WgClient.id)
            .where(WgGroupMember.group_id == group_id)
        )
        members = result.all()
        
        for member, client in members:
            client_ip = client.allocated_ip.split('/')[0]
            WireGuardService._run_iptables("filter", [
                "-D", instance_fwd_chain, "-s", client_ip, "-j", group_chain
            ], suppress_errors=True)
        
        # Delete group chain
        WireGuardService._delete_chain(group_chain, "filter")
        
        return True


wireguard_service = WireGuardService()
