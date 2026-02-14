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
from core.network.utils import get_public_ip, get_default_interface
from core.firewall import iptables as core_iptables

logger = logging.getLogger(__name__)
WIREGUARD_CONFIG_DIR = Path("/etc/wireguard")


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
        """Generate client config file content.
        
        Uses per-client overrides if set, otherwise falls back to instance defaults.
        """
        # Per-client AllowedIPs override or instance default
        if client.allowed_ips:
            # Per-client override takes priority
            allowed_ips = client.allowed_ips
        elif instance.tunnel_mode == "split" and instance.routes:
            # Split tunnel: use routes from instance (only configured routes)
            routes = [r.get('network', '') for r in instance.routes if r.get('network')]
            allowed_ips = ", ".join(routes)
        elif instance.default_allowed_ips and instance.default_allowed_ips != "0.0.0.0/0, ::/0":
            # User explicitly set custom default_allowed_ips
            allowed_ips = instance.default_allowed_ips
        else:
            # Full tunnel or no routes defined
            allowed_ips = "0.0.0.0/0, ::/0"
        
        # Per-client DNS override or instance default
        if client.dns:
            dns = client.dns
        else:
            dns = ", ".join(instance.dns_servers) if instance.dns_servers else "8.8.8.8, 1.1.1.1"
        
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
        """Execute an iptables command using core wrapper."""
        # Use core iptables wrapper which handles error parsing and logging
        # We catch IptablesError here to maintain the boolean return signature expected by WG module
        try:
            success, _ = core_iptables._run_iptables(table, args, suppress_errors=suppress_errors)
            return success
        except core_iptables.IptablesError:
            # If core raises exception (suppress_errors=False), it means it failed and logged/parsed it.
            # We return False to the caller.
            return False
        except Exception as e:
            if not suppress_errors:
                logger.error(f"Unexpected iptables error: {e}")
            return False
    
    @staticmethod
    def _get_group_chain_name(chain_id: str, group_name: str) -> str:
        """Generate a group chain name that fits within iptables 29-char limit.
        
        Format: WG_GRP_{instance_8chars}_{group_8chars}
        Total: 7 + 8 + 1 + 8 = 24 chars max
        
        Args:
            chain_id: Instance chain ID (e.g., "palestra")
            group_name: Group name (e.g., "allenatori")
            
        Returns:
            Chain name like "WG_GRP_palestra_allenato"
        """
        # Truncate to 8 chars each to ensure we stay under 29 char limit
        inst_part = chain_id[:8]
        grp_part = group_name[:8]
        return f"WG_GRP_{inst_part}_{grp_part}"
    
    IPTABLES_MAX_CHAIN_LEN = 29  # iptables chain name limit
    
    @staticmethod
    def _create_or_flush_chain(chain_name: str, table: str = "filter") -> bool:
        """Create chain if doesn't exist, or flush it.
        
        Raises ValueError if chain name exceeds iptables limit.
        """
        if len(chain_name) > WireGuardService.IPTABLES_MAX_CHAIN_LEN:
            raise ValueError(
                f"Nome chain iptables troppo lungo: '{chain_name}' ({len(chain_name)} chars). "
                f"Massimo consentito: {WireGuardService.IPTABLES_MAX_CHAIN_LEN} caratteri."
            )
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
        """Ensure a jump rule exists from source to target chain.
        
        Inserts the jump BEFORE any RETURN rule to ensure proper ordering.
        """
        # Check if rule already exists using -C (check)
        result = subprocess.run(
            ["iptables", "-t", table, "-C", source_chain, "-j", target_chain],
            capture_output=True
        )
        if result.returncode == 0:
            return True  # Already exists
        
        # Find position of RETURN rule (if any) to insert before it
        result = subprocess.run(
            ["iptables", "-t", table, "-S", source_chain],
            capture_output=True,
            text=True
        )
        
        # Parse rules to find RETURN position
        # -S output: first line is -N/-P, then -A lines are rules numbered 1, 2, ...
        lines = result.stdout.strip().split('\n') if result.returncode == 0 else []
        return_pos = None
        for i, line in enumerate(lines):
            if '-j RETURN' in line:
                return_pos = i  # This is the iptables rule position (1-indexed, accounting for -N line at 0)
                break
        
        if return_pos is not None:
            # Insert before RETURN (position = line index since -N is at 0)
            return WireGuardService._run_iptables(table, ["-I", source_chain, str(return_pos), "-j", target_chain])
        else:
            # No RETURN, just append
            return WireGuardService._run_iptables(table, ["-A", source_chain, "-j", target_chain])
    
    @staticmethod
    def _ensure_interface_jump_rule(
        source_chain: str, 
        target_chain: str, 
        table: str = "filter",
        input_interface: str = None,
        output_interface: str = None
    ) -> bool:
        """Ensure an interface-filtered jump rule exists from source to target chain.
        
        Creates a jump rule filtered by input or output interface.
        Inserts the jump BEFORE any RETURN rule to ensure proper ordering.
        """
        # Build the rule args
        rule_args = []
        if input_interface:
            rule_args.extend(["-i", input_interface])
        if output_interface:
            rule_args.extend(["-o", output_interface])
        rule_args.extend(["-j", target_chain])
        
        # Check if rule already exists using -C (check)
        check_cmd = ["iptables", "-t", table, "-C", source_chain] + rule_args
        result = subprocess.run(check_cmd, capture_output=True)
        if result.returncode == 0:
            return True  # Already exists
        
        # Find position of RETURN rule (if any) to insert before it
        result = subprocess.run(
            ["iptables", "-t", table, "-S", source_chain],
            capture_output=True,
            text=True
        )
        
        # Parse rules to find RETURN position
        lines = result.stdout.strip().split('\n') if result.returncode == 0 else []
        return_pos = None
        for i, line in enumerate(lines):
            if '-j RETURN' in line:
                return_pos = i
                break
        
        if return_pos is not None:
            # Insert before RETURN
            return WireGuardService._run_iptables(table, ["-I", source_chain, str(return_pos)] + rule_args)
        else:
            # No RETURN, just append
            return WireGuardService._run_iptables(table, ["-A", source_chain] + rule_args)
    
    @staticmethod
    def _ensure_direct_accept_rule(
        chain: str, 
        table: str = "filter",
        input_interface: str = None,
        output_interface: str = None
    ) -> bool:
        """Ensure a direct ACCEPT rule exists for interface traffic.
        
        Creates an ACCEPT rule filtered by input or output interface.
        Inserts the rule BEFORE any RETURN rule to ensure proper ordering.
        Used for response traffic to VPN clients.
        """
        # Build the rule args
        rule_args = []
        if input_interface:
            rule_args.extend(["-i", input_interface])
        if output_interface:
            rule_args.extend(["-o", output_interface])
        rule_args.extend(["-j", "ACCEPT"])
        
        # Check if rule already exists using -C (check)
        check_cmd = ["iptables", "-t", table, "-C", chain] + rule_args
        result = subprocess.run(check_cmd, capture_output=True)
        if result.returncode == 0:
            return True  # Already exists
        
        # Find position of RETURN rule (if any) to insert before it
        result = subprocess.run(
            ["iptables", "-t", table, "-S", chain],
            capture_output=True,
            text=True
        )
        
        # Parse rules to find RETURN position
        lines = result.stdout.strip().split('\n') if result.returncode == 0 else []
        return_pos = None
        for i, line in enumerate(lines):
            if '-j RETURN' in line:
                return_pos = i
                break
        
        if return_pos is not None:
            # Insert before RETURN
            return WireGuardService._run_iptables(table, ["-I", chain, str(return_pos)] + rule_args)
        else:
            # No RETURN, just append
            return WireGuardService._run_iptables(table, ["-A", chain] + rule_args)
    
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
    def _remove_interface_jump_rule(
        source_chain: str, 
        target_chain: str, 
        table: str = "filter",
        input_interface: str = None,
        output_interface: str = None
    ) -> bool:
        """Remove an interface-filtered jump rule."""
        rule_args = ["-D", source_chain]
        if input_interface:
            rule_args.extend(["-i", input_interface])
        if output_interface:
            rule_args.extend(["-o", output_interface])
        rule_args.extend(["-j", target_chain])
        return WireGuardService._run_iptables(table, rule_args, suppress_errors=True)
    
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
        
        Note: For database registration and linking to system chains, usage of 
        register_module_chains() with the Core Orchestrator is required.
        """
        logger.info("Initializing WireGuard module firewall chains...")
        
        # 1. Create module main chains (don't flush - preserve existing instance rules)
        WireGuardService._create_chain_if_not_exists(WireGuardService.WG_INPUT_CHAIN, "filter")
        WireGuardService._create_chain_if_not_exists(WireGuardService.WG_FORWARD_CHAIN, "filter")
        WireGuardService._create_chain_if_not_exists(WireGuardService.WG_NAT_CHAIN, "nat")
        
        # Ensure RETURN rule at end of chains to allow proceeding to next chains if no match
        # (This is important if we have multiple modules chained)
        # First remove any existing RETURN rule to avoid duplicates
        WireGuardService._run_iptables("filter", ["-D", WireGuardService.WG_INPUT_CHAIN, "-j", "RETURN"], suppress_errors=True)
        WireGuardService._run_iptables("filter", ["-D", WireGuardService.WG_FORWARD_CHAIN, "-j", "RETURN"], suppress_errors=True)
        WireGuardService._run_iptables("nat", ["-D", WireGuardService.WG_NAT_CHAIN, "-j", "RETURN"], suppress_errors=True)
        
        # Then append it to be at the end
        WireGuardService._run_iptables("filter", ["-A", WireGuardService.WG_INPUT_CHAIN, "-j", "RETURN"])
        WireGuardService._run_iptables("filter", ["-A", WireGuardService.WG_FORWARD_CHAIN, "-j", "RETURN"])
        WireGuardService._run_iptables("nat", ["-A", WireGuardService.WG_NAT_CHAIN, "-j", "RETURN"])
        
        logger.info("WireGuard iptables chains created")
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
    def apply_instance_firewall_rules(
        instance_id: str, 
        port: int, 
        interface: str, 
        subnet: str,
        tunnel_mode: str = "full",
        routes: list = None,
        firewall_default_policy: str = "ACCEPT"
    ) -> bool:
        """
        Apply firewall rules for a WireGuard instance.
        
        Creates instance-specific chains:
        - WG_{id}_INPUT: Allows UDP port and interface traffic
        - WG_{id}_FWD: Allows forwarding to/from VPN interface
        - WG_{id}_NAT: Masquerades traffic from VPN subnet
        
        For split tunnel mode, FORWARD rules are restricted to only allow
        traffic to the specified routes. For full tunnel, all traffic is allowed.
        
        And links them to the module main chains (WG_INPUT, WG_FORWARD, WG_NAT).
        """
        # Ensure module chains are initialized first
        WireGuardService.initialize_module_firewall_chains()
        
        # Instance chain names - strip wg_ prefix if present to avoid WG_wg_name redundancy
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        input_chain = f"WG_{chain_id}_INPUT"
        forward_chain = f"WG_{chain_id}_FWD"
        nat_chain = f"WG_{chain_id}_NAT"
        
        wan_interface = get_default_interface() or "eth0"
        
        logger.info(f"Applying firewall rules for WireGuard instance {instance_id} (mode: {tunnel_mode})")
        
        # 1. Create/flush instance chains
        WireGuardService._create_or_flush_chain(input_chain, "filter")
        WireGuardService._create_or_flush_chain(forward_chain, "filter")
        WireGuardService._create_or_flush_chain(nat_chain, "nat")
        
        # 2. Add rules to INPUT chain
        # Allow UDP traffic on WireGuard port
        WireGuardService._run_iptables("filter", [
            "-A", input_chain, "-p", "udp", "--dport", str(port), "-j", "ACCEPT"
        ])
        # Allow all traffic from WireGuard interface (to Server services)
        WireGuardService._run_iptables("filter", [
            "-A", input_chain, "-i", interface, "-j", "ACCEPT"
        ])
        # Return to continue processing
        WireGuardService._run_iptables("filter", [
            "-A", input_chain, "-j", "RETURN"
        ])
        
        # 3. Add rules to FORWARD chain
        # Note: Traffic TO VPN clients (responses) is handled at module level, not here
        
        # Apply default policy for all traffic from VPN
        # Groups handle fine-grained control, default policy handles everything else
        # (no per-route ACCEPT rules - keep it simple, groups are for special cases)
        WireGuardService._run_iptables("filter", [
            "-A", forward_chain, "-i", interface, "-j", firewall_default_policy
        ])
        logger.info(f"  Traffic from VPN policy: {firewall_default_policy}")
        
        # 4. Add rules to NAT chain
        if tunnel_mode == "split" and routes:
            # Split tunnel: Only masquerade traffic to specified networks
            for route in routes:
                network = route.get('network') if isinstance(route, dict) else route
                # Use route-specific interface if specified, otherwise use default WAN
                out_interface = route.get('interface') if isinstance(route, dict) and route.get('interface') else wan_interface
                if network:
                    WireGuardService._run_iptables("nat", [
                        "-A", nat_chain, "-s", subnet, "-d", network, "-o", out_interface, "-j", "MASQUERADE"
                    ])
                    logger.info(f"    Added NAT rule: {subnet} -> {network} via {out_interface}")
        else:
            # Full tunnel: Masquerade all traffic from VPN subnet
            WireGuardService._run_iptables("nat", [
                "-A", nat_chain, "-s", subnet, "-o", wan_interface, "-j", "MASQUERADE"
            ])
        
        WireGuardService._run_iptables("nat", [
            "-A", nat_chain, "-j", "RETURN"
        ])
        
        # 5. Link instance chains to module main chains
        WireGuardService._ensure_jump_rule(WireGuardService.WG_INPUT_CHAIN, input_chain, "filter")
        # FORWARD chain: Use interface filtering to isolate instance traffic
        # Jump for traffic FROM VPN (input interface)
        WireGuardService._ensure_interface_jump_rule(
            WireGuardService.WG_FORWARD_CHAIN, forward_chain, "filter",
            input_interface=interface
        )
        # ACCEPT responses TO VPN clients (output interface) - directly in module chain
        # This is simpler and more efficient than going through instance chain
        WireGuardService._ensure_direct_accept_rule(
            WireGuardService.WG_FORWARD_CHAIN, "filter",
            output_interface=interface
        )
        WireGuardService._ensure_jump_rule(WireGuardService.WG_NAT_CHAIN, nat_chain, "nat")
        
        logger.info(f"Firewall rules applied for WireGuard instance {instance_id}")
        logger.info(f"  Chains created: {input_chain}, {forward_chain}, {nat_chain}")
        logger.info(f"  Linked to: WG_INPUT, WG_FORWARD, WG_NAT")
        return True
    
    @staticmethod
    def remove_instance_firewall_rules(instance_id: str, interface: str = None) -> bool:
        """
        Remove firewall rules for a WireGuard instance.
        
        Args:
            instance_id: The instance ID
            interface: The VPN interface name (e.g., wg_casa). If not provided,
                      falls back to non-interface-filtered removal.
        """
        # Instance chain names - strip wg_ prefix if present
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        input_chain = f"WG_{chain_id}_INPUT"
        forward_chain = f"WG_{chain_id}_FWD"
        nat_chain = f"WG_{chain_id}_NAT"
        
        logger.info(f"Removing firewall rules for WireGuard instance {instance_id}")
        
        # Remove jumps from module main chains
        WireGuardService._remove_jump_rule(WireGuardService.WG_INPUT_CHAIN, input_chain, "filter")
        
        # Remove FORWARD jumps - try both interface-filtered and non-filtered for compatibility
        if interface:
            WireGuardService._remove_interface_jump_rule(
                WireGuardService.WG_FORWARD_CHAIN, forward_chain, "filter",
                input_interface=interface
            )
            WireGuardService._remove_interface_jump_rule(
                WireGuardService.WG_FORWARD_CHAIN, forward_chain, "filter",
                output_interface=interface
            )
            
            # Remove direct ACCEPT rule for output interface (response traffic)
            # This corresponds to _ensure_direct_accept_rule usage in apply_instance_firewall_rules
            WireGuardService._run_iptables("filter", [
                "-D", WireGuardService.WG_FORWARD_CHAIN, 
                "-o", interface, 
                "-j", "ACCEPT"
            ], suppress_errors=True)
        # Also try removing non-filtered jump (for legacy cleanup)
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
        
        # chain_id for naming consistency
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        
        for group in groups:
            # Group chain name with truncation to fit iptables limit
            group_name = group.id.replace(instance_id + '_', '')
            group_chain = WireGuardService._get_group_chain_name(chain_id, group_name)
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
        
        # IMPORTANT: Remove ALL existing group jump rules from instance chain first
        # This ensures orphan rules (from deleted clients) are cleaned up
        success, output = WireGuardService._run_iptables_with_output(
            "filter", ["-S", instance_fwd_chain], suppress_errors=True
        )
        if success and output:
            for line in output.strip().split('\n'):
                # Match rules jumping to group chains: -s IP -j WG_GRP_*
                if ' -j WG_GRP_' in line and ' -s ' in line:
                    # Extract the rule parts to delete it
                    # Line format: -A WG_casa_FWD -s 10.8.0.3/32 -j WG_GRP_casa_figli
                    parts = line.split()
                    if len(parts) >= 6 and parts[0] == '-A':
                        source_ip = parts[3]  # -s value
                        target_chain = parts[5]  # -j value
                        WireGuardService._run_iptables("filter", [
                            "-D", instance_fwd_chain, "-s", source_ip, "-j", target_chain
                        ], suppress_errors=True)
        
        # Get all groups for this instance, ordered by priority (lower order = higher priority)
        # We process in DESC order because we insert at position 1 (LIFO), so the last processed (lowest order) ends up first.
        result = await db.execute(
            select(WgGroup).where(WgGroup.instance_id == instance_id).order_by(WgGroup.order.desc())
        )
        groups = result.scalars().all()
        
        for group in groups:
            # Group chain name with truncation to fit iptables limit
            group_name = group.id.replace(instance_id + '_', '')
            group_chain = WireGuardService._get_group_chain_name(chain_id, group_name)
            
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
                
                # Insert at position 1 (before the default ACCEPT rules)
                WireGuardService._run_iptables("filter", [
                    "-I", instance_fwd_chain, "1", "-s", client_ip, "-j", group_chain
                ])
                
                logger.info(f"  Added rule: {client_ip} -> {group_chain}")
        
        # After processing all groups, update the instance forward chain to use the default policy
        # Remove old generic rules (both specific interface allow/drop and generic allow/drop)
        WireGuardService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-i", instance.interface, "-j", "ACCEPT"
        ], suppress_errors=True)
        WireGuardService._run_iptables("filter", [
            "-D", instance_fwd_chain, "-i", instance.interface, "-j", "DROP"
        ], suppress_errors=True)
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
    async def remove_group_firewall_rules(instance_id: str, group_id: str, group_name: str, db) -> bool:
        """Remove firewall rules for a specific group."""
        from sqlalchemy import select
        from .models import WgGroupMember, WgClient
        
        # Strip instance prefix from instance_id for chain naming
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        instance_fwd_chain = f"WG_{chain_id}_FWD"
        # Group chain name with truncation to fit iptables limit
        group_chain = WireGuardService._get_group_chain_name(chain_id, group_name)
        
        logger.info(f"Removing firewall rules for group {group_name} (chain: {group_chain})")
        
        # Get members to remove their jump rules
        result = await db.execute(
            select(WgGroupMember, WgClient)
            .join(WgClient, WgGroupMember.client_id == WgClient.id)
            .where(WgGroupMember.group_id == group_id)
        )
        members = result.all()
        
        for member, client in members:
            client_ip = client.allocated_ip.split('/')[0] + "/32"
            logger.info(f"  Removing jump rule: {client_ip} -> {group_chain}")
            WireGuardService._run_iptables("filter", [
                "-D", instance_fwd_chain, "-s", client_ip, "-j", group_chain
            ], suppress_errors=True)
        
        # Delete group chain
        logger.info(f"  Deleting chain: {group_chain}")
        WireGuardService._delete_chain(group_chain, "filter")
        
        return True
    
    # --- Per-Client Firewall Enforcement ---
    
    @staticmethod
    def _get_client_chain_name(instance_id: str, client_name: str) -> str:
        """Generate client chain name (max 29 chars).
        
        Format: WG_CLI_{inst_6}_{cli_10}
        Total: 7 + 6 + 1 + 10 = 24 chars max
        """
        inst_part = instance_id.replace('wg_', '')[:6]
        # Sanitize client name: replace invalid chars with underscore
        safe_name = ''.join(c if c.isalnum() else '_' for c in client_name)[:10]
        return f"WG_CLI_{inst_part}_{safe_name}"
    
    @staticmethod
    def get_effective_client_config(client, instance) -> dict:
        """Get effective config for a client (with fallback to instance defaults).
        
        Returns dict with effective_allowed_ips, effective_dns, has_overrides.
        """
        effective_allowed_ips = client.allowed_ips or instance.default_allowed_ips or "0.0.0.0/0, ::/0"
        default_dns = ", ".join(instance.dns_servers) if instance.dns_servers else "8.8.8.8, 1.1.1.1"
        effective_dns = client.dns or default_dns
        has_overrides = bool(client.allowed_ips or client.dns)
        
        return {
            "effective_allowed_ips": effective_allowed_ips,
            "effective_dns": effective_dns,
            "has_overrides": has_overrides
        }
    
    @staticmethod
    def apply_client_firewall_rules(
        instance_id: str,
        client_ip: str,
        client_name: str,
        allowed_ips: str,
        instance_subnet: str = None,
        has_overrides: bool = False
    ) -> bool:
        """Apply per-client firewall enforcement.
        
        Creates chain WG_CLI_{instance}_{client} with:
        - ACCEPT for each network in allowed_ips
        - DROP for everything else (if not full tunnel)
        
        Chain is jumped to from WG_{instance}_FWD after group chains.
        
        OPTIMIZATION: Only creates chain if has_overrides=True.
        Standard clients (no overrides) fall through to generic instance rules.
        """
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        client_chain = WireGuardService._get_client_chain_name(instance_id, client_name)
        instance_fwd = f"WG_{chain_id}_FWD"
        client_ip_clean = client_ip.split('/')[0]
        
        # If client has NO overrides, remove any existing chain and return
        if not has_overrides:
            logger.info(f"Client {client_name} has no overrides, removing chain if exists")
            # Remove jump rule
            subprocess.run([
                "iptables", "-t", "filter", "-D", instance_fwd,
                "-s", client_ip_clean, "-j", client_chain
            ], capture_output=True, check=False)
            # Delete chain
            WireGuardService._delete_chain(client_chain, "filter")
            return True
        
        # Parse allowed_ips (comma-separated CIDRs)
        networks = [n.strip() for n in allowed_ips.split(',') if n.strip()]
        
        # Filter out instance subnet if provided (redundant in forward chain for inter-client/server traffic)
        if instance_subnet:
            networks = [n for n in networks if n != instance_subnet]
            
        is_full_tunnel = any(n in ["0.0.0.0/0", "::/0"] for n in networks)
        
        logger.info(f"Applying client firewall for {client_name} (IP: {client_ip}, chain: {client_chain})")
        logger.info(f"  AllowedIPs: {allowed_ips}, Full tunnel: {is_full_tunnel}")
        
        # Create/flush client chain
        WireGuardService._create_or_flush_chain(client_chain, "filter")
        
        if is_full_tunnel:
            # Full tunnel = simple ACCEPT all (no restrictions beyond groups)
            WireGuardService._run_iptables("filter", [
                "-A", client_chain, "-j", "ACCEPT"
            ])
            logger.info(f"  Full tunnel: ACCEPT all traffic")
        else:
            # Add ACCEPT for each allowed network
            for network in networks:
                if network and network not in ["::/0"]:  # Skip IPv6 for now
                    WireGuardService._run_iptables("filter", [
                        "-A", client_chain, "-d", network, "-j", "ACCEPT"
                    ])
                    logger.info(f"  Added rule: -d {network} -j ACCEPT")
            
            # DROP everything else (enforce allowed_ips)
            WireGuardService._run_iptables("filter", [
                "-A", client_chain, "-j", "DROP"
            ])
            logger.info(f"  Final rule: -j DROP (enforce allowed routes)")
        
        # Remove any existing jump rule for this client
        client_ip_clean = client_ip.split('/')[0]
        subprocess.run([
            "iptables", "-t", "filter", "-D", instance_fwd,
            "-s", client_ip_clean, "-j", client_chain
        ], capture_output=True, check=False)
        
        # Insert jump rule in instance FORWARD chain.
        # Order in chain should be:
        # 1. Group jumps (-s client_ip -j WG_GRP_*)
        # 2. Client jumps (-s client_ip -j WG_CLI_*)
        # 3. Split tunnel -d route rules
        # 4. Default policy (-j ACCEPT or -j DROP)
        #
        # We find the position of the first -d (destination) rule and insert before it.
        # If no -d rules, we find the default policy rule and insert before it.
        success, output = WireGuardService._run_iptables_with_output(
            "filter", ["-S", instance_fwd], suppress_errors=True
        )
        
        insert_pos = None
        if success and output:
            lines = output.strip().split('\n')
            for i, line in enumerate(lines):
                # Skip first line (-N chain_name) and find first -d rule
                if i > 0 and ' -d ' in line and ' -j ACCEPT' in line:
                    insert_pos = i  # iptables positions are 1-indexed excluding -N line
                    break
                # Also stop before final DROP/ACCEPT policy rules (no -d, no -s = generic policy)
                if i > 0 and (line.endswith('-j DROP') or line.endswith('-j ACCEPT')) and ' -d ' not in line and ' -s ' not in line:
                    insert_pos = i
                    break
        
        if insert_pos:
            WireGuardService._run_iptables("filter", [
                "-I", instance_fwd, str(insert_pos), "-s", client_ip_clean, "-j", client_chain
            ])
            logger.info(f"  Jump rule inserted at position {insert_pos}: -s {client_ip_clean} -j {client_chain}")
        else:
            # Fallback to append
            WireGuardService._run_iptables("filter", [
                "-A", instance_fwd, "-s", client_ip_clean, "-j", client_chain
            ])
            logger.info(f"  Jump rule appended: -s {client_ip_clean} -j {client_chain}")
        
        return True
    
    @staticmethod
    def get_effective_client_config(client, instance) -> dict:
        """Calculate effective AllowedIPs and DNS for a client.
        
        Priority:
        1. Client override (if set)
        2. Instance default (if set)
        3. Legacy fallback based on tunnel_mode
        
        Returns dict with effective_allowed_ips, effective_dns, has_overrides.
        """
        # Calculate effective AllowedIPs
        if client.allowed_ips:
            effective_allowed_ips = client.allowed_ips
            has_ips_override = True
        elif instance.default_allowed_ips:
            effective_allowed_ips = instance.default_allowed_ips
            has_ips_override = False
        elif instance.tunnel_mode == "full":
            effective_allowed_ips = "0.0.0.0/0, ::/0"
            has_ips_override = False
        else:
            # Split tunnel fallback
            routes = [r.get('network', '') for r in (instance.routes or []) if r.get('network')]
            routes.append(instance.subnet)
            effective_allowed_ips = ", ".join(routes)
            has_ips_override = False
        
        # Calculate effective DNS
        if client.dns:
            effective_dns = client.dns
            has_dns_override = True
        elif instance.dns_servers:
            effective_dns = ", ".join(instance.dns_servers)
            has_dns_override = False
        else:
            effective_dns = "8.8.8.8, 1.1.1.1"
            has_dns_override = False
        
        return {
            "effective_allowed_ips": effective_allowed_ips,
            "effective_dns": effective_dns,
            "has_overrides": has_ips_override or has_dns_override
        }
    
    @staticmethod
    def remove_client_firewall_rules(instance_id: str, client_ip: str, client_name: str) -> bool:
        """Remove client firewall chain and jump rule."""
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        client_chain = WireGuardService._get_client_chain_name(instance_id, client_name)
        instance_fwd = f"WG_{chain_id}_FWD"
        
        logger.info(f"Removing client firewall for {client_name} (chain: {client_chain})")
        
        # Remove jump rule
        client_ip_clean = client_ip.split('/')[0]
        subprocess.run([
            "iptables", "-t", "filter", "-D", instance_fwd,
            "-s", client_ip_clean, "-j", client_chain
        ], capture_output=True, check=False)
        
        # Delete chain
        WireGuardService._delete_chain(client_chain, "filter")
        
        return True
    
    @staticmethod
    async def apply_all_client_firewall_rules(instance_id: str, db) -> bool:
        """Apply firewall rules for all clients in an instance.
        
        Should be called after instance start or when updating defaults.
        """
        from sqlalchemy import select
        from .models import WgInstance, WgClient
        
        logger.info(f"Applying all client firewall rules for instance {instance_id}")
        
        # Get instance
        result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
        instance = result.scalar_one_or_none()
        if not instance:
            logger.error(f"Instance {instance_id} not found")
            return False
        
        # Get all clients
        result = await db.execute(select(WgClient).where(WgClient.instance_id == instance_id))
        clients = result.scalars().all()
        
        for client in clients:
            # Get effective allowed_ips
            effective = WireGuardService.get_effective_client_config(client, instance)
            
            # Apply firewall rules
            WireGuardService.apply_client_firewall_rules(
                instance_id,
                client.allocated_ip,
                client.name,
                effective["effective_allowed_ips"],
                instance_subnet=instance.subnet,
                has_overrides=effective["has_overrides"]
            )
        
        logger.info(f"Applied firewall rules for {len(clients)} clients")
        return True
    
    @staticmethod
    async def remove_all_client_chains(instance_id: str, db) -> bool:
        """Remove all client firewall chains for an instance.
        
        Called when instance is stopped.
        """
        from sqlalchemy import select
        from .models import WgInstance, WgClient
        
        logger.info(f"Removing all client firewall chains for instance {instance_id}")
        
        # Get instance
        result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
        instance = result.scalar_one_or_none()
        if not instance:
            logger.error(f"Instance {instance_id} not found")
            return False
        
        chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
        instance_fwd = f"WG_{chain_id}_FWD"
        
        # Get all clients
        result = await db.execute(select(WgClient).where(WgClient.instance_id == instance_id))
        clients = result.scalars().all()
        
        for client in clients:
            client_chain = WireGuardService._get_client_chain_name(instance_id, client.name)
            client_ip_clean = client.allocated_ip.split('/')[0]
            
            # Remove jump rule
            subprocess.run([
                "iptables", "-t", "filter", "-D", instance_fwd,
                "-s", client_ip_clean, "-j", client_chain
            ], capture_output=True, check=False)
            
            # Delete chain
            WireGuardService._delete_chain(client_chain, "filter")
        
        logger.info(f"Removed firewall chains for {len(clients)} clients")
        return True


wireguard_service = WireGuardService()
