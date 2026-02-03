"""
WireGuard Pre-Uninstall Hook

Executed before the module is uninstalled:
- Stops all WireGuard interfaces
- Removes all firewall chains (module, instance, and group chains)
- Removes configuration directory
"""
import subprocess
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


async def run():
    """Pre-uninstall hook for WireGuard module."""
    logger.info("Running WireGuard pre-uninstall hook")
    
    # 1. Stop all WireGuard interfaces
    try:
        result = subprocess.run(
            ["wg", "show", "interfaces"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0 and result.stdout.strip():
            interfaces = result.stdout.strip().split('\n')
            for iface in interfaces:
                if iface:
                    logger.info(f"Stopping WireGuard interface: {iface}")
                    subprocess.run(["wg-quick", "down", iface], capture_output=True)
    except Exception as e:
        logger.warning(f"Error stopping interfaces: {e}")
    
    # 2. Remove group chains (WG_GRP_*) from filter table
    try:
        result = subprocess.run(
            ["iptables", "-t", "filter", "-L", "-n"],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if 'Chain WG_GRP_' in line:
                chain_name = line.split()[1]
                # First remove any jump rules to this chain
                _remove_references_to_chain("filter", chain_name)
                # Then flush and delete
                subprocess.run(["iptables", "-t", "filter", "-F", chain_name], capture_output=True)
                subprocess.run(["iptables", "-t", "filter", "-X", chain_name], capture_output=True)
                logger.info(f"Removed group chain: {chain_name}")
    except Exception as e:
        logger.warning(f"Error removing group chains: {e}")
    
    # 2b. Remove client chains (WG_CLI_*) from filter table
    try:
        result = subprocess.run(
            ["iptables", "-t", "filter", "-L", "-n"],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if 'Chain WG_CLI_' in line:
                chain_name = line.split()[1]
                # First remove any jump rules to this chain
                _remove_references_to_chain("filter", chain_name)
                # Then flush and delete
                subprocess.run(["iptables", "-t", "filter", "-F", chain_name], capture_output=True)
                subprocess.run(["iptables", "-t", "filter", "-X", chain_name], capture_output=True)
                logger.info(f"Removed client chain: {chain_name}")
    except Exception as e:
        logger.warning(f"Error removing client chains: {e}")
    
    # 3. Remove per-instance chains (WG_{instance}_FWD, WG_{instance}_INPUT)
    try:
        result = subprocess.run(
            ["iptables", "-t", "filter", "-L", "-n"],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            # Match WG_*_FWD and WG_*_INPUT but NOT WG_GRP_* or MOD_WG_*
            if line.startswith('Chain WG_') and ('_FWD' in line or '_INPUT' in line):
                chain_name = line.split()[1]
                if not chain_name.startswith('WG_GRP_'):
                    _remove_references_to_chain("filter", chain_name)
                    subprocess.run(["iptables", "-t", "filter", "-F", chain_name], capture_output=True)
                    subprocess.run(["iptables", "-t", "filter", "-X", chain_name], capture_output=True)
                    logger.info(f"Removed instance chain: {chain_name}")
    except Exception as e:
        logger.warning(f"Error removing instance chains: {e}")
    
    # 4. Remove NAT instance chains (WG_{instance}_NAT)
    try:
        result = subprocess.run(
            ["iptables", "-t", "nat", "-L", "-n"],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if line.startswith('Chain WG_') and '_NAT' in line:
                chain_name = line.split()[1]
                _remove_references_to_chain("nat", chain_name)
                subprocess.run(["iptables", "-t", "nat", "-F", chain_name], capture_output=True)
                subprocess.run(["iptables", "-t", "nat", "-X", chain_name], capture_output=True)
                logger.info(f"Removed NAT chain: {chain_name}")
    except Exception as e:
        logger.warning(f"Error removing NAT chains: {e}")
    
    # 5. Flush and remove module chains
    module_chains = [
        ("filter", "MOD_WG_INPUT"),
        ("filter", "MOD_WG_FORWARD"),
        ("nat", "MOD_WG_NAT"),
    ]
    
    for table, chain in module_chains:
        # Remove jump rules from parent chains first
        _remove_references_to_chain(table, chain)
        # Flush chain
        subprocess.run(["iptables", "-t", table, "-F", chain], capture_output=True)
        # Delete chain
        subprocess.run(["iptables", "-t", table, "-X", chain], capture_output=True)
        logger.info(f"Removed module chain: {chain}")
    
    # 6. Remove jump rules from system chains (just in case)
    for table, parent, chain in [
        ("filter", "INPUT", "MOD_WG_INPUT"),
        ("filter", "FORWARD", "MOD_WG_FORWARD"),
        ("nat", "POSTROUTING", "MOD_WG_NAT"),
        ("filter", "MADMIN_INPUT", "MOD_WG_INPUT"),
        ("filter", "MADMIN_FORWARD", "MOD_WG_FORWARD"),
    ]:
        subprocess.run(
            ["iptables", "-t", table, "-D", parent, "-j", chain],
            capture_output=True
        )
    
    # 7. Remove configuration directory
    wg_dir = Path("/etc/wireguard")
    if wg_dir.exists():
        try:
            shutil.rmtree(wg_dir)
            logger.info(f"Removed configuration directory: {wg_dir}")
        except Exception as e:
            logger.warning(f"Failed to remove {wg_dir}: {e}")
    
    logger.info("WireGuard pre-uninstall complete")
    return True


def _remove_references_to_chain(table: str, chain_name: str):
    """Remove all jump rules pointing to a chain from all other chains."""
    try:
        # Get all rules
        result = subprocess.run(
            ["iptables", "-t", table, "-S"],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.split('\n'):
            if f"-j {chain_name}" in line and line.startswith('-A '):
                # Extract source chain from -A CHAIN_NAME ...
                parts = line.split()
                if len(parts) >= 2:
                    source_chain = parts[1]
                    # Build delete command by replacing -A with -D
                    delete_cmd = ["iptables", "-t", table] + ["-D" if p == "-A" else p for p in parts]
                    subprocess.run(delete_cmd, capture_output=True)
                    logger.debug(f"Removed jump from {source_chain} to {chain_name}")
    except Exception as e:
        logger.debug(f"Error removing references to {chain_name}: {e}")

