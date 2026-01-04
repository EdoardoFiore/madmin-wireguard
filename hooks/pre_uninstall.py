"""
WireGuard Pre-Uninstall Hook

Executed before the module is uninstalled.
Stops all WireGuard interfaces and cleans up.
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def run():
    """Stop all WireGuard interfaces before uninstall."""
    try:
        # Find all wg interfaces
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
        
        logger.info("WireGuard pre-uninstall completed")
        return True
        
    except Exception as e:
        logger.error(f"Pre-uninstall error: {e}")
        # Don't block uninstall on error
        return True
