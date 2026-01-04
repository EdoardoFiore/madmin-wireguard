"""
WireGuard Post-Update Hook

Executed after the module is updated.
Restarts WireGuard interfaces with new configuration.
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def run():
    """Restart WireGuard interfaces after update."""
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
                    logger.info(f"Restarting WireGuard interface: {iface}")
                    # Restart to apply any config changes
                    subprocess.run(["wg-quick", "down", iface], capture_output=True)
                    subprocess.run(["wg-quick", "up", iface], capture_output=True)
        
        logger.info("WireGuard post-update completed")
        return True
        
    except Exception as e:
        logger.error(f"Post-update error: {e}")
        # Don't block on error
        return True
