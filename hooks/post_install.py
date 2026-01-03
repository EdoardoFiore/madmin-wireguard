"""
WireGuard Module - Post-install Hook

Executes after module installation to configure system for WireGuard:
1. Load WireGuard kernel module
2. Create /etc/wireguard directory with secure permissions
3. Enable IP forwarding persistently
"""
import subprocess
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def run():
    """
    Post-installation system configuration for WireGuard.
    
    This hook is executed after:
    - apt packages are installed (wireguard, wireguard-tools, qrencode)
    - Database migrations are complete
    """
    logger.info("Running WireGuard post-install hook...")
    errors = []
    
    # 1. Load WireGuard kernel module
    logger.info("Loading WireGuard kernel module...")
    try:
        result = subprocess.run(
            ['modprobe', 'wireguard'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            # On some kernels WireGuard is built-in, not a module
            logger.warning(f"modprobe wireguard returned: {result.stderr.strip()}")
        else:
            logger.info("WireGuard kernel module loaded")
    except FileNotFoundError:
        logger.warning("modprobe not found, skipping kernel module load")
    except Exception as e:
        errors.append(f"Kernel module load failed: {e}")
    
    # 2. Create /etc/wireguard directory with secure permissions
    logger.info("Creating /etc/wireguard directory...")
    wg_dir = Path("/etc/wireguard")
    try:
        wg_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(wg_dir, 0o700)
        logger.info(f"Created {wg_dir} with mode 700")
    except PermissionError:
        errors.append(f"Permission denied creating {wg_dir}")
    except Exception as e:
        errors.append(f"Failed to create {wg_dir}: {e}")
    
    # 3. Enable IP forwarding (required for VPN routing)
    logger.info("Enabling IP forwarding...")
    sysctl_conf = Path("/etc/sysctl.d/99-wireguard.conf")
    try:
        # Write persistent configuration
        sysctl_conf.write_text("net.ipv4.ip_forward=1\n")
        logger.info(f"Created {sysctl_conf}")
        
        # Apply immediately
        result = subprocess.run(
            ['sysctl', '-p', str(sysctl_conf)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("IP forwarding enabled")
        else:
            logger.warning(f"sysctl apply warning: {result.stderr.strip()}")
            
    except PermissionError:
        errors.append("Permission denied enabling IP forwarding")
    except FileNotFoundError:
        # Fallback: try direct sysctl
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            logger.info("IP forwarding enabled (direct sysctl)")
        except Exception as e:
            errors.append(f"Failed to enable IP forwarding: {e}")
    except Exception as e:
        errors.append(f"IP forwarding configuration failed: {e}")
    
    # Report results
    if errors:
        for err in errors:
            logger.error(f"Post-install error: {err}")
        logger.warning("WireGuard post-install completed with warnings")
    else:
        logger.info("WireGuard post-install completed successfully")
    
    # Don't fail the installation for non-critical errors
    # The module can still work if manually configured
    return True
