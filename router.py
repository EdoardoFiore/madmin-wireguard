"""
WireGuard Module - API Router

FastAPI endpoints for WireGuard VPN management.
"""
import logging
import io
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlmodel import SQLModel

from core.database import get_session
from core.auth.dependencies import require_permission
from core.auth.models import User

from .models import (
    WgInstance, WgInstanceCreate, WgInstanceRead,
    WgClient, WgClientCreate, WgClientRead,
    WgGroup, WgGroupCreate, WgGroupRead, WgGroupMember, WgGroupMemberRead,
    WgGroupRule, WgGroupRuleCreate, WgGroupRuleRead, WgGroupRuleUpdate,
    RuleOrderUpdate, FirewallPolicyUpdate, WgRoutingUpdate,
    WgMagicToken, SendConfigRequest
)
from .service import wireguard_service, WIREGUARD_CONFIG_DIR

logger = logging.getLogger(__name__)
router = APIRouter()


# --- SYSTEM ---

@router.get("/system/interfaces")
async def get_network_interfaces(
    _user: User = Depends(require_permission("wireguard.view"))
):
    """
    Return list of physical network interfaces.
    Used for route interface selection in split tunnel mode.
    """
    interfaces = wireguard_service.get_physical_interfaces()
    return {"interfaces": interfaces}


@router.post("/system/register-chains")
async def register_module_chains(
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """
    Register WireGuard module chains with the core firewall orchestrator.
    This enables chain priority management via the UI.
    Should be called once after module installation.
    """
    from .service import WireGuardService
    
    success = await WireGuardService.register_module_chains(db)
    if success:
        await db.commit()
        return {"status": "ok", "message": "Chains registered successfully"}
    else:
        raise HTTPException(500, "Failed to register chains")


# --- INSTANCES ---

@router.get("/instances", response_model=List[WgInstanceRead])
async def list_instances(
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.view"))
):
    """List all WireGuard instances."""
    result = await db.execute(select(WgInstance))
    instances = result.scalars().all()
    
    response = []
    for inst in instances:
        count = await db.execute(
            select(func.count()).where(WgClient.instance_id == inst.id)
        )
        response.append(WgInstanceRead(
            id=inst.id, name=inst.name, port=inst.port, subnet=inst.subnet,
            interface=inst.interface, public_key=inst.public_key,
            tunnel_mode=inst.tunnel_mode, routes=inst.routes,
            dns_servers=inst.dns_servers,
            firewall_default_policy=inst.firewall_default_policy,
            status="running" if wireguard_service.get_interface_status(inst.interface) else "stopped",
            client_count=count.scalar() or 0
        ))
    return response


@router.post("/instances", response_model=WgInstanceRead, status_code=201)
async def create_instance(
    data: WgInstanceCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Create new WireGuard instance."""
    interface_name = f"wg_{data.name.lower().replace(' ', '_')[:10]}"
    
    existing = await db.execute(
        select(WgInstance).where(
            (WgInstance.port == data.port) | (WgInstance.interface == interface_name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Porta o interfaccia già in uso")
    
    private_key, public_key = wireguard_service.generate_keypair()
    
    from ipaddress import ip_network
    network = ip_network(data.subnet, strict=False)
    server_ip = str(list(network.hosts())[0])
    
    instance = WgInstance(
        id=interface_name, name=data.name, port=data.port,
        subnet=data.subnet, interface=interface_name,
        private_key=private_key, public_key=public_key,
        tunnel_mode=data.tunnel_mode, routes=data.routes,
        dns_servers=data.dns_servers
    )
    db.add(instance)
    
    config = wireguard_service.create_server_config(
        interface_name, data.port, private_key, f"{server_ip}/{network.prefixlen}"
    )
    config_path = WIREGUARD_CONFIG_DIR / f"{interface_name}.conf"
    config_path.write_text(config)
    config_path.chmod(0o600)
    
    await db.commit()
    
    return WgInstanceRead(
        id=instance.id, name=instance.name, port=instance.port,
        subnet=instance.subnet, interface=instance.interface,
        public_key=instance.public_key, tunnel_mode=instance.tunnel_mode,
        routes=instance.routes, dns_servers=instance.dns_servers,
        firewall_default_policy=instance.firewall_default_policy,
        status="stopped", client_count=0
    )


@router.get("/instances/{instance_id}", response_model=WgInstanceRead)
async def get_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.view"))
):
    """Get a single WireGuard instance by ID."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    count = await db.execute(
        select(func.count()).where(WgClient.instance_id == instance.id)
    )
    
    return WgInstanceRead(
        id=instance.id, name=instance.name, port=instance.port,
        subnet=instance.subnet, interface=instance.interface,
        public_key=instance.public_key, tunnel_mode=instance.tunnel_mode,
        routes=instance.routes, dns_servers=instance.dns_servers,
        firewall_default_policy=instance.firewall_default_policy,
        status="running" if wireguard_service.get_interface_status(instance.interface) else "stopped",
        endpoint=instance.endpoint,
        client_count=count.scalar() or 0
    )


class WgInstanceUpdate(SQLModel):
    """Schema for updating instance settings."""
    endpoint: Optional[str] = None


@router.patch("/instances/{instance_id}")
async def update_instance(
    instance_id: str,
    data: WgInstanceUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Update WireGuard instance settings."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    # Update endpoint if provided (allow setting to None)
    if "endpoint" in data.model_dump(exclude_unset=True):
        instance.endpoint = data.endpoint
    
    instance.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(instance)
    
    return {"success": True, "message": "Istanza aggiornata"}


@router.patch("/instances/{instance_id}/routing")
async def update_instance_routing(
    instance_id: str,
    data: WgRoutingUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """
    Update routing mode for an existing WireGuard instance.
    
    Changes tunnel_mode between 'full' and 'split' without recreating the instance.
    Note: Existing clients must re-download their configuration to apply the new routes.
    """
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    # Validate tunnel_mode
    if data.tunnel_mode not in ("full", "split"):
        raise HTTPException(400, "tunnel_mode deve essere 'full' o 'split'")
    
    # Validate routes if split tunnel
    if data.tunnel_mode == "split" and not data.routes:
        raise HTTPException(400, "Split tunnel richiede almeno una route")
    
    # Update instance
    instance.tunnel_mode = data.tunnel_mode
    instance.routes = data.routes if data.tunnel_mode == "split" else []
    if data.dns_servers is not None:
        instance.dns_servers = data.dns_servers
    instance.updated_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(instance)
    
    # Apply firewall changes if interface is actually running
    # Check real interface status, not just DB status
    if wireguard_service.get_interface_status(instance.interface):
        # Reapply firewall rules (this handles NAT and FORWARD changes)
        wireguard_service.apply_instance_firewall_rules(
            instance.id, instance.port, instance.interface, instance.subnet,
            instance.tunnel_mode, instance.routes, instance.firewall_default_policy
        )
        # Reapply group rules to maintain proper chain structure
        await wireguard_service.apply_group_firewall_rules(instance.id, db)
        logger.info(f"Firewall rules reapplied for instance {instance_id}")
    else:
        logger.info(f"Instance {instance_id} interface not running, firewall will be applied on start")
    
    # Count clients that will need reconfiguration
    client_count_result = await db.execute(
        select(func.count()).select_from(WgClient).where(WgClient.instance_id == instance_id)
    )
    client_count = client_count_result.scalar() or 0
    
    return {
        "success": True,
        "message": "Modalità instradamento aggiornata",
        "tunnel_mode": instance.tunnel_mode,
        "routes": instance.routes,
        "clients_affected": client_count,
        "warning": f"I {client_count} client esistenti devono riscaricare la configurazione per applicare le nuove rotte." if client_count > 0 else None
    }


@router.delete("/instances/{instance_id}", status_code=204)
async def delete_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Delete WireGuard instance."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    wireguard_service.stop_interface(instance.interface)
    # Remove group chains first (needs DB access)
    from .service import WireGuardService
    await WireGuardService.remove_all_group_chains(instance.id, db)
    # Then remove instance chains
    wireguard_service.remove_instance_firewall_rules(instance.id, instance.interface)
    
    config_path = WIREGUARD_CONFIG_DIR / f"{instance.interface}.conf"
    if config_path.exists():
        config_path.unlink()
    
    await db.delete(instance)
    await db.commit()


@router.post("/instances/{instance_id}/start")
async def start_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Start WireGuard instance."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    if wireguard_service.start_interface(instance.interface):
        # Apply firewall rules when interface starts
        wireguard_service.apply_instance_firewall_rules(
            instance.id, instance.port, instance.interface, instance.subnet,
            instance.tunnel_mode, instance.routes, instance.firewall_default_policy
        )
        # Also apply group rules (member jumps, default policy)
        from .service import WireGuardService
        await WireGuardService.apply_group_firewall_rules(instance.id, db)
        return {"status": "running"}
    raise HTTPException(500, "Impossibile avviare istanza")


@router.post("/instances/{instance_id}/stop")
async def stop_instance(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Stop WireGuard instance."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    if wireguard_service.stop_interface(instance.interface):
        # Remove firewall rules when interface stops
        from .service import WireGuardService
        await WireGuardService.remove_all_group_chains(instance.id, db)
        wireguard_service.remove_instance_firewall_rules(instance.id, instance.interface)
        return {"status": "stopped"}
    raise HTTPException(500, "Impossibile fermare istanza")


# --- CLIENTS ---

@router.get("/instances/{instance_id}/clients", response_model=List[WgClientRead])
async def list_clients(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.view"))
):
    """List clients for an instance with live connection status."""
    # Get instance to determine interface name
    inst_result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = inst_result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    # Get live peer status from wg show
    peer_status = wireguard_service.get_peer_status(instance.interface)
    
    # Get clients from database
    result = await db.execute(
        select(WgClient).where(WgClient.instance_id == instance_id)
    )
    clients = result.scalars().all()
    
    response = []
    for c in clients:
        # Merge with live status if available
        status = peer_status.get(c.public_key, {})
        
        response.append(WgClientRead(
            id=c.id,
            name=c.name,
            allocated_ip=c.allocated_ip,
            public_key=c.public_key,
            created_at=c.created_at,
            last_handshake=c.last_handshake,
            is_connected=status.get('is_connected', False),
            last_seen=status.get('last_seen'),
            rx_bytes=status.get('rx_bytes', 0),
            tx_bytes=status.get('tx_bytes', 0),
            endpoint=status.get('endpoint')
        ))
    
    return response


@router.post("/instances/{instance_id}/clients", response_model=WgClientRead, status_code=201)
async def create_client(
    instance_id: str,
    data: WgClientCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.clients"))
):
    """Create new client."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    existing = await db.execute(
        select(WgClient).where(
            (WgClient.instance_id == instance_id) & (WgClient.name == data.name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Nome client già esistente")
    
    private_key, public_key = wireguard_service.generate_keypair()
    psk = wireguard_service.generate_psk()
    allocated_ip = await wireguard_service.allocate_client_ip(db, instance)
    
    client = WgClient(
        instance_id=instance_id, name=data.name,
        private_key=private_key, public_key=public_key,
        preshared_key=psk, allocated_ip=allocated_ip
    )
    db.add(client)
    
    config_path = WIREGUARD_CONFIG_DIR / f"{instance.interface}.conf"
    wireguard_service.add_peer_to_config(config_path, public_key, psk, allocated_ip, data.name)
    
    if wireguard_service.get_interface_status(instance.interface):
        wireguard_service.hot_reload_interface(instance.interface)
    
    await db.commit()
    
    return WgClientRead(
        id=client.id, name=client.name, allocated_ip=client.allocated_ip,
        public_key=client.public_key, created_at=client.created_at,
        last_handshake=client.last_handshake
    )


@router.delete("/instances/{instance_id}/clients/{client_name}", status_code=204)
async def delete_client(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.clients"))
):
    """Delete (revoke) client."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    result = await db.execute(
        select(WgClient).where(
            (WgClient.instance_id == instance_id) & (WgClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client non trovato")
    
    config_path = WIREGUARD_CONFIG_DIR / f"{instance.interface}.conf"
    wireguard_service.remove_peer_from_config(config_path, client.public_key)
    
    if wireguard_service.get_interface_status(instance.interface):
        wireguard_service.hot_reload_interface(instance.interface)
    
    await db.delete(client)
    await db.commit()


@router.get("/instances/{instance_id}/clients/{client_name}/config")
async def get_client_config(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.clients"))
):
    """Download client config."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    result = await db.execute(
        select(WgClient).where(
            (WgClient.instance_id == instance_id) & (WgClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client non trovato")
    
    # Get endpoint: instance-specific > auto-detect > fallback
    from .service import get_public_ip
    endpoint = instance.endpoint or get_public_ip() or "YOUR_SERVER_IP"
    
    config = wireguard_service.generate_client_config(instance, client, endpoint)
    
    return Response(
        content=config, media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={client_name}.conf"}
    )


@router.get("/instances/{instance_id}/clients/{client_name}/qr")
async def get_client_qr(
    instance_id: str,
    client_name: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.clients"))
):
    """Get QR code for client config."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    result = await db.execute(
        select(WgClient).where(
            (WgClient.instance_id == instance_id) & (WgClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client non trovato")
    
    # Get endpoint: instance-specific > auto-detect > fallback
    from .service import get_public_ip
    endpoint = instance.endpoint or get_public_ip() or "YOUR_SERVER_IP"
    
    config = wireguard_service.generate_client_config(instance, client, endpoint)
    qr_bytes = wireguard_service.generate_qr_code(config)
    
    return StreamingResponse(io.BytesIO(qr_bytes), media_type="image/png")


@router.post("/instances/{instance_id}/clients/{client_name}/send-config")
async def send_client_config_email(
    instance_id: str,
    client_name: str,
    data: SendConfigRequest,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.clients"))
):
    """
    Send client config via email with magic token link.
    Token is valid for 48 hours and can only be used once.
    """
    import secrets
    from datetime import timedelta
    from core.settings.models import SMTPSettings
    from core.email import send_email
    
    # Get instance and client
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    result = await db.execute(
        select(WgClient).where(
            (WgClient.instance_id == instance_id) & (WgClient.name == client_name)
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client non trovato")
    
    # Get SMTP settings
    smtp_result = await db.execute(select(SMTPSettings).where(SMTPSettings.id == 1))
    smtp_settings = smtp_result.scalar_one_or_none()
    if not smtp_settings or not smtp_settings.smtp_host:
        raise HTTPException(400, "SMTP non configurato. Configura prima le impostazioni email.")
    
    if not smtp_settings.public_url:
        raise HTTPException(400, "URL pubblico non configurato nelle impostazioni SMTP.")
    
    # Generate magic token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=48)
    
    magic_token = WgMagicToken(
        token=token,
        client_id=client.id,
        expires_at=expires_at
    )
    db.add(magic_token)
    await db.commit()
    
    # Build download URL
    base_url = smtp_settings.public_url.rstrip('/')
    download_url = f"{base_url}/api/modules/wireguard/download/{token}"
    
    # Send email
    body_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px;">
            <h2 style="color: #206bc4;">🔐 Configurazione VPN WireGuard</h2>
            <p>Ciao,</p>
            <p>Ecco il link per scaricare la tua configurazione VPN:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{download_url}" 
                   style="background: #206bc4; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 6px; font-weight: bold;">
                    📥 Scarica Configurazione
                </a>
            </p>
            <p><strong>Client:</strong> {client_name}</p>
            <p><strong>Istanza:</strong> {instance.name}</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">
                ⚠️ Questo link è valido per <strong>48 ore</strong> e può essere usato <strong>una sola volta</strong>.<br>
                Dopo il download il link non sarà più utilizzabile.
            </p>
        </div>
    </body>
    </html>
    """
    
    result = await send_email(
        smtp_host=smtp_settings.smtp_host,
        smtp_port=smtp_settings.smtp_port,
        smtp_encryption=smtp_settings.smtp_encryption,
        smtp_username=smtp_settings.smtp_username,
        smtp_password=smtp_settings.smtp_password,
        sender_email=smtp_settings.sender_email,
        sender_name=smtp_settings.sender_name,
        recipient_email=data.email,
        subject=f"VPN Config - {client_name}",
        body_html=body_html
    )
    
    if not result.get("success"):
        raise HTTPException(500, result.get("message", "Errore invio email"))
    
    return {"success": True, "message": f"Email inviata a {data.email}"}


async def _validate_token(token: str, db: AsyncSession):
    """
    Validate magic token and return (magic_token, client, instance, error) tuple.
    If error is not None, it contains (title, message) for the error page.
    Token can be used multiple times within validity period.
    """
    result = await db.execute(select(WgMagicToken).where(WgMagicToken.token == token))
    magic_token = result.scalar_one_or_none()
    
    if not magic_token:
        return None, None, None, ("Link non valido", "Questo link di download non esiste o è stato rimosso.")
    
    if magic_token.expires_at < datetime.utcnow():
        return None, None, None, ("Link scaduto", "Questo link di download è scaduto. Richiedi un nuovo link all'amministratore.")
    
    result = await db.execute(select(WgClient).where(WgClient.id == magic_token.client_id))
    client = result.scalar_one_or_none()
    if not client:
        return None, None, None, ("Client non trovato", "Il client associato a questo link non esiste più.")
    
    result = await db.execute(select(WgInstance).where(WgInstance.id == client.instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        return None, None, None, ("Istanza non trovata", "L'istanza VPN associata non esiste più.")
    
    return magic_token, client, instance, None


@router.get("/download/{token}", response_class=HTMLResponse)
async def download_landing_page(
    token: str,
    db: AsyncSession = Depends(get_session)
):
    """
    Public landing page with setup instructions for WireGuard.
    Shows mobile/desktop tabs with QR code and download buttons.
    """
    from fastapi.responses import HTMLResponse
    from pathlib import Path
    
    magic_token, client, instance, error = await _validate_token(token, db)
    
    # If error, show error page
    if error:
        error_template = Path(__file__).parent / "static" / "link_error.html"
        html_content = error_template.read_text(encoding="utf-8")
        html_content = html_content.replace("{title}", error[0])
        html_content = html_content.replace("{message}", error[1])
        return HTMLResponse(content=html_content, status_code=410)
    
    # Load and render template
    template_path = Path(__file__).parent / "static" / "download_page.html"
    html_content = template_path.read_text(encoding="utf-8")
    
    # Format expiry date
    expires_str = magic_token.expires_at.strftime("%d/%m/%Y alle %H:%M")
    
    # Build URLs
    base_path = f"/api/modules/wireguard/download/{token}"
    
    html_content = html_content.replace("{client_name}", client.name)
    html_content = html_content.replace("{expires_at}", expires_str)
    html_content = html_content.replace("{download_url}", f"{base_path}/file")
    html_content = html_content.replace("{qr_url}", f"{base_path}/qr")
    
    return HTMLResponse(content=html_content)


@router.get("/download/{token}/file")
async def download_config_file(
    token: str,
    db: AsyncSession = Depends(get_session)
):
    """
    Download the actual .conf file.
    Can be downloaded multiple times within validity period.
    """
    from pathlib import Path
    
    magic_token, client, instance, error = await _validate_token(token, db)
    
    # If error, show error page
    if error:
        error_template = Path(__file__).parent / "static" / "link_error.html"
        html_content = error_template.read_text(encoding="utf-8")
        html_content = html_content.replace("{title}", error[0])
        html_content = html_content.replace("{message}", error[1])
        return HTMLResponse(content=html_content, status_code=410)
    
    # Generate config
    from .service import get_public_ip
    endpoint = instance.endpoint or get_public_ip() or "YOUR_SERVER_IP"
    config = wireguard_service.generate_client_config(instance, client, endpoint)
    
    return Response(
        content=config,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={client.name}.conf"}
    )


@router.get("/download/{token}/qr")
async def download_qr_code(
    token: str,
    db: AsyncSession = Depends(get_session)
):
    """
    Get QR code image for the config.
    """
    from pathlib import Path
    
    magic_token, client, instance, error = await _validate_token(token, db)
    
    # If error, return empty image or error
    if error:
        raise HTTPException(410, error[1])
    
    # Generate config and QR
    from .service import get_public_ip
    endpoint = instance.endpoint or get_public_ip() or "YOUR_SERVER_IP"
    config = wireguard_service.generate_client_config(instance, client, endpoint)
    qr_bytes = wireguard_service.generate_qr_code(config)
    
    return StreamingResponse(io.BytesIO(qr_bytes), media_type="image/png")


# --- GROUPS ---

@router.get("/instances/{instance_id}/groups", response_model=List[WgGroupRead])
async def list_groups(
    instance_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.view"))
):
    """List firewall groups for an instance."""
    result = await db.execute(
        select(WgGroup).where(WgGroup.instance_id == instance_id)
    )
    groups = result.scalars().all()
    
    # Sort by order field
    groups = sorted(groups, key=lambda g: g.order)
    
    response = []
    for g in groups:
        member_count = await db.execute(
            select(func.count()).where(WgGroupMember.group_id == g.id)
        )
        rule_count = await db.execute(
            select(func.count()).where(WgGroupRule.group_id == g.id)
        )
        response.append(WgGroupRead(
            id=g.id, instance_id=g.instance_id, name=g.name, description=g.description,
            order=g.order,
            member_count=member_count.scalar() or 0,
            rule_count=rule_count.scalar() or 0
        ))
    return response


@router.post("/instances/{instance_id}/groups", response_model=WgGroupRead, status_code=201)
async def create_group(
    instance_id: str,
    data: WgGroupCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Create a new firewall group."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Istanza non trovata")
    
    # Sanitize group name and generate ID
    sanitized_name = data.name.lower().replace(' ', '_')
    group_id = f"{instance_id}_{sanitized_name}"
    
    existing = await db.execute(select(WgGroup).where(WgGroup.id == group_id))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Gruppo già esistente")
    
    # Check for chain name collision due to truncation
    # Chain names are truncated to 8 chars for instance and 8 chars for group
    chain_id = instance_id.replace('wg_', '') if instance_id.startswith('wg_') else instance_id
    truncated_group = sanitized_name[:8]
    
    # Get all existing groups for this instance
    result = await db.execute(select(WgGroup).where(WgGroup.instance_id == instance_id))
    existing_groups = result.scalars().all()
    
    for existing_grp in existing_groups:
        existing_name = existing_grp.id.replace(instance_id + '_', '')
        if existing_name[:8] == truncated_group:
            # Collision detected!
            raise HTTPException(
                400, 
                f"Nome gruppo causa collisione con '{existing_grp.name}' - "
                f"entrambi iniziano con '{truncated_group}'. "
                f"Scegli un nome che NON inizi con '{truncated_group}'."
            )
    
    # Get next order value for this instance
    max_order_result = await db.execute(
        select(func.max(WgGroup.order)).where(WgGroup.instance_id == instance_id)
    )
    max_order = max_order_result.scalar() or 0
    next_order = max_order + 1
    
    group = WgGroup(id=group_id, instance_id=instance_id, name=data.name, description=data.description, order=next_order)
    db.add(group)
    await db.commit()
    
    return WgGroupRead(id=group.id, instance_id=group.instance_id, name=group.name, description=group.description, order=group.order)


@router.delete("/instances/{instance_id}/groups/{group_id}", status_code=204)
async def delete_group(
    instance_id: str,
    group_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Delete a firewall group."""
    result = await db.execute(
        select(WgGroup).where((WgGroup.id == group_id) & (WgGroup.instance_id == instance_id))
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(404, "Gruppo non trovato")
    
    # IMPORTANT: Remove firewall rules BEFORE deleting from DB
    # so we still have member info to remove jump rules
    # Use sanitized name from group.id (same as creation) to ensure chain name matches
    sanitized_group_name = group.id.replace(instance_id + '_', '')
    await wireguard_service.remove_group_firewall_rules(instance_id, group_id, sanitized_group_name, db)
    
    await db.delete(group)
    await db.commit()


class GroupOrderUpdate(SQLModel):
    """Schema for updating group order."""
    group_id: str
    order: int


@router.put("/instances/{instance_id}/groups/order")
async def reorder_groups(
    instance_id: str,
    orders: List[GroupOrderUpdate],
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Update group order for an instance. Lower order = higher priority in iptables."""
    for item in orders:
        result = await db.execute(
            select(WgGroup).where(
                (WgGroup.id == item.group_id) & (WgGroup.instance_id == instance_id)
            )
        )
        group = result.scalar_one_or_none()
        if group:
            group.order = item.order
    await db.commit()
    
    # Re-apply firewall rules to reflect new order
    from .service import WireGuardService
    await WireGuardService.apply_group_firewall_rules(instance_id, db)
    
    return {"status": "ok"}


# --- MEMBERS ---

@router.get("/instances/{instance_id}/groups/{group_id}/members", response_model=List[WgGroupMemberRead])
async def list_members(
    instance_id: str,
    group_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.view"))
):
    """List members of a group."""
    result = await db.execute(
        select(WgGroupMember, WgClient)
        .join(WgClient, WgGroupMember.client_id == WgClient.id)
        .where(WgGroupMember.group_id == group_id)
    )
    return [
        WgGroupMemberRead(client_id=m.client_id, client_name=c.name, client_ip=c.allocated_ip)
        for m, c in result.all()
    ]


@router.post("/instances/{instance_id}/groups/{group_id}/members", status_code=201)
async def add_member(
    instance_id: str,
    group_id: str,
    client_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Add a client to a group."""
    import uuid as uuid_module
    
    # Validate group exists
    result = await db.execute(
        select(WgGroup).where((WgGroup.id == group_id) & (WgGroup.instance_id == instance_id))
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Gruppo non trovato")
    
    # Validate client exists
    client_uuid = uuid_module.UUID(client_id)
    result = await db.execute(
        select(WgClient).where((WgClient.id == client_uuid) & (WgClient.instance_id == instance_id))
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Client non trovato")
    
    # Check if already member
    existing = await db.execute(
        select(WgGroupMember).where(
            (WgGroupMember.group_id == group_id) & (WgGroupMember.client_id == client_uuid)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Client già membro del gruppo")
    
    member = WgGroupMember(group_id=group_id, client_id=client_uuid)
    db.add(member)
    await db.commit()
    
    # Apply firewall rules for this instance
    await wireguard_service.apply_group_firewall_rules(instance_id, db)
    
    return {"status": "added"}


@router.delete("/instances/{instance_id}/groups/{group_id}/members/{client_id}", status_code=204)
async def remove_member(
    instance_id: str,
    group_id: str,
    client_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Remove a client from a group."""
    import uuid as uuid_module
    client_uuid = uuid_module.UUID(client_id)
    
    result = await db.execute(
        select(WgGroupMember).where(
            (WgGroupMember.group_id == group_id) & (WgGroupMember.client_id == client_uuid)
        )
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(404, "Membro non trovato")
    
    await db.delete(member)
    await db.commit()
    
    # Reapply firewall rules
    await wireguard_service.apply_group_firewall_rules(instance_id, db)


# --- RULES ---

@router.get("/instances/{instance_id}/groups/{group_id}/rules", response_model=List[WgGroupRuleRead])
async def list_rules(
    instance_id: str,
    group_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.view"))
):
    """List rules for a group."""
    result = await db.execute(
        select(WgGroupRule).where(WgGroupRule.group_id == group_id).order_by(WgGroupRule.order)
    )
    return [
        WgGroupRuleRead(
            id=r.id, action=r.action, protocol=r.protocol, port=r.port,
            destination=r.destination, description=r.description, order=r.order
        ) for r in result.scalars().all()
    ]


@router.post("/instances/{instance_id}/groups/{group_id}/rules", response_model=WgGroupRuleRead, status_code=201)
async def create_rule(
    instance_id: str,
    group_id: str,
    data: WgGroupRuleCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Create a new firewall rule."""
    result = await db.execute(
        select(WgGroup).where((WgGroup.id == group_id) & (WgGroup.instance_id == instance_id))
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Gruppo non trovato")
    
    # Get max order
    max_order = await db.execute(
        select(func.max(WgGroupRule.order)).where(WgGroupRule.group_id == group_id)
    )
    next_order = (max_order.scalar() or -1) + 1
    
    rule = WgGroupRule(
        group_id=group_id, action=data.action, protocol=data.protocol,
        port=data.port, destination=data.destination, description=data.description,
        order=next_order
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    
    # Apply firewall rules
    await wireguard_service.apply_group_firewall_rules(instance_id, db)
    
    return WgGroupRuleRead(
        id=rule.id, action=rule.action, protocol=rule.protocol, port=rule.port,
        destination=rule.destination, description=rule.description, order=rule.order
    )


@router.patch("/instances/{instance_id}/groups/{group_id}/rules/{rule_id}", response_model=WgGroupRuleRead)
async def update_rule(
    instance_id: str,
    group_id: str,
    rule_id: str,
    data: WgGroupRuleUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Update a firewall rule."""
    import uuid as uuid_module
    
    result = await db.execute(
        select(WgGroupRule).where(
            (WgGroupRule.id == uuid_module.UUID(rule_id)) & (WgGroupRule.group_id == group_id)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Regola non trovata")
    
    for field, value in data.dict(exclude_unset=True).items():
        setattr(rule, field, value)
    
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    
    # Apply firewall rules
    await wireguard_service.apply_group_firewall_rules(instance_id, db)
    
    return WgGroupRuleRead(
        id=rule.id, action=rule.action, protocol=rule.protocol, port=rule.port,
        destination=rule.destination, description=rule.description, order=rule.order
    )


@router.delete("/instances/{instance_id}/groups/{group_id}/rules/{rule_id}", status_code=204)
async def delete_rule(
    instance_id: str,
    group_id: str,
    rule_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Delete a firewall rule."""
    import uuid as uuid_module
    
    result = await db.execute(
        select(WgGroupRule).where(
            (WgGroupRule.id == uuid_module.UUID(rule_id)) & (WgGroupRule.group_id == group_id)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Regola non trovata")
    
    await db.delete(rule)
    await db.commit()
    
    # Reapply firewall rules
    await wireguard_service.apply_group_firewall_rules(instance_id, db)


@router.put("/instances/{instance_id}/groups/{group_id}/rules/order")
async def reorder_rules(
    instance_id: str,
    group_id: str,
    orders: List[RuleOrderUpdate],
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Update rule order."""
    for item in orders:
        result = await db.execute(
            select(WgGroupRule).where(
                (WgGroupRule.id == item.id) & (WgGroupRule.group_id == group_id)
            )
        )
        rule = result.scalar_one_or_none()
        if rule:
            rule.order = item.order
            db.add(rule)
    
    await db.commit()
    
    # Reapply firewall rules with new order
    await wireguard_service.apply_group_firewall_rules(instance_id, db)
    
    return {"status": "updated"}


# --- FIREWALL POLICY ---

@router.patch("/instances/{instance_id}/firewall-policy")
async def update_firewall_policy(
    instance_id: str,
    data: FirewallPolicyUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("wireguard.manage"))
):
    """Update instance default firewall policy."""
    result = await db.execute(select(WgInstance).where(WgInstance.id == instance_id))
    instance = result.scalar_one_or_none()
    if not instance:
        raise HTTPException(404, "Istanza non trovata")
    
    if data.policy not in ["ACCEPT", "DROP"]:
        raise HTTPException(400, "Policy deve essere ACCEPT o DROP")
    
    instance.firewall_default_policy = data.policy
    db.add(instance)
    await db.commit()
    
    # Reapply firewall rules with new policy
    await wireguard_service.apply_group_firewall_rules(instance_id, db)
    
    return {"status": "updated", "policy": data.policy}
