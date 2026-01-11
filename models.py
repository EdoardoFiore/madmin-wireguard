"""
WireGuard Module - Database Models

SQLModel tables for WireGuard instances, clients, groups, and rules.
"""
from typing import Optional, List, Dict
from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship, JSON, Column
import uuid


class WgInstance(SQLModel, table=True):
    """WireGuard VPN server instance."""
    __tablename__ = "wg_instance"
    
    id: str = Field(primary_key=True)
    name: str = Field(max_length=100)
    port: int = Field(unique=True)
    subnet: str = Field(max_length=50)
    interface: str = Field(unique=True, max_length=20)
    
    private_key: str
    public_key: str
    
    tunnel_mode: str = Field(default="full")
    routes: List[Dict] = Field(default=[], sa_column=Column(JSON))
    dns_servers: List[str] = Field(default=["8.8.8.8", "1.1.1.1"], sa_column=Column(JSON))
    firewall_default_policy: str = Field(default="ACCEPT")
    status: str = Field(default="stopped")
    
    # Public endpoint for client configs (IP or domain)
    # If empty, will auto-detect public IP
    endpoint: Optional[str] = Field(default=None, max_length=255)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    clients: List["WgClient"] = Relationship(
        back_populates="instance",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    groups: List["WgGroup"] = Relationship(
        back_populates="instance",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class WgClient(SQLModel, table=True):
    """WireGuard VPN client peer."""
    __tablename__ = "wg_client"
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    instance_id: str = Field(foreign_key="wg_instance.id", index=True)
    name: str = Field(max_length=100)
    
    private_key: str
    public_key: str
    preshared_key: str
    allocated_ip: str = Field(max_length=50)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_handshake: Optional[datetime] = None
    
    instance: "WgInstance" = Relationship(back_populates="clients")
    group_links: List["WgGroupMember"] = Relationship(
        back_populates="client",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class WgGroup(SQLModel, table=True):
    """Firewall group for WireGuard clients."""
    __tablename__ = "wg_group"
    
    id: str = Field(primary_key=True)
    instance_id: str = Field(foreign_key="wg_instance.id", index=True)
    name: str = Field(max_length=100)
    description: str = Field(default="", max_length=500)
    order: int = Field(default=0)  # Lower = higher priority in iptables
    
    instance: "WgInstance" = Relationship(back_populates="groups")
    client_links: List["WgGroupMember"] = Relationship(
        back_populates="group",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    rules: List["WgGroupRule"] = Relationship(
        back_populates="group",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class WgGroupMember(SQLModel, table=True):
    """Junction table for groups and clients."""
    __tablename__ = "wg_group_member"
    
    group_id: str = Field(foreign_key="wg_group.id", primary_key=True)
    client_id: uuid.UUID = Field(foreign_key="wg_client.id", primary_key=True)
    
    group: "WgGroup" = Relationship(back_populates="client_links")
    client: "WgClient" = Relationship(back_populates="group_links")


class WgGroupRule(SQLModel, table=True):
    """Firewall rule for a group."""
    __tablename__ = "wg_group_rule"
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    group_id: str = Field(foreign_key="wg_group.id", index=True)
    
    action: str
    protocol: str
    port: Optional[str] = None
    destination: str
    description: str = Field(default="", max_length=255)
    order: int = Field(default=0)
    
    group: "WgGroup" = Relationship(back_populates="rules")


class WgMagicToken(SQLModel, table=True):
    """Temporary token for client config sharing."""
    __tablename__ = "wg_magic_token"
    
    token: str = Field(primary_key=True)
    client_id: uuid.UUID = Field(foreign_key="wg_client.id", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    used: bool = Field(default=False)


# --- Pydantic Schemas ---

class WgInstanceCreate(SQLModel):
    name: str
    port: int
    subnet: str
    tunnel_mode: str = "full"
    routes: List[Dict] = []
    dns_servers: List[str] = ["8.8.8.8", "1.1.1.1"]
    endpoint: Optional[str] = None  # Public IP/domain for client configs


class WgInstanceRead(SQLModel):
    id: str
    name: str
    port: int
    subnet: str
    interface: str
    public_key: str
    tunnel_mode: str
    routes: List[Dict]
    dns_servers: List[str]
    firewall_default_policy: str
    status: str
    endpoint: Optional[str] = None
    client_count: int = 0


class WgClientCreate(SQLModel):
    name: str


class WgClientRead(SQLModel):
    id: uuid.UUID
    name: str
    allocated_ip: str
    public_key: str
    created_at: datetime
    last_handshake: Optional[datetime]
    # Live status fields (from wg show)
    is_connected: Optional[bool] = None
    last_seen: Optional[str] = None
    rx_bytes: Optional[int] = None
    tx_bytes: Optional[int] = None
    endpoint: Optional[str] = None


# --- Group Schemas ---

class SendConfigRequest(SQLModel):
    """Request schema for sending client config via email."""
    email: str


class WgGroupCreate(SQLModel):
    name: str
    description: str = ""


class WgGroupRead(SQLModel):
    id: str
    instance_id: str
    name: str
    description: str
    order: int = 0
    member_count: int = 0
    rule_count: int = 0


class WgGroupMemberRead(SQLModel):
    client_id: uuid.UUID
    client_name: str
    client_ip: str


# --- Rule Schemas ---

class WgGroupRuleCreate(SQLModel):
    action: str  # ACCEPT, DROP
    protocol: str  # tcp, udp, icmp, all
    port: Optional[str] = None
    destination: str
    description: str = ""


class WgGroupRuleRead(SQLModel):
    id: uuid.UUID
    action: str
    protocol: str
    port: Optional[str]
    destination: str
    description: str
    order: int


class WgGroupRuleUpdate(SQLModel):
    action: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[str] = None
    destination: Optional[str] = None
    description: Optional[str] = None


class RuleOrderUpdate(SQLModel):
    id: uuid.UUID
    order: int


class FirewallPolicyUpdate(SQLModel):
    policy: str  # ACCEPT or DROP


class WgRoutingUpdate(SQLModel):
    """Schema for updating instance routing mode."""
    tunnel_mode: str  # "full" or "split"
    routes: List[Dict] = []  # Required when tunnel_mode is "split"
    dns_servers: Optional[List[str]] = None  # Optional DNS update
