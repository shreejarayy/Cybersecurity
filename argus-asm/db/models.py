"""
Argus ASM — ORM models
Three tables:
  Asset  — one row per discovered domain/IP
  Port   — one row per open port on an asset
  Banner — one row per grabbed banner/header set on a port
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, Boolean, Float
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class Asset(Base):
    """
    Represents a discovered internet-facing asset (domain or IP).
    One asset can have many ports; those ports can each have a banner.
    """
    __tablename__ = "assets"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    domain       = Column(String(255), nullable=False, index=True)
    ip           = Column(String(45))           # supports IPv6
    registrar    = Column(String(255))
    org          = Column(String(255))
    country      = Column(String(10))
    whois_expiry = Column(String(50))           # stored as ISO string
    first_seen   = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen    = Column(DateTime, default=datetime.utcnow,
                          onupdate=datetime.utcnow, nullable=False)
    is_active    = Column(Boolean, default=True)

    ports    = relationship("Port",   back_populates="asset",
                            cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Asset domain={self.domain} ip={self.ip}>"


class Port(Base):
    """
    Represents a single open TCP port on an asset.
    Linked back to its Asset; can have one Banner.
    """
    __tablename__ = "ports"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    asset_id   = Column(Integer, ForeignKey("assets.id"), nullable=False,
                        index=True)
    port       = Column(Integer, nullable=False)
    protocol   = Column(String(10), default="tcp")
    state      = Column(String(20), default="open")
    service    = Column(String(100))            # e.g. "HTTP", "SSH"
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen  = Column(DateTime, default=datetime.utcnow,
                        onupdate=datetime.utcnow, nullable=False)
    is_active  = Column(Boolean, default=True)

    asset  = relationship("Asset",  back_populates="ports")
    banner = relationship("Banner", back_populates="port", uselist=False,
                          cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Port {self.port}/{self.protocol} on asset_id={self.asset_id}>"


class Banner(Base):
    """
    Stores the raw grab result for a port:
      - HTTP ports: status code + response headers as text
      - TCP ports:  raw banner string
      - HTTPS ports: above + TLS certificate info
    """
    __tablename__ = "banners"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    port_id       = Column(Integer, ForeignKey("ports.id"), nullable=False,
                           index=True)
    banner_type   = Column(String(10))          # "http", "tcp"
    raw_banner    = Column(Text)                # TCP banner string
    http_status   = Column(Integer)             # e.g. 200, 404
    http_headers  = Column(Text)                # JSON-encoded header dict
    server        = Column(String(255))         # Server: header value
    powered_by    = Column(String(255))         # X-Powered-By header
    tls_subject   = Column(Text)                # JSON-encoded cert subject
    tls_issuer    = Column(Text)                # JSON-encoded cert issuer
    tls_expiry    = Column(String(100))
    scraped_at    = Column(DateTime, default=datetime.utcnow, nullable=False)

    port = relationship("Port", back_populates="banner")

    def __repr__(self):
        return f"<Banner port_id={self.port_id} type={self.banner_type}>"
