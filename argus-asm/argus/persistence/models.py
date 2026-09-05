"""SQLAlchemy ORM models: the six entities from the report's ER diagram.

Target 1--* Scan 1--* Asset 1--* Port 1--* Banner
Asset 1--* Change

Uses SQLAlchemy 2.0 style declarative mapping.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    String, Integer, Float, DateTime, ForeignKey, Text, Boolean
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    authorised: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target",
                                               cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    max_risk: Mapped[float] = mapped_column(Float, default=0.0)

    target: Mapped["Target"] = relationship(back_populates="scans")
    assets: Mapped[list["Asset"]] = relationship(back_populates="scan",
                                                 cascade="all, delete-orphan")
    changes: Mapped[list["Change"]] = relationship(back_populates="scan",
                                                   cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped["Scan"] = relationship(back_populates="assets")
    ports: Mapped[list["Port"]] = relationship(back_populates="asset",
                                               cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    service: Mapped[str] = mapped_column(String(64), default="unknown")
    state: Mapped[str] = mapped_column(String(16), default="open")

    asset: Mapped["Asset"] = relationship(back_populates="ports")
    banners: Mapped[list["Banner"]] = relationship(back_populates="port",
                                                   cascade="all, delete-orphan")


class Banner(Base):
    __tablename__ = "banners"
    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"), index=True)
    raw: Mapped[str] = mapped_column(Text, default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    port: Mapped["Port"] = relationship(back_populates="banners")


class Change(Base):
    __tablename__ = "changes"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    asset_ip: Mapped[str] = mapped_column(String(64), index=True)
    # Typed change events: new_asset, new_port, closed_port, banner_changed, new_subdomain
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped["Scan"] = relationship(back_populates="changes")