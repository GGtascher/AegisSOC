from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    host: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), default="INFO")
    data: Mapped[str] = mapped_column(Text, default="{}")
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(40))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    status: Mapped[str] = mapped_column(String(24), default="NEW", index=True)
    evidence: Mapped[str] = mapped_column(Text, default="{}")
    recommendation: Mapped[str] = mapped_column(Text, default="Review the related activity.")
    mitre_technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    incidents: Mapped[list["Incident"]] = relationship(
        secondary="incident_alerts", back_populates="alerts"
    )


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24), default="NEW")
    summary: Mapped[str] = mapped_column(Text)
    entities: Mapped[str] = mapped_column(Text, default="{}")
    alerts: Mapped[list[Alert]] = relationship(
        secondary="incident_alerts", back_populates="incidents", order_by="Alert.timestamp"
    )


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("ip", "mac", name="uq_device_ip_mac"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64))
    mac: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(40), default="Unknown")
    vendor: Mapped[str] = mapped_column(String(120), default="Unknown")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Baseline(Base):
    __tablename__ = "baselines"
    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    kind: Mapped[str] = mapped_column(String(60), index=True)
    value: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_id: Mapped[str] = mapped_column(String(80), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="OPEN")
    details: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class RuleState(Base):
    __tablename__ = "rule_states"
    rule_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
