"""Structured audit logging on top of the audit_log table."""

from khaos.audit.logger import AuditEntry, AuditLogger, parse_detail

__all__ = ["AuditEntry", "AuditLogger", "parse_detail"]


def __getattr__(name: str):
    # Lazy import of the export module so importing the package never pulls in
    # csv/json helpers unless export is actually used.
    if name in {"export_audit_json", "export_audit_csv", "export_security_events"}:
        from khaos.audit import export

        return getattr(export, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
