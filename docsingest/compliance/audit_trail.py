"""
Audit Trail and Chain of Custody for FedRAMP-ready document processing.

Provides tamper-evident logging with SHA-256 hash chains, chain-of-custody
tracking, CEF (Common Event Format) export for SIEM integration, and
comprehensive compliance with NIST 800-53 AU family controls.

References:
- NIST SP 800-53 Rev 5: AU-2, AU-3, AU-6, AU-8, AU-9, AU-11, AU-12
- NIST SP 800-171: 3.3.1, 3.3.2
- FedRAMP Audit and Accountability Requirements
- CEF (ArcSight Common Event Format)
"""

import hashlib
import json
import logging
import os
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of auditable events per NIST 800-53 AU-2."""
    DOCUMENT_ACCESS = "document_access"
    DOCUMENT_INGEST = "document_ingest"
    DOCUMENT_TRANSFORM = "document_transform"
    DOCUMENT_EXPORT = "document_export"
    COMPLIANCE_SCAN = "compliance_scan"
    PII_DETECTION = "pii_detection"
    CUI_DETECTION = "cui_detection"
    EXPORT_CONTROL_SCAN = "export_control_scan"
    SANITIZATION = "sanitization"
    CLASSIFICATION_CHANGE = "classification_change"
    ACCESS_DENIED = "access_denied"
    CONFIGURATION_CHANGE = "configuration_change"
    SYSTEM_ERROR = "system_error"
    AUDIT_LOG_ACCESS = "audit_log_access"
    CHAIN_OF_CUSTODY = "chain_of_custody"


class AuditSeverity(Enum):
    """Severity levels aligned with CEF and syslog."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


@dataclass
class AuditEntry:
    """
    A single audit log entry with hash chain integrity.

    Per NIST 800-53 AU-3, each entry includes:
    - What type of event occurred
    - When the event occurred (timestamp)
    - Where the event occurred (source)
    - Who initiated the event (actor)
    - What was the outcome
    - Hash chain for tamper evidence
    """
    entry_id: str
    timestamp: str  # ISO 8601 UTC
    event_type: str
    severity: int
    actor: str
    source_host: str
    source_ip: str
    document_path: str
    document_hash: str
    action: str
    outcome: str
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str
    nist_controls: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            'entry_id': self.entry_id,
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'severity': self.severity,
            'actor': self.actor,
            'source_host': self.source_host,
            'source_ip': self.source_ip,
            'document_path': self.document_path,
            'document_hash': self.document_hash,
            'action': self.action,
            'outcome': self.outcome,
            'details': self.details,
            'previous_hash': self.previous_hash,
            'entry_hash': self.entry_hash,
            'nist_controls': self.nist_controls,
        }

    def to_cef(self) -> str:
        """
        Convert to CEF (Common Event Format) string for SIEM integration.

        Format: CEF:Version|Device Vendor|Device Product|Device Version|
                Signature ID|Name|Severity|Extension
        """
        # CEF severity mapping (0-10 scale)
        cef_severity = min(10, max(0, 10 - self.severity))

        extensions = [
            f"rt={self.timestamp}",
            f"duser={self.actor}",
            f"shost={self.source_host}",
            f"src={self.source_ip}",
            f"fname={os.path.basename(self.document_path)}",
            f"fileHash={self.document_hash}",
            f"act={self.action}",
            f"outcome={self.outcome}",
            f"cs1={self.entry_id}",
            f"cs1Label=EntryID",
            f"cs2={self.previous_hash[:16]}",
            f"cs2Label=PreviousHash",
        ]

        # Add detail fields
        for key, value in self.details.items():
            if isinstance(value, (str, int, float, bool)):
                safe_value = str(value).replace('|', '\\|').replace('=', '\\=')
                extensions.append(f"cs3={safe_value}")
                extensions.append(f"cs3Label={key}")
                break  # CEF has limited custom fields

        ext_str = ' '.join(extensions)

        return (
            f"CEF:0|docsingest|ComplianceAudit|0.2.0|"
            f"{self.event_type}|{self.action}|{cef_severity}|{ext_str}"
        )


class AuditTrail:
    """
    FedRAMP-ready audit trail with tamper-evident hash chain.

    Provides:
    - SHA-256 hash chain linking each entry to the previous
    - NIST 800-53 AU family compliance
    - CEF export for SIEM integration
    - Chain-of-custody tracking for legal/compliance review
    - Integrity verification of the audit log
    """

    def __init__(self, log_path: Optional[str] = None, actor: str = "system") -> None:
        """
        Initialize audit trail.

        Args:
            log_path: Path to the audit log file. If None, logs to memory only.
            actor: Default actor identity for log entries.
        """
        self.log_path = log_path
        self.actor = actor
        self.entries: List[AuditEntry] = []
        self._previous_hash = self._genesis_hash()
        self._hostname = socket.gethostname()
        self._source_ip = self._get_local_ip()

        # Load existing entries if log file exists
        if log_path and os.path.exists(log_path):
            self._load_existing_log(log_path)

        logger.info("Audit trail initialized: actor=%s, log=%s", actor, log_path)

    def log_event(
        self,
        event_type: AuditEventType,
        document_path: str,
        action: str,
        outcome: str,
        severity: AuditSeverity = AuditSeverity.INFORMATIONAL,
        details: Optional[Dict[str, Any]] = None,
        actor: Optional[str] = None,
        document_hash: Optional[str] = None,
    ) -> AuditEntry:
        """
        Log an auditable event to the trail.

        Args:
            event_type: Type of event (per AU-2).
            document_path: Path to the document involved.
            action: Description of the action performed.
            outcome: Result of the action ("success", "failure", "partial").
            severity: Event severity level.
            details: Additional event-specific details.
            actor: Override the default actor for this entry.
            document_hash: SHA-256 hash of the document. Auto-computed if not provided.

        Returns:
            The created AuditEntry.
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        effective_actor = actor or self.actor

        # Compute document hash if not provided
        if document_hash is None:
            document_hash = self._compute_document_hash(document_path)

        # Determine applicable NIST controls
        nist_controls = self._map_nist_controls(event_type)

        # Build entry content for hashing (before computing hash)
        entry_content = {
            'entry_id': entry_id,
            'timestamp': timestamp,
            'event_type': event_type.value,
            'severity': severity.value,
            'actor': effective_actor,
            'source_host': self._hostname,
            'source_ip': self._source_ip,
            'document_path': document_path,
            'document_hash': document_hash,
            'action': action,
            'outcome': outcome,
            'details': details or {},
            'previous_hash': self._previous_hash,
        }

        # Compute hash chain
        entry_hash = self._compute_entry_hash(entry_content)

        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type.value,
            severity=severity.value,
            actor=effective_actor,
            source_host=self._hostname,
            source_ip=self._source_ip,
            document_path=document_path,
            document_hash=document_hash,
            action=action,
            outcome=outcome,
            details=details or {},
            previous_hash=self._previous_hash,
            entry_hash=entry_hash,
            nist_controls=nist_controls,
        )

        self.entries.append(entry)
        self._previous_hash = entry_hash

        # Persist to file if configured
        if self.log_path:
            self._append_to_log(entry)

        logger.debug(
            "Audit entry logged: %s | %s | %s | %s",
            entry.event_type, entry.action, entry.outcome, entry.entry_id
        )

        return entry

    def log_document_access(
        self, document_path: str, access_type: str = "read", outcome: str = "success"
    ) -> AuditEntry:
        """Convenience method for logging document access events."""
        return self.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path=document_path,
            action=f"Document {access_type}",
            outcome=outcome,
            details={"access_type": access_type},
        )

    def log_document_ingest(
        self, document_path: str, file_type: str, tokens: int, outcome: str = "success"
    ) -> AuditEntry:
        """Convenience method for logging document ingestion."""
        return self.log_event(
            event_type=AuditEventType.DOCUMENT_INGEST,
            document_path=document_path,
            action="Document ingested",
            outcome=outcome,
            details={"file_type": file_type, "tokens": tokens},
        )

    def log_compliance_scan(
        self,
        document_path: str,
        scan_type: str,
        findings_count: int,
        risk_score: int,
        outcome: str = "success",
    ) -> AuditEntry:
        """Convenience method for logging compliance scan events."""
        event_type_map = {
            "pii": AuditEventType.PII_DETECTION,
            "cui": AuditEventType.CUI_DETECTION,
            "export_control": AuditEventType.EXPORT_CONTROL_SCAN,
            "sanitization": AuditEventType.SANITIZATION,
        }
        event_type = event_type_map.get(scan_type, AuditEventType.COMPLIANCE_SCAN)

        severity = AuditSeverity.INFORMATIONAL
        if risk_score >= 75:
            severity = AuditSeverity.ALERT
        elif risk_score >= 50:
            severity = AuditSeverity.WARNING
        elif risk_score >= 25:
            severity = AuditSeverity.NOTICE

        return self.log_event(
            event_type=event_type,
            document_path=document_path,
            action=f"Compliance scan: {scan_type}",
            outcome=outcome,
            severity=severity,
            details={
                "scan_type": scan_type,
                "findings_count": findings_count,
                "risk_score": risk_score,
            },
        )

    def log_document_export(
        self, document_path: str, export_format: str, destination: str, outcome: str = "success"
    ) -> AuditEntry:
        """Convenience method for logging document export events."""
        return self.log_event(
            event_type=AuditEventType.DOCUMENT_EXPORT,
            document_path=document_path,
            action=f"Document exported as {export_format}",
            outcome=outcome,
            details={"export_format": export_format, "destination": destination},
        )

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of the audit trail hash chain.

        Per NIST 800-53 AU-9, ensures log entries have not been tampered with.

        Returns:
            Verification result with status and details.
        """
        if not self.entries:
            return {
                "verified": True,
                "total_entries": 0,
                "message": "Audit trail is empty.",
            }

        errors: List[Dict[str, str]] = []
        expected_prev_hash = self._genesis_hash()

        for i, entry in enumerate(self.entries):
            # Verify previous hash chain
            if entry.previous_hash != expected_prev_hash:
                errors.append({
                    "entry_index": str(i),
                    "entry_id": entry.entry_id,
                    "error": "Previous hash mismatch - possible tampering",
                    "expected": expected_prev_hash[:16] + "...",
                    "found": entry.previous_hash[:16] + "...",
                })

            # Verify entry hash
            entry_content = {
                'entry_id': entry.entry_id,
                'timestamp': entry.timestamp,
                'event_type': entry.event_type,
                'severity': entry.severity,
                'actor': entry.actor,
                'source_host': entry.source_host,
                'source_ip': entry.source_ip,
                'document_path': entry.document_path,
                'document_hash': entry.document_hash,
                'action': entry.action,
                'outcome': entry.outcome,
                'details': entry.details,
                'previous_hash': entry.previous_hash,
            }
            computed_hash = self._compute_entry_hash(entry_content)

            if entry.entry_hash != computed_hash:
                errors.append({
                    "entry_index": str(i),
                    "entry_id": entry.entry_id,
                    "error": "Entry hash mismatch - content modified",
                    "expected": computed_hash[:16] + "...",
                    "found": entry.entry_hash[:16] + "...",
                })

            expected_prev_hash = entry.entry_hash

        return {
            "verified": len(errors) == 0,
            "total_entries": len(self.entries),
            "errors": errors,
            "message": "Integrity verified" if not errors else f"INTEGRITY FAILURE: {len(errors)} error(s) detected",
        }

    def generate_chain_of_custody_report(
        self, document_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a chain-of-custody report for legal/compliance review.

        Args:
            document_path: Optional filter for a specific document. If None,
                          generates report for all documents.

        Returns:
            Chain-of-custody report as a dictionary.
        """
        relevant_entries = self.entries
        if document_path:
            relevant_entries = [e for e in self.entries if e.document_path == document_path]

        # Group by document
        documents: Dict[str, List[AuditEntry]] = {}
        for entry in relevant_entries:
            doc = entry.document_path
            if doc not in documents:
                documents[doc] = []
            documents[doc].append(entry)

        # Build report
        custody_records: List[Dict[str, Any]] = []
        for doc_path, entries in sorted(documents.items()):
            entries_sorted = sorted(entries, key=lambda e: e.timestamp)
            record = {
                "document": doc_path,
                "first_access": entries_sorted[0].timestamp if entries_sorted else None,
                "last_access": entries_sorted[-1].timestamp if entries_sorted else None,
                "total_events": len(entries_sorted),
                "actors_involved": sorted(set(e.actor for e in entries_sorted)),
                "hosts_involved": sorted(set(e.source_host for e in entries_sorted)),
                "document_hashes": sorted(set(e.document_hash for e in entries_sorted if e.document_hash)),
                "actions": [
                    {
                        "timestamp": e.timestamp,
                        "actor": e.actor,
                        "action": e.action,
                        "outcome": e.outcome,
                        "host": e.source_host,
                        "entry_id": e.entry_id,
                    }
                    for e in entries_sorted
                ],
            }
            custody_records.append(record)

        integrity = self.verify_integrity()

        report = {
            "report_type": "Chain of Custody",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generated_by": self.actor,
            "total_documents": len(custody_records),
            "total_events": len(relevant_entries),
            "integrity_status": integrity["message"],
            "integrity_verified": integrity["verified"],
            "custody_records": custody_records,
            "nist_controls": ["AU-2", "AU-3", "AU-6", "AU-8", "AU-9", "AU-11", "AU-12"],
            "nist_800_171": ["3.3.1", "3.3.2"],
        }

        return report

    def export_cef(self, output_path: Optional[str] = None) -> str:
        """
        Export audit trail in CEF format for SIEM integration.

        Args:
            output_path: Optional file path to write CEF output.

        Returns:
            CEF-formatted string of all entries.
        """
        cef_lines = [entry.to_cef() for entry in self.entries]
        cef_output = '\n'.join(cef_lines)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(cef_output)
            logger.info("CEF export written to: %s", output_path)

        return cef_output

    def get_entries_for_document(self, document_path: str) -> List[AuditEntry]:
        """Get all audit entries for a specific document."""
        return [e for e in self.entries if e.document_path == document_path]

    def get_entries_by_type(self, event_type: AuditEventType) -> List[AuditEntry]:
        """Get all audit entries of a specific type."""
        return [e for e in self.entries if e.event_type == event_type.value]

    def get_entries_by_actor(self, actor: str) -> List[AuditEntry]:
        """Get all audit entries by a specific actor."""
        return [e for e in self.entries if e.actor == actor]

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the audit trail."""
        if not self.entries:
            return {
                "total_entries": 0,
                "date_range": None,
                "event_types": {},
                "actors": [],
                "documents_tracked": 0,
            }

        event_types: Dict[str, int] = {}
        actors: set = set()
        documents: set = set()

        for entry in self.entries:
            event_types[entry.event_type] = event_types.get(entry.event_type, 0) + 1
            actors.add(entry.actor)
            documents.add(entry.document_path)

        return {
            "total_entries": len(self.entries),
            "date_range": {
                "first": self.entries[0].timestamp,
                "last": self.entries[-1].timestamp,
            },
            "event_types": event_types,
            "actors": sorted(actors),
            "documents_tracked": len(documents),
            "integrity_verified": self.verify_integrity()["verified"],
        }

    def _map_nist_controls(self, event_type: AuditEventType) -> List[str]:
        """Map event types to applicable NIST 800-53 controls."""
        base_controls = ["AU-2", "AU-3", "AU-8", "AU-12"]

        type_specific = {
            AuditEventType.DOCUMENT_ACCESS: ["AU-6", "AU-11"],
            AuditEventType.DOCUMENT_INGEST: ["AU-6"],
            AuditEventType.DOCUMENT_TRANSFORM: ["AU-6", "AU-11"],
            AuditEventType.DOCUMENT_EXPORT: ["AU-6", "AU-9", "AU-11"],
            AuditEventType.COMPLIANCE_SCAN: ["AU-6"],
            AuditEventType.PII_DETECTION: ["AU-6", "SI-4", "SI-19"],
            AuditEventType.CUI_DETECTION: ["AU-6", "AU-9"],
            AuditEventType.EXPORT_CONTROL_SCAN: ["AU-6", "AC-22"],
            AuditEventType.SANITIZATION: ["AU-6", "SI-4"],
            AuditEventType.CLASSIFICATION_CHANGE: ["AU-6", "AU-9", "AU-11"],
            AuditEventType.ACCESS_DENIED: ["AU-6", "AU-9"],
            AuditEventType.CONFIGURATION_CHANGE: ["AU-6", "AU-9", "CM-3"],
            AuditEventType.SYSTEM_ERROR: ["AU-6", "SI-4"],
            AuditEventType.AUDIT_LOG_ACCESS: ["AU-6", "AU-9"],
            AuditEventType.CHAIN_OF_CUSTODY: ["AU-6", "AU-9", "AU-11"],
        }

        specific = type_specific.get(event_type, [])
        return sorted(set(base_controls + specific))

    def _compute_entry_hash(self, entry_content: Dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of an entry, including the previous entry's hash.

        This creates the tamper-evident hash chain per NIST 800-53 AU-9.
        """
        # Canonical JSON serialization for deterministic hashing
        canonical = json.dumps(entry_content, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def _compute_document_hash(self, document_path: str) -> str:
        """Compute SHA-256 hash of a document file."""
        if not document_path or not os.path.exists(document_path):
            return hashlib.sha256(document_path.encode('utf-8')).hexdigest()

        sha256 = hashlib.sha256()
        try:
            with open(document_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
        except (PermissionError, OSError) as e:
            logger.warning("Could not hash document %s: %s", document_path, e)
            return hashlib.sha256(document_path.encode('utf-8')).hexdigest()

        return sha256.hexdigest()

    @staticmethod
    def _genesis_hash() -> str:
        """Generate the genesis hash for the first entry in the chain."""
        return hashlib.sha256(b"GENESIS:docsingest:audit_trail:v1").hexdigest()

    @staticmethod
    def _get_local_ip() -> str:
        """Get the local IP address for audit entries."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _append_to_log(self, entry: AuditEntry) -> None:
        """Append an entry to the audit log file."""
        try:
            log_path = self.log_path
            if log_path is None:
                raise ValueError("log_path is required for file operations")
            os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry.to_dict(), separators=(',', ':')) + '\n')
        except Exception as e:
            logger.error("Failed to write audit entry to %s: %s", self.log_path, e)

    def _load_existing_log(self, log_path: str) -> None:
        """Load existing audit log entries from file."""
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        entry = AuditEntry(
                            entry_id=data['entry_id'],
                            timestamp=data['timestamp'],
                            event_type=data['event_type'],
                            severity=data['severity'],
                            actor=data['actor'],
                            source_host=data['source_host'],
                            source_ip=data['source_ip'],
                            document_path=data['document_path'],
                            document_hash=data['document_hash'],
                            action=data['action'],
                            outcome=data['outcome'],
                            details=data.get('details', {}),
                            previous_hash=data['previous_hash'],
                            entry_hash=data['entry_hash'],
                            nist_controls=data.get('nist_controls', []),
                        )
                        self.entries.append(entry)
                        self._previous_hash = entry.entry_hash
                    except (KeyError, json.JSONDecodeError) as e:
                        logger.warning("Skipping malformed audit entry: %s", e)

            logger.info("Loaded %d existing audit entries from %s", len(self.entries), log_path)

        except Exception as e:
            logger.warning("Could not load existing audit log %s: %s", log_path, e)
