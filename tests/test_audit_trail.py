"""Tests for Audit Trail and Chain of Custody module."""

import json
import os
import tempfile

import pytest

from docsingest.compliance.audit_trail import (
    AuditEventType,
    AuditSeverity,
    AuditTrail,
)


class TestAuditTrail:
    """Test suite for FedRAMP-ready audit trail capabilities."""

    @pytest.fixture
    def trail(self):
        return AuditTrail(actor="test_user")

    @pytest.fixture
    def trail_with_file(self):
        with tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False, mode='w') as tmp:
            tmp_path = tmp.name
        trail = AuditTrail(log_path=tmp_path, actor="test_user")
        yield trail, tmp_path
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # --- Event Logging ---

    def test_log_basic_event(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Document read",
            outcome="success",
        )
        assert entry.event_type == "document_access"
        assert entry.action == "Document read"
        assert entry.outcome == "success"
        assert entry.actor == "test_user"
        assert len(trail.entries) == 1

    def test_log_event_with_details(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.COMPLIANCE_SCAN,
            document_path="/test/doc.txt",
            action="PII scan",
            outcome="success",
            details={"scan_type": "pii", "findings": 5, "risk_score": 75},
        )
        assert entry.details["scan_type"] == "pii"
        assert entry.details["findings"] == 5

    def test_log_event_with_severity(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.ACCESS_DENIED,
            document_path="/test/classified.txt",
            action="Access attempt",
            outcome="failure",
            severity=AuditSeverity.ALERT,
        )
        assert entry.severity == AuditSeverity.ALERT.value

    def test_log_event_actor_override(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Document read",
            outcome="success",
            actor="admin_user",
        )
        assert entry.actor == "admin_user"

    # --- Convenience Methods ---

    def test_log_document_access(self, trail):
        entry = trail.log_document_access("/test/doc.txt", access_type="read")
        assert entry.event_type == "document_access"
        assert "read" in entry.action.lower()

    def test_log_document_ingest(self, trail):
        entry = trail.log_document_ingest(
            "/test/doc.txt", file_type=".docx", tokens=1500
        )
        assert entry.event_type == "document_ingest"
        assert entry.details["file_type"] == ".docx"
        assert entry.details["tokens"] == 1500

    def test_log_compliance_scan(self, trail):
        entry = trail.log_compliance_scan(
            "/test/doc.txt", scan_type="cui", findings_count=3, risk_score=60
        )
        assert entry.event_type == "cui_detection"
        assert entry.details["risk_score"] == 60

    def test_log_compliance_scan_pii(self, trail):
        entry = trail.log_compliance_scan(
            "/test/doc.txt", scan_type="pii", findings_count=5, risk_score=80
        )
        assert entry.event_type == "pii_detection"
        assert entry.severity == AuditSeverity.ALERT.value  # High risk

    def test_log_document_export(self, trail):
        entry = trail.log_document_export(
            "/test/doc.txt", export_format="markdown", destination="/output/report.md"
        )
        assert entry.event_type == "document_export"
        assert entry.details["export_format"] == "markdown"

    # --- SHA-256 Hash Chain ---

    def test_hash_chain_integrity(self, trail):
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc1.txt",
            action="Read",
            outcome="success",
        )
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc2.txt",
            action="Read",
            outcome="success",
        )
        trail.log_event(
            event_type=AuditEventType.COMPLIANCE_SCAN,
            document_path="/test/doc1.txt",
            action="PII scan",
            outcome="success",
        )

        result = trail.verify_integrity()
        assert result["verified"] is True
        assert result["total_entries"] == 3

    def test_hash_chain_links(self, trail):
        entry1 = trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )
        entry2 = trail.log_event(
            event_type=AuditEventType.DOCUMENT_TRANSFORM,
            document_path="/test/doc.txt",
            action="Transform",
            outcome="success",
        )
        # Entry 2's previous_hash should equal entry 1's entry_hash
        assert entry2.previous_hash == entry1.entry_hash

    def test_hash_chain_detects_tampering(self, trail):
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_TRANSFORM,
            document_path="/test/doc.txt",
            action="Transform",
            outcome="success",
        )

        # Tamper with an entry
        trail.entries[0].action = "TAMPERED_ACTION"

        result = trail.verify_integrity()
        assert result["verified"] is False
        assert len(result["errors"]) > 0

    def test_genesis_hash_consistent(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )
        # First entry should reference genesis hash
        genesis = trail._genesis_hash()
        assert entry.previous_hash == genesis

    # --- Unique Entry IDs ---

    def test_unique_entry_ids(self, trail):
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )
        ids = {e.entry_id for e in trail.entries}
        assert len(ids) == 2

    # --- Timestamps ---

    def test_timestamps_are_utc(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )
        assert "T" in entry.timestamp
        assert "+" in entry.timestamp or "Z" in entry.timestamp

    # --- NIST Controls ---

    def test_nist_controls_mapped(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.PII_DETECTION,
            document_path="/test/doc.txt",
            action="PII scan",
            outcome="success",
        )
        assert "AU-2" in entry.nist_controls
        assert "AU-3" in entry.nist_controls
        assert "SI-4" in entry.nist_controls

    def test_nist_controls_for_document_export(self, trail):
        entry = trail.log_event(
            event_type=AuditEventType.DOCUMENT_EXPORT,
            document_path="/test/doc.txt",
            action="Export",
            outcome="success",
        )
        assert "AU-9" in entry.nist_controls

    # --- CEF Export ---

    def test_cef_format(self, trail):
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Document read",
            outcome="success",
        )
        cef = trail.export_cef()
        assert cef.startswith("CEF:0|docsingest|ComplianceAudit|")
        assert "document_access" in cef
        assert "Document read" in cef

    def test_cef_export_to_file(self, trail):
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )
        with tempfile.NamedTemporaryFile(suffix='.cef', delete=False, mode='w') as tmp:
            tmp_path = tmp.name

        try:
            trail.export_cef(output_path=tmp_path)
            assert os.path.exists(tmp_path)
            with open(tmp_path, 'r') as f:
                content = f.read()
            assert "CEF:0" in content
        finally:
            os.unlink(tmp_path)

    def test_cef_multiple_entries(self, trail):
        for i in range(3):
            trail.log_event(
                event_type=AuditEventType.DOCUMENT_ACCESS,
                document_path=f"/test/doc{i}.txt",
                action="Read",
                outcome="success",
            )
        cef = trail.export_cef()
        lines = cef.strip().split('\n')
        assert len(lines) == 3

    # --- Chain of Custody ---

    def test_chain_of_custody_report(self, trail):
        trail.log_document_access("/test/doc.txt")
        trail.log_compliance_scan("/test/doc.txt", "pii", 5, 60)
        trail.log_document_export("/test/doc.txt", "markdown", "/output/report.md")

        report = trail.generate_chain_of_custody_report(document_path="/test/doc.txt")
        assert report["total_documents"] == 1
        assert report["total_events"] == 3
        assert report["integrity_verified"] is True
        assert len(report["custody_records"]) == 1
        assert len(report["custody_records"][0]["actions"]) == 3

    def test_chain_of_custody_multiple_documents(self, trail):
        trail.log_document_access("/test/doc1.txt")
        trail.log_document_access("/test/doc2.txt")
        trail.log_compliance_scan("/test/doc1.txt", "cui", 2, 40)

        report = trail.generate_chain_of_custody_report()
        assert report["total_documents"] == 2

    def test_chain_of_custody_tracks_actors(self, trail):
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
            actor="analyst1",
        )
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_TRANSFORM,
            document_path="/test/doc.txt",
            action="Redact",
            outcome="success",
            actor="analyst2",
        )

        report = trail.generate_chain_of_custody_report(document_path="/test/doc.txt")
        actors = report["custody_records"][0]["actors_involved"]
        assert "analyst1" in actors
        assert "analyst2" in actors

    def test_chain_of_custody_nist_controls(self, trail):
        trail.log_document_access("/test/doc.txt")
        report = trail.generate_chain_of_custody_report()
        assert "AU-2" in report["nist_controls"]
        assert "AU-9" in report["nist_controls"]
        assert "3.3.1" in report["nist_800_171"]

    # --- File Persistence ---

    def test_log_to_file(self, trail_with_file):
        trail, tmp_path = trail_with_file
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
        )

        assert os.path.exists(tmp_path)
        with open(tmp_path, 'r') as f:
            lines = f.readlines()
        assert len(lines) == 1

        data = json.loads(lines[0])
        assert data["event_type"] == "document_access"
        assert data["entry_hash"] is not None

    def test_load_existing_log(self, trail_with_file):
        trail, tmp_path = trail_with_file
        # Log some entries
        trail.log_document_access("/test/doc1.txt")
        trail.log_document_access("/test/doc2.txt")

        # Create new trail from same file
        trail2 = AuditTrail(log_path=tmp_path, actor="test_user2")
        assert len(trail2.entries) == 2

        # Verify integrity of loaded entries
        result = trail2.verify_integrity()
        assert result["verified"] is True

    def test_append_to_existing_log(self, trail_with_file):
        trail, tmp_path = trail_with_file
        trail.log_document_access("/test/doc1.txt")

        # Reload and append
        trail2 = AuditTrail(log_path=tmp_path, actor="test_user")
        trail2.log_document_access("/test/doc2.txt")

        with open(tmp_path, 'r') as f:
            lines = f.readlines()
        assert len(lines) == 2

    # --- Query Methods ---

    def test_get_entries_for_document(self, trail):
        trail.log_document_access("/test/doc1.txt")
        trail.log_document_access("/test/doc2.txt")
        trail.log_compliance_scan("/test/doc1.txt", "pii", 3, 50)

        entries = trail.get_entries_for_document("/test/doc1.txt")
        assert len(entries) == 2

    def test_get_entries_by_type(self, trail):
        trail.log_document_access("/test/doc.txt")
        trail.log_compliance_scan("/test/doc.txt", "pii", 3, 50)
        trail.log_document_export("/test/doc.txt", "md", "/out.md")

        access_entries = trail.get_entries_by_type(AuditEventType.DOCUMENT_ACCESS)
        assert len(access_entries) == 1

    def test_get_entries_by_actor(self, trail):
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
            actor="user_a",
        )
        trail.log_event(
            event_type=AuditEventType.DOCUMENT_ACCESS,
            document_path="/test/doc.txt",
            action="Read",
            outcome="success",
            actor="user_b",
        )

        entries = trail.get_entries_by_actor("user_a")
        assert len(entries) == 1

    # --- Summary ---

    def test_get_summary(self, trail):
        trail.log_document_access("/test/doc1.txt")
        trail.log_document_access("/test/doc2.txt")
        trail.log_compliance_scan("/test/doc1.txt", "pii", 3, 50)

        summary = trail.get_summary()
        assert summary["total_entries"] == 3
        assert summary["documents_tracked"] == 2
        assert "test_user" in summary["actors"]
        assert summary["integrity_verified"] is True

    def test_get_summary_empty(self, trail):
        summary = trail.get_summary()
        assert summary["total_entries"] == 0
        assert summary["date_range"] is None

    # --- To Dict ---

    def test_entry_to_dict(self, trail):
        entry = trail.log_document_access("/test/doc.txt")
        d = entry.to_dict()
        assert isinstance(d, dict)
        assert d["event_type"] == "document_access"
        assert "entry_hash" in d
        assert "previous_hash" in d

    # --- Empty Trail ---

    def test_verify_empty_trail(self, trail):
        result = trail.verify_integrity()
        assert result["verified"] is True
        assert result["total_entries"] == 0
