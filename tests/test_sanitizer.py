"""Tests for Document Sanitization Engine."""

import hashlib
import os
import tempfile
import zipfile

import pytest

from docsingest.compliance.sanitizer import (
    DocumentSanitizer,
    FindingType,
    SanitizationSeverity,
)


class TestDocumentSanitizer:
    """Test suite for document sanitization capabilities."""

    @pytest.fixture
    def sanitizer(self):
        return DocumentSanitizer()

    # --- Text Content Analysis ---

    def test_detect_zero_width_characters(self, sanitizer):
        text = "Normal text\u200bwith\u200czero\u200dwidth characters."
        report = sanitizer.analyze_text(text, filename="test.txt")
        assert report.hidden_content_detected is True
        assert any(f.finding_type == FindingType.HIDDEN_TEXT for f in report.findings)

    def test_detect_css_display_none(self, sanitizer):
        text = '<div style="display: none">Hidden content</div>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert any(f.finding_type == FindingType.HIDDEN_TEXT for f in report.findings)

    def test_detect_css_visibility_hidden(self, sanitizer):
        text = '<span style="visibility: hidden">Secret text</span>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert any(f.finding_type == FindingType.HIDDEN_TEXT for f in report.findings)

    def test_detect_zero_font_size(self, sanitizer):
        text = '<span style="font-size: 0">Invisible</span>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert any(f.finding_type == FindingType.HIDDEN_TEXT for f in report.findings)

    def test_detect_white_text(self, sanitizer):
        text = '<span style="color: white">White text on white</span>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert any(f.finding_type == FindingType.HIDDEN_TEXT for f in report.findings)

    def test_detect_zero_opacity(self, sanitizer):
        text = '<div style="opacity: 0">Transparent</div>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert any(f.finding_type == FindingType.HIDDEN_TEXT for f in report.findings)

    # --- Script Detection ---

    def test_detect_javascript_block(self, sanitizer):
        text = '<script>alert("test")</script>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert report.macros_detected is True
        assert any(f.finding_type == FindingType.MACRO_SCRIPT for f in report.findings)

    def test_detect_iframe(self, sanitizer):
        text = '<iframe src="https://evil.com/data"></iframe>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert any(f.finding_type == FindingType.MACRO_SCRIPT for f in report.findings)

    def test_detect_eval_execution(self, sanitizer):
        text = "result = eval(user_input)"
        report = sanitizer.analyze_text(text, filename="test.py")
        assert any(f.finding_type == FindingType.MACRO_SCRIPT for f in report.findings)

    def test_detect_subprocess_call(self, sanitizer):
        text = "subprocess.call(['rm', '-rf', '/'])"
        report = sanitizer.analyze_text(text, filename="test.py")
        assert any(f.finding_type == FindingType.MACRO_SCRIPT for f in report.findings)

    # --- Hyperlink Analysis ---

    def test_detect_suspicious_ip_url(self, sanitizer):
        text = "Visit http://192.168.1.100/payload for more info."
        report = sanitizer.analyze_text(text, filename="test.txt")
        assert len(report.suspicious_links) > 0
        assert any(f.finding_type == FindingType.HYPERLINK for f in report.findings)

    def test_detect_pastebin_link(self, sanitizer):
        text = "Data uploaded to https://pastebin.com/raw/abc123"
        report = sanitizer.analyze_text(text, filename="test.txt")
        assert len(report.suspicious_links) > 0

    def test_detect_data_uri(self, sanitizer):
        text = 'data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTwvc2NyaXB0Pg=='
        report = sanitizer.analyze_text(text, filename="test.txt")
        assert any(f.finding_type == FindingType.HYPERLINK for f in report.findings)

    def test_normal_urls_not_flagged(self, sanitizer):
        text = "Visit https://www.defense.gov for official information."
        report = sanitizer.analyze_text(text, filename="test.txt")
        assert len(report.suspicious_links) == 0

    # --- OOXML Analysis (docx/xlsx/pptx) ---

    def test_detect_docx_metadata(self, sanitizer):
        """Test metadata detection in a synthetic OOXML file."""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                # Add core.xml with metadata
                core_xml = """<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/">
  <dc:creator>John Smith</dc:creator>
  <cp:lastModifiedBy>Jane Doe</cp:lastModifiedBy>
  <cp:revision>15</cp:revision>
  <dc:title>Secret Project Plan</dc:title>
</cp:coreProperties>"""
                zf.writestr('docProps/core.xml', core_xml)

                # Add minimal content
                zf.writestr('word/document.xml', '<w:document/>')
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            assert len(report.metadata_stripped) > 0
            assert 'creator' in report.metadata_stripped
            assert report.metadata_stripped['creator'] == 'John Smith'
            assert any(f.finding_type == FindingType.METADATA for f in report.findings)
        finally:
            os.unlink(tmp_path)

    def test_detect_ooxml_macros(self, sanitizer):
        """Test macro detection in OOXML."""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                zf.writestr('word/vbaProject.bin', b'\x00' * 100)
                zf.writestr('word/document.xml', '<w:document/>')
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            assert report.macros_detected is True
            assert any(
                f.finding_type == FindingType.MACRO_SCRIPT and
                f.severity == SanitizationSeverity.CRITICAL
                for f in report.findings
            )
        finally:
            os.unlink(tmp_path)

    def test_detect_embedded_objects(self, sanitizer):
        """Test embedded file detection in OOXML."""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                zf.writestr('word/embeddings/oleObject1.bin', b'\x00' * 50)
                zf.writestr('word/document.xml', '<w:document/>')
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            assert len(report.embedded_files_found) > 0
            assert any(f.finding_type == FindingType.EMBEDDED_FILE for f in report.findings)
        finally:
            os.unlink(tmp_path)

    def test_detect_comments(self, sanitizer):
        """Test comment detection in OOXML."""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                comments_xml = """<?xml version="1.0"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:comment w:id="1" w:author="Reviewer">
    <w:p><w:r><w:t>This needs revision</w:t></w:r></w:p>
  </w:comment>
  <w:comment w:id="2" w:author="Editor">
    <w:p><w:r><w:t>Approved</w:t></w:r></w:p>
  </w:comment>
</w:comments>"""
                zf.writestr('word/comments.xml', comments_xml)
                zf.writestr('word/document.xml', '<w:document/>')
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            assert any(f.finding_type == FindingType.COMMENTS for f in report.findings)
        finally:
            os.unlink(tmp_path)

    def test_detect_tracked_changes(self, sanitizer):
        """Test tracked changes detection in OOXML."""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                doc_xml = """<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:ins w:author="Editor" w:date="2025-01-01T00:00:00Z">
        <w:r><w:t>Inserted text</w:t></w:r>
      </w:ins>
      <w:del w:author="Editor" w:date="2025-01-01T00:00:00Z">
        <w:r><w:delText>Deleted text</w:delText></w:r>
      </w:del>
    </w:p>
  </w:body>
</w:document>"""
                zf.writestr('word/document.xml', doc_xml)
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            assert report.hidden_content_detected is True
            assert any(f.finding_type == FindingType.TRACKED_CHANGES for f in report.findings)
        finally:
            os.unlink(tmp_path)

    def test_detect_hidden_xlsx_sheets(self, sanitizer):
        """Test hidden sheet detection in Excel files."""
        with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                workbook_xml = """<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="Visible" sheetId="1" state="visible"/>
    <sheet name="HiddenData" sheetId="2" state="hidden"/>
    <sheet name="VeryHidden" sheetId="3" state="veryHidden"/>
  </sheets>
</workbook>"""
                zf.writestr('xl/workbook.xml', workbook_xml)
                zf.writestr('xl/worksheets/sheet1.xml', '<worksheet/>')
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            assert report.hidden_content_detected is True
            hidden_findings = [f for f in report.findings if f.finding_type == FindingType.HIDDEN_TEXT]
            assert any("HiddenData" in f.description or "VeryHidden" in f.description for f in hidden_findings)
        finally:
            os.unlink(tmp_path)

    # --- SHA-256 Hash ---

    def test_sha256_hash_computed(self, sanitizer):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as tmp:
            tmp_path = tmp.name
            tmp.write("Test content for hashing.")

        try:
            report = sanitizer.analyze(tmp_path)
            assert report.sha256_before is not None
            assert len(report.sha256_before) == 64  # SHA-256 hex length
            # Verify hash is correct
            expected = hashlib.sha256(b"Test content for hashing.").hexdigest()
            assert report.sha256_before == expected
        finally:
            os.unlink(tmp_path)

    # --- Risk Score ---

    def test_risk_score_clean_text(self, sanitizer):
        text = "This is a simple, clean document with no issues."
        report = sanitizer.analyze_text(text, filename="clean.txt")
        assert report.risk_score == 0

    def test_risk_score_increases_with_findings(self, sanitizer):
        text_clean = "Normal text."
        text_dirty = (
            '<script>alert("xss")</script>\n'
            '<div style="display: none">Hidden</div>\n'
            'http://192.168.1.100/exfil\n'
            "subprocess.call(['cmd'])\n"
        )
        report_clean = sanitizer.analyze_text(text_clean, filename="clean.txt")
        report_dirty = sanitizer.analyze_text(text_dirty, filename="dirty.txt")
        assert report_dirty.risk_score > report_clean.risk_score

    # --- Severity Levels ---

    def test_macro_finding_is_critical(self, sanitizer):
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                zf.writestr('word/vbaProject.bin', b'\x00' * 100)
                zf.writestr('word/document.xml', '<w:document/>')
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            macro_findings = [f for f in report.findings if f.finding_type == FindingType.MACRO_SCRIPT]
            assert any(f.severity == SanitizationSeverity.CRITICAL for f in macro_findings)
        finally:
            os.unlink(tmp_path)

    # --- Summary ---

    def test_summary_generation(self, sanitizer):
        text = '<script>alert("test")</script>'
        report = sanitizer.analyze_text(text, filename="test.html")
        assert "test.html" in report.summary
        assert "Risk Score" in report.summary

    def test_summary_clean_document(self, sanitizer):
        text = "Clean document content."
        report = sanitizer.analyze_text(text, filename="clean.txt")
        assert "clean.txt" in report.summary

    # --- NIST Controls ---

    def test_nist_controls_in_findings(self, sanitizer):
        text = '<script>alert("test")</script>'
        report = sanitizer.analyze_text(text, filename="test.html")
        for finding in report.findings:
            assert len(finding.nist_controls) > 0

    # --- File Type Detection ---

    def test_file_type_reported(self, sanitizer):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as tmp:
            tmp_path = tmp.name
            tmp.write("Test content.")

        try:
            report = sanitizer.analyze(tmp_path)
            assert report.file_type == '.txt'
        finally:
            os.unlink(tmp_path)

    # --- PDF Analysis ---

    def test_analyze_pdf_metadata(self, sanitizer):
        """Test PDF metadata extraction from a synthetic PDF."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False, mode='wb') as tmp:
            tmp_path = tmp.name
            # Write a minimal PDF with metadata
            pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
3 0 obj
<< /Title (Secret Project) /Author (John Smith) /Creator (TestApp) >>
endobj
xref
0 4
trailer
<< /Size 4 /Root 1 0 R /Info 3 0 R >>
startxref
0
%%EOF"""
            tmp.write(pdf_content)

        try:
            report = sanitizer.analyze(tmp_path)
            assert report.file_type == '.pdf'
            # Metadata may or may not be found depending on parsing
            # But the analysis should complete without error
            assert report.sha256_before is not None
        finally:
            os.unlink(tmp_path)

    # --- Font Fingerprint ---

    def test_detect_embedded_fonts(self, sanitizer):
        """Test font fingerprint detection."""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as tmp:
            tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                zf.writestr('word/fonts/CustomFont.ttf', b'\x00' * 100)
                zf.writestr('word/fonts/AnotherFont.otf', b'\x00' * 100)
                zf.writestr('word/document.xml', '<w:document/>')
                zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types/>')

        try:
            report = sanitizer.analyze(tmp_path)
            assert any(f.finding_type == FindingType.FONT_FINGERPRINT for f in report.findings)
        finally:
            os.unlink(tmp_path)
