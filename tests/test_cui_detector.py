"""Tests for CUI Detection and Classification module."""

import pytest

from docsingest.compliance.cui_detector import (
    ClassificationLevel,
    CUICategory,
    CUIDetector,
    DisseminationControl,
)


class TestCUIDetector:
    """Test suite for CUI detection capabilities."""

    @pytest.fixture
    def detector(self):
        return CUIDetector()

    # --- CUI Marking Detection ---

    def test_detect_basic_cui_marking(self, detector):
        text = "This document is marked CUI and contains controlled information."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert len(report.cui_markings) >= 1
        assert any(m.marking_text == "CUI" for m in report.cui_markings)

    def test_detect_cui_specified_category(self, detector):
        text = "CUI//SP-CTI - This contains controlled technical information."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.CTI for m in report.cui_markings)

    def test_detect_cui_specified_itar(self, detector):
        text = "CUI//SP-ITAR - International Traffic in Arms Regulations controlled."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.ITAR for m in report.cui_markings)

    def test_detect_cui_rel_to(self, detector):
        text = "CUI//REL TO USA, GBR, AUS"
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any("REL TO" in m.marking_text for m in report.cui_markings)

    def test_detect_fouo_legacy_marking(self, detector):
        text = "FOR OFFICIAL USE ONLY\nThis document contains FOUO information."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.FOUO for m in report.cui_markings)

    def test_detect_sbu_marking(self, detector):
        text = "SENSITIVE BUT UNCLASSIFIED - Handle accordingly."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.SBU for m in report.cui_markings)

    def test_detect_les_marking(self, detector):
        text = "LAW ENFORCEMENT SENSITIVE - Do not distribute."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.LES for m in report.cui_markings)

    # --- Classification Banner Detection ---

    def test_detect_unclassified_banner(self, detector):
        text = "UNCLASSIFIED\n\nThis is an unclassified document.\n\nUNCLASSIFIED"
        report = detector.detect(text, filename="test.txt")
        assert any(
            b.level == ClassificationLevel.UNCLASSIFIED
            for b in report.classification_banners
        )

    def test_detect_unclassified_fouo_banner(self, detector):
        text = "UNCLASSIFIED//FOUO\n\nSensitive but unclassified content.\n\nUNCLASSIFIED//FOUO"
        report = detector.detect(text, filename="test.txt")
        assert any(
            b.level == ClassificationLevel.UNCLASSIFIED_FOUO
            for b in report.classification_banners
        )

    def test_detect_secret_banner(self, detector):
        text = "SECRET\n\nClassified document content.\n\nSECRET"
        report = detector.detect(text, filename="test.txt")
        assert report.classification_detected is True
        assert any(
            b.level == ClassificationLevel.SECRET
            for b in report.classification_banners
        )

    def test_detect_top_secret_banner(self, detector):
        text = "TOP SECRET\n\nHighly classified content.\n\nTOP SECRET"
        report = detector.detect(text, filename="test.txt")
        assert report.classification_detected is True
        assert any(
            b.level == ClassificationLevel.TOP_SECRET
            for b in report.classification_banners
        )

    def test_detect_top_secret_sci_banner(self, detector):
        text = "TOP SECRET//SCI\n\nSCI content.\n\nTOP SECRET//SCI"
        report = detector.detect(text, filename="test.txt")
        assert report.classification_detected is True
        assert any(
            b.level == ClassificationLevel.TOP_SECRET_SCI
            for b in report.classification_banners
        )

    def test_banner_position_detection(self, detector):
        text = "SECRET\n\nContent here.\n\nMore content.\n\nSECRET"
        report = detector.detect(text, filename="test.txt")
        positions = {b.position_in_document for b in report.classification_banners}
        assert "header" in positions or "footer" in positions

    # --- Dissemination Control Detection ---

    def test_detect_noforn(self, detector):
        text = "NOFORN - Not releasable to foreign nationals."
        report = detector.detect(text, filename="test.txt")
        assert any(
            d.control == DisseminationControl.NOFORN
            for d in report.dissemination_controls
        )

    def test_detect_rel_to_countries(self, detector):
        text = "REL TO USA, GBR, CAN, AUS, NZL"
        report = detector.detect(text, filename="test.txt")
        rel_to = [d for d in report.dissemination_controls if d.control == DisseminationControl.REL_TO]
        assert len(rel_to) >= 1

    def test_detect_orcon(self, detector):
        text = "ORCON - Originator Controlled distribution."
        report = detector.detect(text, filename="test.txt")
        assert any(
            d.control == DisseminationControl.ORCON
            for d in report.dissemination_controls
        )

    def test_detect_propin(self, detector):
        text = "PROPIN - Proprietary Information Involved."
        report = detector.detect(text, filename="test.txt")
        assert any(
            d.control == DisseminationControl.PROPIN
            for d in report.dissemination_controls
        )

    # --- Marking Compliance Checks ---

    def test_flag_missing_header_banner(self, detector):
        text = "Some content here.\n\nThis document contains CUI information.\n\nMore content."
        report = detector.detect(text, filename="test.txt")
        assert len(report.marking_deficiencies) > 0
        assert any("banner" in d.lower() for d in report.marking_deficiencies)

    def test_flag_contradictory_noforn_rel_to(self, detector):
        text = "NOFORN\nREL TO GBR, AUS\nDocument content here."
        report = detector.detect(text, filename="test.txt")
        assert any("contradictory" in d.lower() or "noforn" in d.lower() for d in report.marking_deficiencies)

    def test_flag_legacy_fouo(self, detector):
        text = "FOUO\nThis document is for official use only."
        report = detector.detect(text, filename="test.txt")
        assert any("legacy" in d.lower() or "fouo" in d.lower() for d in report.marking_deficiencies)

    # --- Risk Scoring ---

    def test_risk_score_no_markings(self, detector):
        text = "This is a plain document with no sensitive markings."
        report = detector.detect(text, filename="test.txt")
        assert report.risk_score == 0

    def test_risk_score_increases_with_classification(self, detector):
        text_low = "CUI\nSome controlled information."
        text_high = "TOP SECRET\nHighly classified content."
        report_low = detector.detect(text_low, filename="test.txt")
        report_high = detector.detect(text_high, filename="test.txt")
        assert report_high.risk_score > report_low.risk_score

    def test_risk_score_itar_high(self, detector):
        text = "CUI//SP-ITAR\nITAR controlled technical data."
        report = detector.detect(text, filename="test.txt")
        assert report.risk_score >= 25

    # --- Handling Recommendations ---

    def test_handling_recommendations_for_cui(self, detector):
        text = "CUI//SP-CTI\nControlled technical information."
        report = detector.detect(text, filename="test.txt")
        assert len(report.handling_recommendations) > 0
        assert any("NIST" in r or "800-171" in r for r in report.handling_recommendations)

    def test_handling_recommendations_for_classified(self, detector):
        text = "SECRET\nClassified defense information.\nSECRET"
        report = detector.detect(text, filename="test.txt")
        assert any("classified" in r.lower() for r in report.handling_recommendations)

    def test_handling_recommendations_for_itar(self, detector):
        text = "CUI//SP-ITAR\nITAR restricted data."
        report = detector.detect(text, filename="test.txt")
        assert any("itar" in r.lower() or "foreign" in r.lower() for r in report.handling_recommendations)

    # --- NIST Controls ---

    def test_nist_controls_for_cui(self, detector):
        text = "CUI\nControlled information."
        report = detector.detect(text, filename="test.txt")
        assert "3.1.1" in report.nist_800_171_controls
        assert "3.8.1" in report.nist_800_171_controls

    # --- Summary ---

    def test_summary_generation(self, detector):
        text = "CUI//SP-CTI\nControlled technical information."
        report = detector.detect(text, filename="test_doc.txt")
        assert "test_doc.txt" in report.summary
        assert "CUI" in report.summary

    # --- Expanded CUI Registry Subcategory Tests ---

    def test_detect_cui_specified_prvcy(self, detector):
        text = "CUI//SP-PRVCY - Privacy protected information."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.PRVCY for m in report.cui_markings)

    def test_detect_cui_specified_intel(self, detector):
        text = "CUI//SP-INTEL - Intelligence community information."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.INTEL for m in report.cui_markings)

    def test_detect_cui_specified_expt(self, detector):
        text = "CUI//SP-EXPT - Export controlled technical data."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.EXPT for m in report.cui_markings)

    def test_detect_ceii_legacy_marking(self, detector):
        text = "CRITICAL ENERGY INFRASTRUCTURE INFORMATION - Do not release."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.CEII for m in report.cui_markings)

    def test_detect_ucni_legacy_marking(self, detector):
        text = "UNCLASSIFIED CONTROLLED NUCLEAR INFORMATION."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.UCNI for m in report.cui_markings)

    def test_detect_nnpi_legacy_marking(self, detector):
        text = "NAVAL NUCLEAR PROPULSION INFORMATION - Distribution limited."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.NNPI for m in report.cui_markings)

    def test_detect_fti_legacy_marking(self, detector):
        text = "FEDERAL TAX INFORMATION - IRC 6103 protected."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.FTI for m in report.cui_markings)

    def test_detect_sbir_legacy_marking(self, detector):
        text = "SMALL BUSINESS INNOVATION RESEARCH data enclosed."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.SBIR for m in report.cui_markings)

    def test_detect_comsec_legacy_marking(self, detector):
        text = "COMSEC - Communications Security procedures apply."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.COMSEC for m in report.cui_markings)

    def test_detect_deliberative_process(self, detector):
        text = "DELIBERATIVE PROCESS - Pre-decisional draft."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.DELIBERATIVE for m in report.cui_markings)

    def test_detect_cfats_marking(self, detector):
        text = "CFATS - Chemical Facility Anti-Terrorism Standards data."
        report = detector.detect(text, filename="test.txt")
        assert report.cui_detected is True
        assert any(m.category == CUICategory.CHEM for m in report.cui_markings)

    def test_cui_category_resolution_new_categories(self, detector):
        """Test that new CUI categories resolve correctly from SP markings."""
        for cat_name in ['CEII', 'UCNI', 'NNPI', 'FTI', 'COMSEC', 'SBIR', 'STTR']:
            text = f"CUI//SP-{cat_name} - Test data."
            report = detector.detect(text, filename="test.txt")
            assert report.cui_detected is True, f"Failed to detect CUI//SP-{cat_name}"
            assert any(
                m.category is not None and m.category.name == cat_name
                for m in report.cui_markings
            ), f"Failed to resolve category {cat_name}"

    # --- No CUI Document ---

    def test_clean_document(self, detector):
        text = (
            "This is a completely normal document.\n"
            "It discusses weather patterns and sports.\n"
            "Nothing sensitive here at all."
        )
        report = detector.detect(text, filename="clean.txt")
        assert report.cui_detected is False
        assert report.classification_detected is False
        assert report.risk_score == 0
        assert len(report.findings) == 0
