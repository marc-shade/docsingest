"""Tests for Export Control Screening module."""

import pytest

from docsingest.compliance.export_control import (
    ExportControlRegime,
    ExportControlScreener,
    USMLCategory,
)


class TestExportControlScreener:
    """Test suite for ITAR/EAR export control screening."""

    @pytest.fixture
    def screener(self):
        return ExportControlScreener()

    # --- USML Category Detection ---

    def test_detect_usml_category_reference(self, screener):
        text = "This item falls under USML Category XII fire control equipment."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert report.itar_findings > 0
        assert len(report.usml_categories_referenced) > 0

    def test_detect_usml_category_iv(self, screener):
        text = "USML Category IV guided missiles and launch vehicles."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        usml_findings = [f for f in report.findings if f.finding_type == "usml_reference"]
        assert len(usml_findings) > 0

    def test_detect_usml_category_viii(self, screener):
        text = "Category VIII of the USML covers aircraft and related articles."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_usml_category_xi(self, screener):
        text = "USML Category XI military electronics systems."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_usml_category_xv(self, screener):
        text = "USML Category XV spacecraft and related articles."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_usml_category_xxi(self, screener):
        text = "USML Category XXI miscellaneous defense articles."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_usml_finding_is_critical(self, screener):
        text = "USML Category IV missiles and munitions."
        report = screener.screen(text, filename="test.txt")
        usml_findings = [f for f in report.findings if f.finding_type == "usml_reference"]
        assert all(f.severity == "critical" for f in usml_findings)

    # --- ECCN Pattern Detection ---

    def test_detect_eccn_labeled(self, screener):
        text = "This item is classified as ECCN 3A001 for electronic components."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert report.ear_findings > 0
        assert "3A001" in report.eccn_patterns_found

    def test_detect_eccn_5d002(self, screener):
        text = "Encryption software classified under ECCN 5D002."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert "5D002" in report.eccn_patterns_found

    def test_detect_eccn_9a003(self, screener):
        text = "ECCN: 9A003 aerospace propulsion equipment."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_eccn_in_context(self, screener):
        text = (
            "The export control classification for this item is as follows.\n"
            "ECCN 3A001 applies to the signal processing components.\n"
            "A BIS license may be required for certain destinations."
        )
        report = screener.screen(text, filename="test.txt")
        assert "3A001" in report.eccn_patterns_found

    def test_eccn_finding_has_category_description(self, screener):
        text = "ECCN 5D002 information security software."
        report = screener.screen(text, filename="test.txt")
        eccn_findings = [f for f in report.findings if f.finding_type == "eccn_reference"]
        assert len(eccn_findings) > 0
        assert "Telecommunications" in eccn_findings[0].description

    # --- Controlled Technology Keywords ---

    def test_detect_night_vision(self, screener):
        text = "The system includes advanced night vision capabilities."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert any("night vision" in t.lower() for t in report.controlled_technologies)

    def test_detect_encryption(self, screener):
        text = "Implements AES-256 encryption algorithm for data protection."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_thermal_imaging(self, screener):
        text = "The sensor uses thermal imaging for target detection."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_ballistic_armor(self, screener):
        text = "Ballistic armor plating meets NIJ Level IV specifications."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert report.itar_findings > 0

    def test_detect_inertial_navigation(self, screener):
        text = "The missile uses inertial navigation for terminal guidance."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert report.itar_findings > 0

    def test_detect_radar_absorbing_material(self, screener):
        text = "Coated with radar absorbing material for stealth."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        critical = [f for f in report.findings if f.severity == "critical"]
        assert len(critical) > 0

    def test_detect_directed_energy_weapon(self, screener):
        text = "Research into directed energy weapon systems."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_solid_rocket_motor(self, screener):
        text = "The solid rocket motor provides 50,000 lbs of thrust."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        critical = [f for f in report.findings if f.severity == "critical"]
        assert len(critical) > 0

    def test_detect_zero_day_exploit(self, screener):
        text = "Discovered a zero-day exploit in the target system."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    # --- Foreign Person/Entity Detection ---

    def test_detect_foreign_national(self, screener):
        text = "Briefing attended by foreign national observers."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert len(report.foreign_references) > 0

    def test_detect_deemed_export(self, screener):
        text = "This sharing constitutes a deemed export under EAR."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_foreign_military_sale(self, screener):
        text = "This is part of a foreign military sale to allied nations."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_non_us_person(self, screener):
        text = "Access restricted. Non-U.S. persons must obtain authorization."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    # --- Technical Data Indicators ---

    def test_detect_technical_data_package(self, screener):
        text = "The technical data package (TDP) includes engineering drawings."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert any(f.finding_type == "technical_data" for f in report.findings)

    def test_detect_engineering_drawings(self, screener):
        text = "Classified engineering drawing of the propulsion system."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_distribution_statement(self, screener):
        text = "Distribution statement B applies to this document."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_manufacturing_specification(self, screener):
        text = "Manufacturing process for composite armor panels."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    # --- Dual-Use Indicators ---

    def test_detect_dual_use_technology(self, screener):
        text = "This is a dual-use technology with both military and commercial applications."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True
        assert any(f.finding_type == "dual_use" for f in report.findings)

    def test_detect_wassenaar(self, screener):
        text = "Items controlled under the Wassenaar Arrangement."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    def test_detect_mtcr(self, screener):
        text = "Subject to Missile Technology Control Regime restrictions."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    # --- Risk Scoring ---

    def test_risk_score_no_findings(self, screener):
        text = "This document discusses weather patterns and gardening tips."
        report = screener.screen(text, filename="test.txt")
        assert report.risk_score == 0

    def test_risk_score_increases_with_severity(self, screener):
        text_low = "The system uses AES-256 encryption algorithm."
        text_high = (
            "USML Category IV guided missiles.\n"
            "Solid rocket motor specifications.\n"
            "Foreign military sale to Country X.\n"
            "Warhead design specifications."
        )
        report_low = screener.screen(text_low, filename="test.txt")
        report_high = screener.screen(text_high, filename="test.txt")
        assert report_high.risk_score > report_low.risk_score

    def test_risk_bonus_for_usml_plus_foreign(self, screener):
        text = (
            "USML Category VIII aircraft systems.\n"
            "Briefing attended by foreign national representatives."
        )
        report = screener.screen(text, filename="test.txt")
        assert report.risk_score >= 40  # USML + foreign = high risk

    # --- Classification Recommendations ---

    def test_recommendations_for_usml(self, screener):
        text = "USML Category XII fire control equipment."
        report = screener.screen(text, filename="test.txt")
        assert len(report.classification_recommendations) > 0
        assert any("ITAR" in r or "DDTC" in r for r in report.classification_recommendations)

    def test_recommendations_for_eccn(self, screener):
        text = "ECCN 3A001 electronic components."
        report = screener.screen(text, filename="test.txt")
        assert len(report.classification_recommendations) > 0
        assert any("EAR" in r or "BIS" in r for r in report.classification_recommendations)

    def test_recommendations_for_foreign(self, screener):
        text = "Shared with foreign national engineers."
        report = screener.screen(text, filename="test.txt")
        assert any("deemed export" in r.lower() for r in report.classification_recommendations)

    # --- NIST Controls ---

    def test_nist_controls_applied(self, screener):
        text = "USML Category IV missile systems."
        report = screener.screen(text, filename="test.txt")
        assert "AC-22" in report.nist_controls_applicable
        assert "MP-4" in report.nist_controls_applicable

    # --- Custom Keywords ---

    def test_additional_keywords(self):
        custom_keywords = {
            "quantum radar": ("Quantum radar system", "ITAR", "critical"),
        }
        screener = ExportControlScreener(additional_keywords=custom_keywords)
        text = "Development of quantum radar detection capability."
        report = screener.screen(text, filename="test.txt")
        assert report.export_controlled is True

    # --- Summary ---

    def test_summary_with_findings(self, screener):
        text = "USML Category XII and ECCN 3A001 components."
        report = screener.screen(text, filename="test_doc.txt")
        assert "test_doc.txt" in report.summary
        assert "ITAR" in report.summary or "Risk Score" in report.summary

    def test_summary_no_findings(self, screener):
        text = "Recipe for chocolate cake."
        report = screener.screen(text, filename="recipe.txt")
        assert "No export control indicators" in report.summary

    # --- Clean Document ---

    def test_clean_document(self, screener):
        text = (
            "Annual Report for FY2025\n"
            "Revenue increased by 15% year over year.\n"
            "Customer satisfaction scores remain high.\n"
            "New office locations planned for Q3."
        )
        report = screener.screen(text, filename="annual_report.txt")
        assert report.export_controlled is False
        assert report.itar_findings == 0
        assert report.ear_findings == 0
        assert report.risk_score == 0
