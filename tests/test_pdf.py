import unittest

from io import BytesIO

from models.report_model import (
    create_executive_summary,
    create_report_document,
    create_report_readiness,
    create_report_scope,
    create_report_statistics,
)

from services.pdf_service import (
    clean_evidence_text,
    format_risk,
    generate_report_pdf,
    humanize_label,
    safe_number,
)


# ============================================================
# PDF SERVICE TESTS
# ============================================================

class PDFServiceTests(unittest.TestCase):

    def setUp(self):
        """
        Build controlled normalized AttackLens report data.

        These tests do not access:
        - MongoDB
        - Nmap
        - external services
        - the browser

        They test PDF rendering only.
        """

        self.assets = [
            {
                "target": "scanme.nmap.org",
                "hostname": "scanme.nmap.org",
                "operating_system": "Linux 4.19 - 5.15",
                "criticality": "normal",
                "exposure": "unknown",

                "ports": [
                    {
                        "port": 22,
                        "state": "open",
                    },
                    {
                        "port": 80,
                        "state": "open",
                    },
                    {
                        "port": 9929,
                        "state": "open",
                    },
                    {
                        "port": 31337,
                        "state": "open",
                    },
                ],

                "risk": {
                    "score": 8,
                    "level": "LOW",
                },

                "vulnerabilities": [],
            }
        ]

        self.attack_graph = {
            "relationships": [],
            "paths": [],
        }

        self.defense_analysis = {
            "findings": [
                {
                    "title": (
                        "Security-Relevant Asset: "
                        "scanme.nmap.org"
                    ),

                    "priority": "LOW",

                    "description": (
                        "This asset contains security evidence "
                        "that increases its defensive importance "
                        "within the current environment."
                    ),

                    "evidence": [
                        "Current asset risk score is 8/100.",

                        (
                            "Security-sensitive open ports "
                            "detected: 22."
                        ),
                    ],
                }
            ]
        }

        self.mitigation_analysis = {
            "recommendations": [
                {
                    "title": (
                        "Review Sensitive Network Services"
                    ),

                    "category": "service_exposure",

                    "priority": "LOW",

                    "score": 8,

                    "target": "scanme.nmap.org",

                    "evidence": [
                        (
                            "Security-sensitive open port(s) "
                            "detected: 22."
                        ),

                        (
                            "Current asset risk score "
                            "is 8.0/100."
                        ),
                    ],

                    "expected_effect": (
                        "Reduced exposure of security-sensitive "
                        "network services and a smaller reachable "
                        "attack surface."
                    ),
                }
            ]
        }

        self.risk_comparison = {
            "current_state": {
                "risk_score": 8,
                "risk_level": "LOW",
                "total_assets": 1,
                "vulnerable_assets": 0,
                "vulnerability_count": 0,
                "open_ports": 4,
                "sensitive_ports": 1,
                "attack_paths": 0,
                "high_risk_attack_paths": 0,
            },

            "projected_state": {
                "risk_score": 6.4,
                "risk_level": "LOW",
                "total_assets": 1,
                "vulnerable_assets": 0,
                "vulnerability_count": 0,
                "open_ports": 4,
                "sensitive_ports": 0,
                "attack_paths": 0,
                "high_risk_attack_paths": 0,
            },

            "reduction": {
                "risk_points": 1.6,
                "risk_percentage": 20,
                "vulnerability_count": 0,
                "sensitive_ports": 1,
                "attack_paths": 0,
            },

            "statistics": {
                "risk_reduction": 1.6,
                "risk_reduction_percentage": 20,
            },
        }

        self.report = create_report_document(
            created_by="test-user",

            title=(
                "AttackLens Security Assessment"
            ),

            scope=create_report_scope(
                asset_count=1,
                target_count=1,

                targets=[
                    "scanme.nmap.org"
                ],

                analysis_source=(
                    "AttackLens Analysis"
                ),
            ),

            executive_summary=create_executive_summary(
                overall_risk_score=8,
                overall_risk_level="LOW",

                asset_count=1,

                vulnerability_count=0,

                attack_path_count=0,

                defense_finding_count=1,

                recommendation_count=1,

                projected_risk_score=6.4,

                projected_risk_level="LOW",

                projected_reduction=1.6,

                projected_reduction_percentage=20,
            ),

            assets=self.assets,

            vulnerability_summary={
                "vulnerability_count": 0,
                "vulnerable_assets": 0,
                "affected_targets": [],
                "findings": [],
            },

            attack_path_analysis=(
                self.attack_graph
            ),

            defense_analysis=(
                self.defense_analysis
            ),

            mitigation_analysis=(
                self.mitigation_analysis
            ),

            risk_comparison=(
                self.risk_comparison
            ),

            readiness=create_report_readiness(
                asset_inventory=True,

                risk_assessment=True,

                attack_path_analysis=True,

                defense_analysis=True,

                mitigation_recommendations=True,

                risk_comparison=True,

                report_generation_available=True,
            ),

            statistics=create_report_statistics(
                total_assets=1,

                total_vulnerabilities=0,

                vulnerable_assets=0,

                open_ports=4,

                attack_paths=0,

                high_risk_attack_paths=0,

                defense_findings=1,

                recommendations=1,

                current_risk_score=8,

                current_risk_level="LOW",

                projected_risk_score=6.4,

                projected_risk_level="LOW",

                risk_reduction=1.6,

                risk_reduction_percentage=20,
            ),
        )


    # --------------------------------------------------------
    # VALID PDF OUTPUT
    # --------------------------------------------------------

    def test_generate_report_pdf_returns_bytesio(self):
        """
        PDF generator must return an in-memory BytesIO stream.
        """

        result = generate_report_pdf(
            self.report
        )

        self.assertIsInstance(
            result,
            BytesIO
        )


    def test_generated_pdf_stream_is_rewound(self):
        """
        The returned PDF stream must be positioned at byte zero
        so Flask send_file can read it correctly.
        """

        result = generate_report_pdf(
            self.report
        )

        self.assertEqual(
            result.tell(),
            0
        )


    def test_generated_pdf_has_valid_pdf_signature(self):
        """
        Generated bytes must begin with a valid PDF signature.
        """

        result = generate_report_pdf(
            self.report
        )

        pdf_bytes = result.getvalue()

        self.assertTrue(
            pdf_bytes.startswith(
                b"%PDF-"
            )
        )


    def test_generated_pdf_contains_eof_marker(self):
        """
        A completed PDF should contain the standard EOF marker.
        """

        result = generate_report_pdf(
            self.report
        )

        pdf_bytes = result.getvalue()

        self.assertIn(
            b"%%EOF",
            pdf_bytes[-1024:]
        )


    def test_generated_pdf_is_not_empty(self):
        """
        A realistic AttackLens report must produce substantial
        PDF output rather than an empty or tiny document.
        """

        result = generate_report_pdf(
            self.report
        )

        pdf_bytes = result.getvalue()

        self.assertGreater(
            len(
                pdf_bytes
            ),
            1000
        )


    # --------------------------------------------------------
    # ZERO-FINDING REPORT
    # --------------------------------------------------------

    def test_zero_findings_report_generates_successfully(self):
        """
        Zero vulnerabilities and zero attack paths are valid
        completed analysis and must not break PDF generation.
        """

        result = generate_report_pdf(
            self.report
        )

        pdf_bytes = result.getvalue()

        self.assertTrue(
            pdf_bytes.startswith(
                b"%PDF-"
            )
        )

        self.assertGreater(
            len(
                pdf_bytes
            ),
            1000
        )


    # --------------------------------------------------------
    # EMPTY / NOT READY REPORT
    # --------------------------------------------------------

    def test_empty_report_document_does_not_crash_pdf_service(self):
        """
        The rendering layer should remain defensive even if it
        receives a normalized report with no assets.
        """

        empty_report = create_report_document(
            created_by="empty-user",

            scope=create_report_scope(),

            executive_summary=(
                create_executive_summary()
            ),

            assets=[],

            vulnerability_summary={
                "vulnerability_count": 0,
                "vulnerable_assets": 0,
                "affected_targets": [],
                "findings": [],
            },

            attack_path_analysis={
                "relationships": [],
                "paths": [],
            },

            defense_analysis={
                "findings": []
            },

            mitigation_analysis={
                "recommendations": []
            },

            risk_comparison={
                "current_state": {},
                "projected_state": {},
                "reduction": {},
                "statistics": {},
            },

            readiness=create_report_readiness(
                report_generation_available=False
            ),

            statistics=(
                create_report_statistics()
            ),
        )

        result = generate_report_pdf(
            empty_report
        )

        self.assertIsInstance(
            result,
            BytesIO
        )

        self.assertTrue(
            result.getvalue().startswith(
                b"%PDF-"
            )
        )


    # --------------------------------------------------------
    # MALFORMED INPUT
    # --------------------------------------------------------

    def test_none_input_is_handled_safely(self):
        """
        PDF service normalizes invalid top-level input and should
        not raise an exception for None.
        """

        result = generate_report_pdf(
            None
        )

        self.assertIsInstance(
            result,
            BytesIO
        )

        self.assertTrue(
            result.getvalue().startswith(
                b"%PDF-"
            )
        )


    def test_empty_dictionary_input_is_handled_safely(self):
        """
        An empty dictionary should still generate a safe PDF
        rather than crashing the renderer.
        """

        result = generate_report_pdf(
            {}
        )

        self.assertIsInstance(
            result,
            BytesIO
        )

        self.assertGreater(
            len(
                result.getvalue()
            ),
            500
        )


    # --------------------------------------------------------
    # SPECIAL CHARACTER SAFETY
    # --------------------------------------------------------

    def test_special_characters_do_not_break_pdf_generation(self):
        """
        ReportLab Paragraph markup-sensitive characters must be
        escaped safely.
        """

        special_report = create_report_document(
            created_by="test-user",

            title=(
                "AttackLens <Security> & Assessment"
            ),

            scope=create_report_scope(
                asset_count=1,

                target_count=1,

                targets=[
                    "host&test.example"
                ],
            ),

            assets=[
                {
                    "target": (
                        "host&test.example"
                    ),

                    "hostname": (
                        "<internal-host>"
                    ),

                    "operating_system": (
                        "Linux & Unix"
                    ),

                    "ports": [
                        {
                            "port": 443,
                            "state": "open",
                        }
                    ],

                    "criticality": "high",

                    "exposure": "external",

                    "risk": {
                        "score": 25,
                        "level": "MEDIUM",
                    },
                }
            ],

            vulnerability_summary={
                "vulnerability_count": 0,
                "vulnerable_assets": 0,
                "affected_targets": [],
                "findings": [],
            },

            attack_path_analysis={
                "relationships": [],
                "paths": [],
            },

            defense_analysis={
                "findings": []
            },

            mitigation_analysis={
                "recommendations": []
            },

            risk_comparison={
                "current_state": {
                    "risk_score": 25,
                    "risk_level": "MEDIUM",
                    "total_assets": 1,
                },

                "projected_state": {
                    "risk_score": 25,
                    "risk_level": "MEDIUM",
                },

                "reduction": {
                    "risk_points": 0,
                    "risk_percentage": 0,
                },

                "statistics": {
                    "risk_reduction": 0,
                    "risk_reduction_percentage": 0,
                },
            },

            readiness=create_report_readiness(
                asset_inventory=True,

                risk_assessment=True,

                attack_path_analysis=True,

                defense_analysis=True,

                mitigation_recommendations=True,

                risk_comparison=True,

                report_generation_available=True,
            ),

            statistics=create_report_statistics(
                total_assets=1,

                current_risk_score=25,

                current_risk_level="MEDIUM",

                projected_risk_score=25,

                projected_risk_level="MEDIUM",
            ),
        )

        result = generate_report_pdf(
            special_report
        )

        self.assertTrue(
            result.getvalue().startswith(
                b"%PDF-"
            )
        )


    # --------------------------------------------------------
    # EVIDENCE CLEANUP
    # --------------------------------------------------------

    def test_clean_evidence_text_removes_bad_punctuation(self):
        """
        PDF display cleanup must remove '.;' sequences.
        """

        value = [
            "Current asset risk score is 8/100.",

            (
                "Security-sensitive open ports "
                "detected: 22."
            ),
        ]

        cleaned = clean_evidence_text(
            value
        )

        self.assertNotIn(
            ".;",
            cleaned
        )

        self.assertIn(
            "8/100;",
            cleaned
        )


    def test_clean_evidence_text_humanizes_port_parentheses(self):
        """
        Generated 'port(s)' wording must be humanized in the PDF.
        """

        value = (
            "Security-sensitive open port(s) "
            "detected: 22."
        )

        cleaned = clean_evidence_text(
            value
        )

        self.assertNotIn(
            "port(s)",
            cleaned
        )

        self.assertIn(
            "open ports",
            cleaned
        )


    # --------------------------------------------------------
    # HUMAN-READABLE LABELS
    # --------------------------------------------------------

    def test_humanize_label_converts_internal_identifier(self):
        """
        Internal model identifiers must become professional
        display labels.
        """

        self.assertEqual(
            humanize_label(
                "security_assessment"
            ),
            "Security Assessment"
        )

        self.assertEqual(
            humanize_label(
                "service_exposure"
            ),
            "Service Exposure"
        )


    # --------------------------------------------------------
    # RISK FORMATTING
    # --------------------------------------------------------

    def test_format_risk_uses_standard_attacklens_format(self):
        """
        Risk display must follow score/100 plus risk level.
        """

        result = format_risk(
            8,
            "low"
        )

        self.assertEqual(
            result,
            "8.00/100 (LOW)"
        )


    def test_safe_number_prevents_negative_values(self):
        """
        PDF numeric rendering must not produce negative security
        values when invalid input is supplied.
        """

        self.assertEqual(
            safe_number(
                -10
            ),
            0.0
        )

        self.assertEqual(
            safe_number(
                "8.456"
            ),
            8.46
        )

        self.assertEqual(
            safe_number(
                "invalid"
            ),
            0.0
        )


# ============================================================
# TEST ENTRY POINT
# ============================================================

if __name__ == "__main__":
    unittest.main()