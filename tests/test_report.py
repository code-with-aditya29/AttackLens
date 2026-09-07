import unittest

from datetime import datetime, timezone
from unittest.mock import patch

from models.report_model import (
    REPORT_STATUS_NOT_READY,
    REPORT_STATUS_READY,
    REPORT_TYPE_SECURITY_ASSESSMENT,
    REPORT_VERSION,
    create_report_document,
    create_report_readiness,
    create_report_statistics,
    normalize_datetime,
    normalize_percentage,
    normalize_score,
)

from services.report_service import (
    build_report_readiness,
    build_report_scope,
    build_report_statistics,
    build_vulnerability_summary,
    count_open_ports,
    generate_report_data,
)


# ============================================================
# REPORT SERVICE TESTS
# ============================================================

class ReportServiceTests(unittest.TestCase):

    def setUp(self):
        """
        Create reusable controlled test data.

        These fixtures do not access MongoDB, Nmap, or external
        services. They represent normalized AttackLens analysis data.
        """

        self.assets = [
            {
                "target": "10.0.0.10",
                "hostname": "web-01",
                "ports": [
                    {
                        "port": 22,
                        "state": "open"
                    },
                    {
                        "port": "80",
                        "state": "OPEN"
                    },
                    {
                        "port": 80,
                        "state": "open"
                    },
                    {
                        "port": 443,
                        "state": "closed"
                    },
                    {
                        "port": "invalid",
                        "state": "open"
                    },
                ],
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2026-0001",
                        "severity": "HIGH",
                        "cvss_score": 8.1,
                    }
                ],
            },

            {
                "ip_address": "10.0.0.20",
                "hostname": "db-01",
                "ports": [
                    {
                        "port": 3306,
                        "state": "open"
                    }
                ],
                "cves": [
                    {
                        "cve_id": "CVE-2026-0002",
                        "severity": "MEDIUM",
                        "cvss_score": 5.4,
                    }
                ],
            },
        ]

        self.attack_graph = {
            "relationships": [
                {
                    "source": "10.0.0.10",
                    "target": "10.0.0.20",
                }
            ],

            "paths": [
                {
                    "path": [
                        "10.0.0.10",
                        "10.0.0.20",
                    ],
                    "score": 60,
                    "risk_level": "HIGH",
                }
            ],
        }

        self.defense_analysis = {
            "findings": [
                {
                    "title": "Security-Relevant Asset",
                    "priority": "HIGH",
                }
            ]
        }

        self.mitigation_analysis = {
            "recommendations": [
                {
                    "title": "Restrict Sensitive Service",
                    "category": "service_exposure",
                    "priority": "HIGH",
                    "target": "10.0.0.20",
                }
            ]
        }

        self.risk_comparison = {
            "current_state": {
                "total_assets": 2,
                "vulnerable_assets": 2,
                "vulnerability_count": 2,
                "open_ports": 3,
                "attack_paths": 1,
                "high_risk_attack_paths": 1,
                "risk_score": 60,
                "risk_level": "HIGH",
            },

            "projected_state": {
                "risk_score": 45,
                "risk_level": "MEDIUM",
            },

            "reduction": {
                "risk_points": 15,
                "risk_percentage": 25,
            },

            "statistics": {
                "risk_reduction": 15,
                "risk_reduction_percentage": 25,
            },
        }


    # --------------------------------------------------------
    # COMPLETE REPORT GENERATION
    # --------------------------------------------------------

    def test_generate_report_data_with_supplied_analysis(self):
        """
        Verify that a complete normalized report is created when
        existing analysis results are supplied by the caller.
        """

        report = generate_report_data(
            assets=self.assets,
            attack_graph=self.attack_graph,
            defense_analysis=self.defense_analysis,
            mitigation_analysis=self.mitigation_analysis,
            risk_comparison=self.risk_comparison,
            created_by="user-123",
        )

        self.assertEqual(
            report["report_type"],
            REPORT_TYPE_SECURITY_ASSESSMENT
        )

        self.assertEqual(
            report["report_version"],
            REPORT_VERSION
        )

        self.assertEqual(
            report["status"],
            REPORT_STATUS_READY
        )

        self.assertEqual(
            report["created_by"],
            "user-123"
        )

        self.assertEqual(
            report["scope"]["asset_count"],
            2
        )

        self.assertEqual(
            report["scope"]["target_count"],
            2
        )

        self.assertEqual(
            report["scope"]["targets"],
            [
                "10.0.0.10",
                "10.0.0.20",
            ]
        )

        self.assertEqual(
            report["statistics"]["total_assets"],
            2
        )

        self.assertEqual(
            report["statistics"]["total_vulnerabilities"],
            2
        )

        self.assertEqual(
            report["statistics"]["open_ports"],
            3
        )

        self.assertEqual(
            report["statistics"]["attack_paths"],
            1
        )

        self.assertEqual(
            report["statistics"]["defense_findings"],
            1
        )

        self.assertEqual(
            report["statistics"]["recommendations"],
            1
        )

        self.assertEqual(
            report["statistics"]["current_risk_score"],
            60.0
        )

        self.assertEqual(
            report["statistics"]["projected_risk_score"],
            45.0
        )

        self.assertEqual(
            report["statistics"]["risk_reduction"],
            15.0
        )

        self.assertEqual(
            report["statistics"]["risk_reduction_percentage"],
            25.0
        )

        self.assertEqual(
            report["executive_summary"]["overall_risk_level"],
            "HIGH"
        )

        self.assertEqual(
            report["executive_summary"]["projected_risk_level"],
            "MEDIUM"
        )

        self.assertTrue(
            report["readiness"]["report_generation_available"]
        )


    # --------------------------------------------------------
    # PIPELINE EXECUTION
    # --------------------------------------------------------

    @patch(
        "services.report_service.generate_risk_comparison"
    )
    @patch(
        "services.report_service.generate_mitigation_recommendations"
    )
    @patch(
        "services.report_service.generate_defense_analysis"
    )
    @patch(
        "services.report_service.generate_attack_graph"
    )
    def test_generate_report_data_invokes_pipeline_when_analysis_missing(
        self,
        mock_attack_graph,
        mock_defense_analysis,
        mock_mitigation,
        mock_risk_comparison,
    ):
        """
        Verify that Report Service calls the existing analysis
        pipeline in the required order when results are not supplied.
        """

        calls = []

        def attack_side_effect(
            *,
            assets,
            created_by
        ):
            calls.append(
                "attack"
            )

            self.assertEqual(
                assets,
                self.assets
            )

            self.assertEqual(
                created_by,
                "owner-1"
            )

            return self.attack_graph


        def defense_side_effect(
            *,
            assets,
            attack_graph,
            created_by
        ):
            calls.append(
                "defense"
            )

            self.assertEqual(
                attack_graph,
                self.attack_graph
            )

            return self.defense_analysis


        def mitigation_side_effect(
            *,
            assets,
            attack_graph,
            defense_analysis,
            created_by
        ):
            calls.append(
                "mitigation"
            )

            self.assertEqual(
                defense_analysis,
                self.defense_analysis
            )

            return self.mitigation_analysis


        def risk_side_effect(
            *,
            assets,
            attack_graph,
            defense_analysis,
            mitigation_analysis,
            created_by
        ):
            calls.append(
                "risk"
            )

            self.assertEqual(
                mitigation_analysis,
                self.mitigation_analysis
            )

            return self.risk_comparison


        mock_attack_graph.side_effect = (
            attack_side_effect
        )

        mock_defense_analysis.side_effect = (
            defense_side_effect
        )

        mock_mitigation.side_effect = (
            mitigation_side_effect
        )

        mock_risk_comparison.side_effect = (
            risk_side_effect
        )

        report = generate_report_data(
            assets=self.assets,
            created_by="owner-1",
        )

        self.assertEqual(
            calls,
            [
                "attack",
                "defense",
                "mitigation",
                "risk",
            ]
        )

        self.assertEqual(
            report["status"],
            REPORT_STATUS_READY
        )


    # --------------------------------------------------------
    # EMPTY ENVIRONMENT
    # --------------------------------------------------------

    def test_empty_assets_produce_not_ready_report(self):
        """
        A report without authorized assets must not be available
        for generation.
        """

        report = generate_report_data(
            assets=[],
            attack_graph={},
            defense_analysis={},
            mitigation_analysis={},
            risk_comparison={},
            created_by="owner-empty",
        )

        self.assertEqual(
            report["status"],
            REPORT_STATUS_NOT_READY
        )

        self.assertEqual(
            report["scope"]["asset_count"],
            0
        )

        self.assertEqual(
            report["scope"]["target_count"],
            0
        )

        self.assertEqual(
            report["sections"]["assets"],
            []
        )

        self.assertFalse(
            report[
                "readiness"
            ][
                "report_generation_available"
            ]
        )


    # --------------------------------------------------------
    # ZERO FINDINGS ARE VALID ANALYSIS
    # --------------------------------------------------------

    def test_zero_findings_still_ready_when_asset_exists(self):
        """
        Zero vulnerabilities, zero paths, and zero recommendations
        are valid results when an authorized asset exists.
        """

        assets = [
            {
                "target": "scanme.nmap.org",
                "ports": [
                    {
                        "port": 80,
                        "state": "open"
                    }
                ],
            }
        ]

        report = generate_report_data(
            assets=assets,

            attack_graph={
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
                    "total_assets": 1,
                    "vulnerability_count": 0,
                    "vulnerable_assets": 0,
                    "open_ports": 1,
                    "attack_paths": 0,
                    "high_risk_attack_paths": 0,
                    "risk_score": 8,
                    "risk_level": "LOW",
                },

                "projected_state": {
                    "risk_score": 8,
                    "risk_level": "LOW",
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
        )

        self.assertEqual(
            report["status"],
            REPORT_STATUS_READY
        )

        self.assertTrue(
            report[
                "readiness"
            ][
                "report_generation_available"
            ]
        )

        self.assertTrue(
            report[
                "readiness"
            ][
                "attack_path_analysis"
            ]
        )

        self.assertTrue(
            report[
                "readiness"
            ][
                "defense_analysis"
            ]
        )

        self.assertTrue(
            report[
                "readiness"
            ][
                "mitigation_recommendations"
            ]
        )

        self.assertTrue(
            report[
                "readiness"
            ][
                "risk_comparison"
            ]
        )

        self.assertEqual(
            report["statistics"]["total_vulnerabilities"],
            0
        )

        self.assertEqual(
            report["statistics"]["attack_paths"],
            0
        )

        self.assertEqual(
            report["statistics"]["recommendations"],
            0
        )


    # --------------------------------------------------------
    # REPORT SCOPE
    # --------------------------------------------------------

    def test_build_report_scope_deduplicates_targets(self):
        """
        Verify that duplicate target identifiers are not repeated
        in report scope.
        """

        assets = [
            {
                "target": "10.0.0.1"
            },
            {
                "target": "10.0.0.1"
            },
            {
                "ip_address": "10.0.0.2"
            },
            {
                "target": "   "
            },
            {},
        ]

        scope = build_report_scope(
            assets
        )

        self.assertEqual(
            scope["asset_count"],
            5
        )

        self.assertEqual(
            scope["target_count"],
            2
        )

        self.assertEqual(
            scope["targets"],
            [
                "10.0.0.1",
                "10.0.0.2",
            ]
        )


    # --------------------------------------------------------
    # VULNERABILITY SUMMARY
    # --------------------------------------------------------

    def test_build_vulnerability_summary_supports_known_fields(self):
        """
        Verify support for both historically used vulnerability
        fields: vulnerabilities and cves.
        """

        summary = build_vulnerability_summary(
            self.assets
        )

        self.assertEqual(
            summary["vulnerability_count"],
            2
        )

        self.assertEqual(
            summary["vulnerable_assets"],
            2
        )

        self.assertEqual(
            summary["affected_targets"],
            [
                "10.0.0.10",
                "10.0.0.20",
            ]
        )

        self.assertEqual(
            len(
                summary["findings"]
            ),
            2
        )

        self.assertEqual(
            summary[
                "findings"
            ][0][
                "finding"
            ][
                "cve_id"
            ],
            "CVE-2026-0001"
        )

        self.assertEqual(
            summary[
                "findings"
            ][1][
                "finding"
            ][
                "cve_id"
            ],
            "CVE-2026-0002"
        )


    # --------------------------------------------------------
    # OPEN PORT COUNTING
    # --------------------------------------------------------

    def test_count_open_ports_deduplicates_per_asset(self):
        """
        Verify:
        - duplicate ports are counted once per asset
        - uppercase OPEN is accepted
        - closed ports are ignored
        - invalid ports are ignored
        """

        self.assertEqual(
            count_open_ports(
                self.assets
            ),
            3
        )


    # --------------------------------------------------------
    # REPORT STATISTICS
    # --------------------------------------------------------

    def test_build_report_statistics_uses_comparison_and_analysis_counts(
        self
    ):
        """
        Verify that report statistics correctly combine the
        risk-comparison state and analysis result counts.
        """

        statistics = build_report_statistics(
            assets=self.assets,
            attack_graph=self.attack_graph,
            defense_analysis=self.defense_analysis,
            mitigation_analysis=self.mitigation_analysis,
            risk_comparison=self.risk_comparison,
        )

        self.assertEqual(
            statistics["total_assets"],
            2
        )

        self.assertEqual(
            statistics["total_vulnerabilities"],
            2
        )

        self.assertEqual(
            statistics["vulnerable_assets"],
            2
        )

        self.assertEqual(
            statistics["open_ports"],
            3
        )

        self.assertEqual(
            statistics["attack_paths"],
            1
        )

        self.assertEqual(
            statistics["high_risk_attack_paths"],
            1
        )

        self.assertEqual(
            statistics["defense_findings"],
            1
        )

        self.assertEqual(
            statistics["recommendations"],
            1
        )

        self.assertEqual(
            statistics["current_risk_score"],
            60.0
        )

        self.assertEqual(
            statistics["projected_risk_score"],
            45.0
        )

        self.assertEqual(
            statistics["risk_reduction"],
            15.0
        )

        self.assertEqual(
            statistics["risk_reduction_percentage"],
            25.0
        )


    # --------------------------------------------------------
    # REPORT READINESS
    # --------------------------------------------------------

    def test_build_report_readiness_requires_assets_for_generation(
        self
    ):
        """
        Analysis dictionaries may contain zero findings and still
        be considered completed, but report generation requires
        at least one authorized asset.
        """

        ready = build_report_readiness(
            assets=[
                {
                    "target": "10.0.0.1"
                }
            ],
            attack_graph={},
            defense_analysis={},
            mitigation_analysis={},
            risk_comparison={},
        )

        self.assertTrue(
            ready["asset_inventory"]
        )

        self.assertTrue(
            ready["risk_assessment"]
        )

        self.assertTrue(
            ready["attack_path_analysis"]
        )

        self.assertTrue(
            ready["defense_analysis"]
        )

        self.assertTrue(
            ready["mitigation_recommendations"]
        )

        self.assertTrue(
            ready["risk_comparison"]
        )

        self.assertTrue(
            ready[
                "report_generation_available"
            ]
        )


        not_ready = build_report_readiness(
            assets=[],
            attack_graph={},
            defense_analysis={},
            mitigation_analysis={},
            risk_comparison={},
        )

        self.assertFalse(
            not_ready["asset_inventory"]
        )

        self.assertFalse(
            not_ready[
                "report_generation_available"
            ]
        )


# ============================================================
# REPORT MODEL TESTS
# ============================================================

class ReportModelTests(unittest.TestCase):

    # --------------------------------------------------------
    # REPORT DOCUMENT NORMALIZATION
    # --------------------------------------------------------

    def test_create_report_document_normalizes_core_fields(
        self
    ):
        """
        Verify normalized metadata, status, score boundaries,
        percentage boundaries, and generated timestamp.
        """

        report = create_report_document(
            created_by=12345,

            title="  Test Security Report  ",

            readiness=create_report_readiness(
                report_generation_available=True
            ),

            statistics=create_report_statistics(
                current_risk_score=150,
                projected_risk_score=-5,
                risk_reduction_percentage=130,
            ),
        )

        self.assertTrue(
            report["report_id"]
        )

        self.assertEqual(
            report["report_type"],
            REPORT_TYPE_SECURITY_ASSESSMENT
        )

        self.assertEqual(
            report["report_version"],
            REPORT_VERSION
        )

        self.assertEqual(
            report["title"],
            "Test Security Report"
        )

        self.assertEqual(
            report["created_by"],
            "12345"
        )

        self.assertEqual(
            report["status"],
            REPORT_STATUS_READY
        )

        self.assertEqual(
            report[
                "statistics"
            ][
                "current_risk_score"
            ],
            100.0
        )

        self.assertEqual(
            report[
                "statistics"
            ][
                "projected_risk_score"
            ],
            0.0
        )

        self.assertEqual(
            report[
                "statistics"
            ][
                "risk_reduction_percentage"
            ],
            100.0
        )

        self.assertIsInstance(
            report["generated_at"],
            datetime
        )

        self.assertIsNotNone(
            report[
                "generated_at"
            ].tzinfo
        )


    # --------------------------------------------------------
    # NOT READY STATUS
    # --------------------------------------------------------

    def test_create_report_document_not_ready_without_generation_flag(
        self
    ):
        """
        Report status must be not_ready when generation is not
        available.
        """

        report = create_report_document(
            readiness=create_report_readiness(
                report_generation_available=False
            )
        )

        self.assertEqual(
            report["status"],
            REPORT_STATUS_NOT_READY
        )


    # --------------------------------------------------------
    # SCORE AND PERCENTAGE NORMALIZATION
    # --------------------------------------------------------

    def test_numeric_normalizers_clamp_values(
        self
    ):
        """
        Security scores and percentages must stay within 0-100.
        """

        self.assertEqual(
            normalize_score(
                -10
            ),
            0.0
        )

        self.assertEqual(
            normalize_score(
                45.678
            ),
            45.68
        )

        self.assertEqual(
            normalize_score(
                120
            ),
            100.0
        )

        self.assertEqual(
            normalize_percentage(
                -1
            ),
            0.0
        )

        self.assertEqual(
            normalize_percentage(
                33.333
            ),
            33.33
        )

        self.assertEqual(
            normalize_percentage(
                150
            ),
            100.0
        )


    # --------------------------------------------------------
    # DATETIME NORMALIZATION
    # --------------------------------------------------------

    def test_normalize_datetime_adds_utc_to_naive_datetime(
        self
    ):
        """
        Naive timestamps should become timezone-aware UTC
        timestamps.
        """

        value = datetime(
            2026,
            9,
            7,
            12,
            0,
            0
        )

        normalized = normalize_datetime(
            value
        )

        self.assertEqual(
            normalized.tzinfo,
            timezone.utc
        )


# ============================================================
# TEST ENTRY POINT
# ============================================================

if __name__ == "__main__":
    unittest.main()
    