# ==========================================
# MITIGATION ENGINE TESTS
# ==========================================


import unittest


from models.mitigation_model import (
    create_mitigation_document,
    create_mitigation_recommendation,
    create_mitigation_statistics,
    normalize_score,
    normalize_priority_level,
    normalize_confidence,
    normalize_port_list
)


from services.mitigation_service import (
    generate_mitigation_recommendations,
    normalize_assets,
    normalize_defense_analysis,
    normalize_attack_graph,
    build_asset_index,
    generate_sensitive_service_recommendations,
    generate_external_exposure_recommendations,
    generate_vulnerability_recommendations,
    generate_relationship_recommendations,
    generate_attack_path_recommendations,
    determine_priority_level,
    get_open_ports,
    get_sensitive_open_ports,
    get_vulnerabilities,
    extract_cve_ids,
    get_highest_vulnerability_severity,
    normalize_exposure,
    normalize_port_number,
    deduplicate_recommendations,
    sort_recommendations
)


class TestMitigationEngine(
    unittest.TestCase
):


    def setUp(
        self
    ):

        self.user_id = (
            "user-001"
        )

        self.other_user_id = (
            "user-002"
        )


        self.low_risk_asset = {

            "_id":
                "asset-low",

            "created_by":
                self.user_id,

            "target":
                "127.0.0.1",

            "ports": [
                {
                    "port": 80,
                    "state": "open",
                    "service": "http"
                }
            ],

            "vulnerabilities":
                [],

            "risk_score":
                5,

            "risk_level":
                "LOW",

            "criticality":
                "NORMAL",

            "exposure":
                "INTERNAL"
        }


        self.sensitive_asset = {

            "_id":
                "asset-sensitive",

            "created_by":
                self.user_id,

            "target":
                "10.0.0.10",

            "ports": [
                {
                    "port": 135,
                    "state": "open",
                    "service": "msrpc"
                },
                {
                    "port": 445,
                    "state": "open",
                    "service": "microsoft-ds"
                },
                {
                    "port": 443,
                    "state": "closed",
                    "service": "https"
                }
            ],

            "vulnerabilities":
                [],

            "risk_score":
                18,

            "risk_level":
                "LOW",

            "criticality":
                "HIGH",

            "exposure":
                "INTERNAL"
        }


        self.external_asset = {

            "_id":
                "asset-external",

            "created_by":
                self.user_id,

            "target":
                "192.0.2.10",

            "ports": [
                {
                    "port": 443,
                    "state": "open",
                    "service": "https"
                }
            ],

            "vulnerabilities":
                [],

            "risk_score":
                35,

            "risk_level":
                "MEDIUM",

            "criticality":
                "HIGH",

            "exposure":
                "EXTERNAL"
        }


        self.vulnerable_asset = {

            "_id":
                "asset-vulnerable",

            "created_by":
                self.user_id,

            "target":
                "10.0.0.25",

            "ports": [
                {
                    "port": 80,
                    "state": "open",
                    "service": "http"
                }
            ],

            "vulnerabilities": [
                {
                    "cve_id":
                        "CVE-2026-1234",

                    "severity":
                        "HIGH",

                    "score":
                        8.1
                }
            ],

            "risk_score":
                68,

            "risk_level":
                "HIGH",

            "criticality":
                "HIGH",

            "exposure":
                "INTERNAL"
        }


        self.defense_analysis = {

            "findings": [

                {
                    "id":
                        "finding-relationship",

                    "finding_type":
                        "relationship_choke_point",

                    "title":
                        "Potential Defensive Choke Point",

                    "target":
                        "10.0.0.10",

                    "asset_id":
                        "asset-sensitive",

                    "score":
                        45,

                    "confidence":
                        "MEDIUM",

                    "evidence": [
                        "Potential graph relationship."
                    ]
                }

            ],

            "priorities": [

                {
                    "id":
                        "priority-sensitive",

                    "target":
                        "10.0.0.10",

                    "score":
                        45
                }

            ],

            "statistics": {
                "total_findings": 1
            }
        }


        self.attack_graph = {

            "nodes": [
                {
                    "id":
                        "external-attacker",
                    "node_type":
                        "attacker"
                },
                {
                    "id":
                        "asset-external",
                    "node_type":
                        "asset"
                },
                {
                    "id":
                        "asset-sensitive",
                    "node_type":
                        "asset"
                }
            ],

            "edges": [
                {
                    "id":
                        "edge-entry",
                    "source":
                        "external-attacker",
                    "target":
                        "asset-external"
                },
                {
                    "id":
                        "edge-pivot",
                    "source":
                        "asset-external",
                    "target":
                        "asset-sensitive"
                }
            ],

            "paths": [
                {
                    "id":
                        "path-1",

                    "nodes": [
                        "external-attacker",
                        "asset-external",
                        "asset-sensitive"
                    ],

                    "edges": [
                        "edge-entry",
                        "edge-pivot"
                    ],

                    "score":
                        70,

                    "risk_level":
                        "HIGH",

                    "confidence":
                        "MEDIUM",

                    "evidence": [
                        "Potential attacker progression."
                    ]
                }
            ],

            "statistics": {
                "total_paths": 1
            }
        }


    # ======================================
    # MODEL
    # ======================================

    def test_create_empty_document(
        self
    ):

        document = (
            create_mitigation_document(
                created_by=self.user_id
            )
        )

        self.assertEqual(
            document[
                "created_by"
            ],
            self.user_id
        )

        self.assertEqual(
            document[
                "recommendations"
            ],
            []
        )


    def test_create_recommendation(
        self
    ):

        recommendation = (
            create_mitigation_recommendation(

                recommendation_id=
                    "rec-1",

                category=
                    "test",

                title=
                    "Test Recommendation",

                description=
                    "Test",

                score=
                    80,

                priority_level=
                    "critical",

                confidence=
                    "high",

                related_ports=[
                    445
                ]
            )
        )

        self.assertEqual(
            recommendation[
                "score"
            ],
            80
        )

        self.assertEqual(
            recommendation[
                "priority_level"
            ],
            "CRITICAL"
        )


    def test_statistics(
        self
    ):

        recommendations = [

            create_mitigation_recommendation(
                "a",
                "test",
                "A",
                "A",
                target="10.0.0.1",
                score=80,
                priority_level="CRITICAL"
            ),

            create_mitigation_recommendation(
                "b",
                "test",
                "B",
                "B",
                target="10.0.0.2",
                score=60,
                priority_level="HIGH"
            )
        ]

        statistics = (
            create_mitigation_statistics(
                recommendations
            )
        )

        self.assertEqual(
            statistics[
                "total_recommendations"
            ],
            2
        )

        self.assertEqual(
            statistics[
                "affected_assets"
            ],
            2
        )

        self.assertEqual(
            statistics[
                "highest_score"
            ],
            80
        )


    # ======================================
    # NORMALIZATION
    # ======================================

    def test_score_normalization(
        self
    ):

        self.assertEqual(
            normalize_score(
                150
            ),
            100
        )

        self.assertEqual(
            normalize_score(
                -10
            ),
            0
        )


    def test_priority_normalization(
        self
    ):

        self.assertEqual(
            normalize_priority_level(
                "high"
            ),
            "HIGH"
        )


    def test_confidence_normalization(
        self
    ):

        self.assertEqual(
            normalize_confidence(
                "medium"
            ),
            "MEDIUM"
        )


    def test_port_normalization(
        self
    ):

        self.assertEqual(
            normalize_port_list(
                [
                    445,
                    "135",
                    445,
                    70000
                ]
            ),
            [
                135,
                445
            ]
        )


    # ======================================
    # OWNER ISOLATION
    # ======================================

    def test_asset_owner_isolation(
        self
    ):

        other_asset = dict(
            self.low_risk_asset
        )

        other_asset[
            "created_by"
        ] = self.other_user_id

        assets = normalize_assets(
            [
                self.low_risk_asset,
                other_asset
            ],
            created_by=self.user_id
        )

        self.assertEqual(
            len(
                assets
            ),
            1
        )


    # ======================================
    # PORTS
    # ======================================

    def test_open_ports(
        self
    ):

        self.assertEqual(
            get_open_ports(
                self.sensitive_asset
            ),
            [
                135,
                445
            ]
        )


    def test_sensitive_ports(
        self
    ):

        self.assertEqual(
            get_sensitive_open_ports(
                self.sensitive_asset
            ),
            [
                135,
                445
            ]
        )


    def test_invalid_ports_safe(
        self
    ):

        self.assertIsNone(
            normalize_port_number(
                "invalid"
            )
        )


    # ======================================
    # SENSITIVE SERVICES
    # ======================================

    def test_sensitive_service_recommendation(
        self
    ):

        recommendations = (
            generate_sensitive_service_recommendations(
                [
                    self.sensitive_asset
                ]
            )
        )

        self.assertEqual(
            len(
                recommendations
            ),
            1
        )

        self.assertEqual(
            recommendations[0][
                "category"
            ],
            "service_exposure"
        )


    def test_low_risk_http_does_not_generate_sensitive_service_recommendation(
        self
    ):

        recommendations = (
            generate_sensitive_service_recommendations(
                [
                    self.low_risk_asset
                ]
            )
        )

        self.assertEqual(
            recommendations,
            []
        )


    # ======================================
    # EXTERNAL EXPOSURE
    # ======================================

    def test_external_exposure_recommendation(
        self
    ):

        recommendations = (
            generate_external_exposure_recommendations(
                [
                    self.external_asset
                ]
            )
        )

        self.assertEqual(
            len(
                recommendations
            ),
            1
        )

        self.assertEqual(
            recommendations[0][
                "category"
            ],
            "exposure_reduction"
        )


    def test_internal_asset_no_external_recommendation(
        self
    ):

        recommendations = (
            generate_external_exposure_recommendations(
                [
                    self.low_risk_asset
                ]
            )
        )

        self.assertEqual(
            recommendations,
            []
        )


    # ======================================
    # VULNERABILITIES
    # ======================================

    def test_cve_extraction(
        self
    ):

        cves = extract_cve_ids(
            self.vulnerable_asset[
                "vulnerabilities"
            ]
        )

        self.assertEqual(
            cves,
            [
                "CVE-2026-1234"
            ]
        )


    def test_vulnerability_recommendation(
        self
    ):

        recommendations = (
            generate_vulnerability_recommendations(
                [
                    self.vulnerable_asset
                ]
            )
        )

        self.assertEqual(
            len(
                recommendations
            ),
            1
        )

        self.assertIn(
            "CVE-2026-1234",
            recommendations[0][
                "related_cves"
            ]
        )


    def test_no_vulnerability_no_patch_recommendation(
        self
    ):

        recommendations = (
            generate_vulnerability_recommendations(
                [
                    self.low_risk_asset
                ]
            )
        )

        self.assertEqual(
            recommendations,
            []
        )


    def test_highest_vulnerability_severity(
        self
    ):

        severity = (
            get_highest_vulnerability_severity(
                self.vulnerable_asset[
                    "vulnerabilities"
                ]
            )
        )

        self.assertEqual(
            severity,
            "HIGH"
        )


    # ======================================
    # RELATIONSHIP
    # ======================================

    def test_relationship_recommendation(
        self
    ):

        recommendations = (
            generate_relationship_recommendations(

                defense_analysis=
                    self.defense_analysis,

                attack_graph=
                    self.attack_graph,

                asset_index=
                    build_asset_index(
                        [
                            self.sensitive_asset
                        ]
                    )
            )
        )

        self.assertEqual(
            len(
                recommendations
            ),
            1
        )

        self.assertEqual(
            recommendations[0][
                "category"
            ],
            "segmentation"
        )


    # ======================================
    # ATTACK PATH
    # ======================================

    def test_attack_path_recommendation(
        self
    ):

        asset_index = (
            build_asset_index(
                [
                    self.external_asset,
                    self.sensitive_asset
                ]
            )
        )

        recommendations = (
            generate_attack_path_recommendations(

                defense_analysis=
                    self.defense_analysis,

                attack_graph=
                    self.attack_graph,

                asset_index=
                    asset_index
            )
        )

        self.assertEqual(
            len(
                recommendations
            ),
            1
        )

        self.assertEqual(
            recommendations[0][
                "category"
            ],
            "attack_path_disruption"
        )


    # ======================================
    # PRIORITY
    # ======================================

    def test_priority_thresholds(
        self
    ):

        self.assertEqual(
            determine_priority_level(
                10
            ),
            "LOW"
        )

        self.assertEqual(
            determine_priority_level(
                30
            ),
            "MEDIUM"
        )

        self.assertEqual(
            determine_priority_level(
                60
            ),
            "HIGH"
        )

        self.assertEqual(
            determine_priority_level(
                80
            ),
            "CRITICAL"
        )


    # ======================================
    # DEDUPLICATION
    # ======================================

    def test_deduplication(
        self
    ):

        recommendation = (
            create_mitigation_recommendation(
                "one",
                "test",
                "Review Asset",
                "Test",
                target="10.0.0.1"
            )
        )

        duplicate = dict(
            recommendation
        )

        duplicate[
            "id"
        ] = "two"

        result = (
            deduplicate_recommendations(
                [
                    recommendation,
                    duplicate
                ]
            )
        )

        self.assertEqual(
            len(
                result
            ),
            1
        )


    # ======================================
    # SORTING
    # ======================================

    def test_sorting(
        self
    ):

        recommendations = [

            {
                "title":
                    "Low",
                "score":
                    10
            },

            {
                "title":
                    "High",
                "score":
                    90
            }
        ]

        result = (
            sort_recommendations(
                recommendations
            )
        )

        self.assertEqual(
            result[0][
                "title"
            ],
            "High"
        )


    # ======================================
    # COMPLETE ENGINE
    # ======================================

    def test_empty_environment(
        self
    ):

        analysis = (
            generate_mitigation_recommendations(
                assets=[],
                defense_analysis=None,
                attack_graph=None,
                created_by=self.user_id
            )
        )

        self.assertEqual(
            analysis[
                "recommendations"
            ],
            []
        )


    def test_low_risk_environment_no_false_recommendation(
        self
    ):

        analysis = (
            generate_mitigation_recommendations(

                assets=[
                    self.low_risk_asset
                ],

                defense_analysis={
                    "findings": [],
                    "priorities": []
                },

                attack_graph={
                    "nodes": [],
                    "edges": [],
                    "paths": []
                },

                created_by=
                    self.user_id
            )
        )

        self.assertEqual(
            analysis[
                "recommendations"
            ],
            []
        )


    def test_security_relevant_environment_generates_recommendations(
        self
    ):

        analysis = (
            generate_mitigation_recommendations(

                assets=[
                    self.sensitive_asset,
                    self.external_asset,
                    self.vulnerable_asset
                ],

                defense_analysis=
                    self.defense_analysis,

                attack_graph=
                    self.attack_graph,

                created_by=
                    self.user_id
            )
        )

        self.assertGreater(
            len(
                analysis[
                    "recommendations"
                ]
            ),
            0
        )


    def test_invalid_input_safe(
        self
    ):

        analysis = (
            generate_mitigation_recommendations(
                assets=None,
                defense_analysis=None,
                attack_graph=None,
                created_by=self.user_id
            )
        )

        self.assertEqual(
            analysis[
                "recommendations"
            ],
            []
        )


if __name__ == "__main__":

    unittest.main()