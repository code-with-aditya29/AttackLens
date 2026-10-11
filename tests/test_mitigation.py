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









# ==========================================

# ADDITIONAL MITIGATION REGRESSION TESTS

# ==========================================



class TestMitigationEnhancements(unittest.TestCase):

    """Additional cases using the original fixtures."""



    def setUp(self):

        self.fixture = TestMitigationEngine(methodName="test_empty_environment")

        self.fixture.setUp()

        self.user_id = self.fixture.user_id

        self.other_user_id = self.fixture.other_user_id

        self.sensitive_asset = self.fixture.sensitive_asset

        self.external_asset = self.fixture.external_asset

        self.defense_analysis = self.fixture.defense_analysis

        self.attack_graph = self.fixture.attack_graph



    def test_selected_host_scope_excludes_other_hosts(self):

        analysis = generate_mitigation_recommendations(

            assets=[self.sensitive_asset],

            defense_analysis={"findings": [], "priorities": []},

            attack_graph={"nodes": [], "edges": [], "paths": []},

            created_by=self.user_id,

        )

        recommendations = analysis.get("recommendations", [])

        self.assertTrue(recommendations)

        self.assertTrue(all(

            recommendation.get("asset_id") in (None, "asset-sensitive")

            for recommendation in recommendations

        ))

        self.assertTrue(all(

            recommendation.get("target") in (None, "10.0.0.10")

            for recommendation in recommendations

        ))



    def test_foreign_asset_does_not_produce_recommendations(self):

        foreign = dict(self.sensitive_asset)

        foreign["created_by"] = self.other_user_id

        analysis = generate_mitigation_recommendations(

            assets=[foreign],

            defense_analysis={"findings": [], "priorities": []},

            attack_graph={"nodes": [], "edges": [], "paths": []},

            created_by=self.user_id,

        )

        self.assertEqual(analysis.get("recommendations"), [])



    def test_modern_attack_path_schema(self):

        graph = {

            "nodes": self.attack_graph["nodes"],

            "edges": self.attack_graph["edges"],

            "paths": [{

                "id": "modern-path-1",

                "node_ids": ["external-attacker", "asset-external", "asset-sensitive"],

                "edge_ids": ["edge-entry", "edge-pivot"],

                "path_type": "potential_service_entry",

                "status": "POTENTIAL",

                "exploitation_verified": False,

                "score": 70,

                "confidence": "MEDIUM",

                "evidence": ["Potential progression inferred from observed services."],

            }],

            "statistics": {"total_paths": 1},

        }

        results = generate_attack_path_recommendations(

            defense_analysis=self.defense_analysis,

            attack_graph=graph,

            asset_index=build_asset_index([self.external_asset, self.sensitive_asset]),

        )

        self.assertTrue(results, "Modern node_ids path should generate a recommendation")

        self.assertTrue(any(

            "modern-path-1" in rec.get("related_path_ids", [])

            for rec in results

        ))



    def test_distinct_path_recommendations_not_collapsed(self):

        first = create_mitigation_recommendation(

            "rec-path-1", "attack_path_disruption", "Disrupt Potential Path",

            "Review inferred route", target="10.0.0.10",

            related_path_ids=["path-1"],

        )

        second = create_mitigation_recommendation(

            "rec-path-2", "attack_path_disruption", "Disrupt Potential Path",

            "Review inferred route", target="10.0.0.10",

            related_path_ids=["path-2"],

        )

        result = deduplicate_recommendations([first, second])

        self.assertEqual(len(result), 2)



    def test_model_preserves_evidence_references(self):

        rec = create_mitigation_recommendation(

            "rec-evidence", "vulnerability_remediation", "Review CVE",

            "Validate applicability", related_cves=["CVE-2026-1234"],

            related_finding_ids=["finding-1"], related_path_ids=["path-1"],

            related_ports=[445],

        )

        self.assertEqual(rec["related_cves"], ["CVE-2026-1234"])

        self.assertEqual(rec["related_finding_ids"], ["finding-1"])

        self.assertEqual(rec["related_path_ids"], ["path-1"])

        self.assertEqual(rec["related_ports"], [445])





# ==========================================
# MITIGATION PRIORITY SCORING REGRESSION TESTS
# ==========================================

class TestMitigationScoringRegression(unittest.TestCase):
    """Check that priority follows recommendation evidence, not just asset risk."""

    def test_asset_risk_100_does_not_force_all_priorities_to_100(self):
        from services.mitigation_service import calculate_mitigation_priority
        self.assertLess(calculate_mitigation_priority(70, 100, 100), 100)
        self.assertLess(calculate_mitigation_priority(25, 100, 100), 100)

    def test_stronger_evidence_has_higher_priority(self):
        from services.mitigation_service import calculate_mitigation_priority
        low = calculate_mitigation_priority(25, 100, 100)
        high = calculate_mitigation_priority(90, 100, 100)
        self.assertGreater(high, low)

    def test_sensitive_service_priority_not_forced_to_100(self):
        asset = {
            "_id": "asset-priority-1",
            "target": "192.0.2.10",
            "risk_score": 100,
            "ports": [{"port": 22, "state": "open", "service": "ssh"}],
        }
        recommendations = generate_sensitive_service_recommendations([asset])
        self.assertEqual(len(recommendations), 1)
        self.assertLess(recommendations[0]["score"], 100)

    def test_distinct_attack_paths_keep_distinct_priorities(self):
        fixture = TestMitigationEngine(methodName="test_empty_environment")
        fixture.setUp()
        asset = dict(fixture.sensitive_asset, risk_score=100)
        graph = dict(fixture.attack_graph)
        graph["paths"] = [
            dict(fixture.attack_graph["paths"][0], id="path-70", score=70),
            dict(fixture.attack_graph["paths"][0], id="path-40", score=40),
        ]
        recommendations = generate_attack_path_recommendations(
            defense_analysis=fixture.defense_analysis,
            attack_graph=graph,
            asset_index=build_asset_index([fixture.external_asset, asset]),
        )
        by_path = {
            rec["related_path_ids"][0]: rec
            for rec in recommendations
            if rec.get("related_path_ids")
        }
        self.assertEqual(set(by_path), {"path-70", "path-40"})
        self.assertGreater(by_path["path-70"]["score"], by_path["path-40"]["score"])
        self.assertLess(by_path["path-70"]["score"], 100)


if __name__ == "__main__":

    unittest.main()