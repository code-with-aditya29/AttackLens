import unittest


from models.risk_comparison_model import (
    create_comparison_state,
    create_reduction_result,
    normalize_score,
    normalize_percentage,
    normalize_risk_level
)


from services.risk_comparison_service import (
    generate_risk_comparison,
    build_current_state,
    build_projected_state,
    calculate_reduction,
    determine_risk_level,
    get_applicable_recommendations
)


class RiskComparisonModelTests(
    unittest.TestCase
):

    # ======================================
    # SCORE NORMALIZATION
    # ======================================

    def test_score_is_clamped_to_100(
        self
    ):

        self.assertEqual(
            normalize_score(
                150
            ),
            100.0
        )


    def test_negative_score_becomes_zero(
        self
    ):

        self.assertEqual(
            normalize_score(
                -20
            ),
            0.0
        )


    # ======================================
    # PERCENTAGE NORMALIZATION
    # ======================================

    def test_percentage_is_clamped(
        self
    ):

        self.assertEqual(
            normalize_percentage(
                120
            ),
            100.0
        )


    # ======================================
    # RISK LEVEL NORMALIZATION
    # ======================================

    def test_invalid_risk_level_defaults_low(
        self
    ):

        self.assertEqual(
            normalize_risk_level(
                "UNKNOWN"
            ),
            "LOW"
        )


    # ======================================
    # STATE CREATION
    # ======================================

    def test_create_comparison_state(
        self
    ):

        state = create_comparison_state(
            risk_score=45,
            risk_level="MEDIUM",
            total_assets=3,
            attack_paths=2
        )

        self.assertEqual(
            state["risk_score"],
            45.0
        )

        self.assertEqual(
            state["risk_level"],
            "MEDIUM"
        )

        self.assertEqual(
            state["total_assets"],
            3
        )

        self.assertEqual(
            state["attack_paths"],
            2
        )


    # ======================================
    # REDUCTION MODEL
    # ======================================

    def test_reduction_result_never_negative(
        self
    ):

        reduction = (
            create_reduction_result(
                risk_points=-5,
                attack_paths=-2
            )
        )

        self.assertEqual(
            reduction["risk_points"],
            0.0
        )

        self.assertEqual(
            reduction["attack_paths"],
            0
        )


class RiskComparisonServiceTests(
    unittest.TestCase
):

    # ======================================
    # EMPTY ENVIRONMENT
    # ======================================

    def test_empty_environment(
        self
    ):

        result = generate_risk_comparison(
            assets=[],
            attack_graph={},
            defense_analysis={},
            mitigation_analysis={},
            created_by="user-1"
        )

        self.assertEqual(
            result[
                "current_state"
            ][
                "risk_score"
            ],
            0.0
        )

        self.assertEqual(
            result[
                "projected_state"
            ][
                "risk_score"
            ],
            0.0
        )

        self.assertEqual(
            result[
                "reduction"
            ][
                "risk_points"
            ],
            0.0
        )


    # ======================================
    # CURRENT STATE
    # ======================================

    def test_current_state_uses_highest_asset_risk(
        self
    ):

        assets = [
            {
                "risk_score": 12
            },
            {
                "risk_score": 55
            }
        ]

        state = build_current_state(
            assets=assets,
            attack_graph={}
        )

        self.assertEqual(
            state["risk_score"],
            55.0
        )

        self.assertEqual(
            state["risk_level"],
            "HIGH"
        )


    # ======================================
    # SENSITIVE PORTS
    # ======================================

    def test_current_state_counts_sensitive_ports(
        self
    ):

        assets = [
            {
                "risk_score": 12,

                "ports": [
                    {
                        "port": 80,
                        "state": "open"
                    },
                    {
                        "port": 135,
                        "state": "open"
                    },
                    {
                        "port": 445,
                        "state": "open"
                    }
                ]
            }
        ]

        state = build_current_state(
            assets=assets,
            attack_graph={}
        )

        self.assertEqual(
            state["open_ports"],
            3
        )

        self.assertEqual(
            state["sensitive_ports"],
            2
        )


    # ======================================
    # NO RECOMMENDATIONS
    # ======================================

    def test_no_recommendations_produces_no_improvement(
        self
    ):

        current = create_comparison_state(
            risk_score=40,
            risk_level="MEDIUM",
            sensitive_ports=2
        )

        projected = build_projected_state(
            current_state=current,
            recommendations=[]
        )

        self.assertEqual(
            projected["risk_score"],
            40.0
        )

        self.assertEqual(
            projected["sensitive_ports"],
            2
        )


    # ======================================
    # SERVICE EXPOSURE
    # ======================================

    def test_service_exposure_recommendation_reduces_projection(
        self
    ):

        current = create_comparison_state(
            risk_score=40,
            risk_level="MEDIUM",
            open_ports=4,
            sensitive_ports=2
        )

        recommendations = [
            {
                "recommendation_id":
                    "rec-1",

                "category":
                    "service_exposure",

                "target":
                    "127.0.0.1",

                "score":
                    20,

                "related_ports":
                    [
                        135,
                        445
                    ]
            }
        ]

        projected = build_projected_state(
            current_state=current,
            recommendations=recommendations
        )

        self.assertLess(
            projected["risk_score"],
            current["risk_score"]
        )

        self.assertEqual(
            projected["sensitive_ports"],
            0
        )


    # ======================================
    # SEGMENTATION
    # ======================================

    def test_segmentation_can_reduce_attack_path(
        self
    ):

        current = create_comparison_state(
            risk_score=60,
            risk_level="HIGH",
            attack_paths=3,
            high_risk_attack_paths=1
        )

        recommendations = [
            {
                "recommendation_id":
                    "rec-2",

                "category":
                    "segmentation",

                "target":
                    "server-1",

                "score":
                    50
            }
        ]

        projected = build_projected_state(
            current_state=current,
            recommendations=recommendations
        )

        self.assertEqual(
            projected["attack_paths"],
            2
        )

        self.assertEqual(
            projected[
                "high_risk_attack_paths"
            ],
            0
        )


    # ======================================
    # CONSERVATIVE CAP
    # ======================================

    def test_projected_reduction_is_capped(
        self
    ):

        current = create_comparison_state(
            risk_score=20,
            risk_level="LOW",
            vulnerability_count=5
        )

        recommendations = [
            {
                "category":
                    "patch_vulnerability",

                "target":
                    f"asset-{index}",

                "score":
                    100
            }
            for index in range(
                10
            )
        ]

        projected = build_projected_state(
            current_state=current,
            recommendations=recommendations
        )

        self.assertGreaterEqual(
            projected["risk_score"],
            10.0
        )


    # ======================================
    # REDUCTION CALCULATION
    # ======================================

    def test_calculate_reduction(
        self
    ):

        current = create_comparison_state(
            risk_score=50,
            risk_level="HIGH",
            attack_paths=4,
            sensitive_ports=3
        )

        projected = create_comparison_state(
            risk_score=35,
            risk_level="MEDIUM",
            attack_paths=2,
            sensitive_ports=1
        )

        reduction = calculate_reduction(
            current_state=current,
            projected_state=projected
        )

        self.assertEqual(
            reduction["risk_points"],
            15.0
        )

        self.assertEqual(
            reduction["risk_percentage"],
            30.0
        )

        self.assertEqual(
            reduction["attack_paths"],
            2
        )

        self.assertEqual(
            reduction["sensitive_ports"],
            2
        )


    # ======================================
    # RISK LEVELS
    # ======================================

    def test_risk_level_boundaries(
        self
    ):

        self.assertEqual(
            determine_risk_level(
                24
            ),
            "LOW"
        )

        self.assertEqual(
            determine_risk_level(
                25
            ),
            "MEDIUM"
        )

        self.assertEqual(
            determine_risk_level(
                50
            ),
            "HIGH"
        )

        self.assertEqual(
            determine_risk_level(
                75
            ),
            "CRITICAL"
        )


    # ======================================
    # UNSUPPORTED RECOMMENDATION
    # ======================================

    def test_unsupported_recommendation_not_applied(
        self
    ):

        recommendations = [
            {
                "category":
                    "unknown_action",

                "score":
                    100
            }
        ]

        applicable = (
            get_applicable_recommendations(
                recommendations
            )
        )

        self.assertEqual(
            applicable,
            []
        )


    # ======================================
    # MALFORMED DATA
    # ======================================

    def test_malformed_inputs_do_not_crash(
        self
    ):

        result = generate_risk_comparison(
            assets=None,
            attack_graph=None,
            defense_analysis=None,
            mitigation_analysis=None
        )

        self.assertIsInstance(
            result,
            dict
        )


    # ======================================
    # END-TO-END PROJECTION
    # ======================================

    def test_complete_projection(
        self
    ):

        assets = [
            {
                "target":
                    "127.0.0.1",

                "created_by":
                    "user-1",

                "risk_score":
                    40,

                "ports": [
                    {
                        "port":
                            80,

                        "state":
                            "open"
                    },
                    {
                        "port":
                            135,

                        "state":
                            "open"
                    },
                    {
                        "port":
                            445,

                        "state":
                            "open"
                    }
                ],

                "vulnerabilities":
                    []
            }
        ]


        attack_graph = {
            "paths":
                []
        }


        mitigation_analysis = {
            "recommendations": [
                {
                    "recommendation_id":
                        "rec-service",

                    "category":
                        "service_exposure",

                    "target":
                        "127.0.0.1",

                    "score":
                        20,

                    "related_ports":
                        [
                            135,
                            445
                        ]
                }
            ]
        }


        result = generate_risk_comparison(
            assets=assets,
            attack_graph=attack_graph,
            mitigation_analysis=(
                mitigation_analysis
            ),
            created_by="user-1"
        )


        self.assertEqual(
            result[
                "current_state"
            ][
                "risk_score"
            ],
            40.0
        )


        self.assertLess(
            result[
                "projected_state"
            ][
                "risk_score"
            ],
            40.0
        )


        self.assertGreater(
            result[
                "reduction"
            ][
                "risk_points"
            ],
            0
        )


if __name__ == "__main__":

    unittest.main()