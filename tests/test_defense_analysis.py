# ==========================================
# DEFENSE ANALYSIS ENGINE TESTS
# ==========================================
#
# Tests:
#
# 1. Defense Analysis model
# 2. Finding creation
# 3. Priority creation
# 4. Statistics generation
# 5. Score normalization
# 6. Severity normalization
# 7. Confidence normalization
# 8. Asset owner isolation
# 9. Open-port filtering
# 10. Sensitive-port detection
# 11. Vulnerability counting
# 12. Asset path frequency
# 13. Asset edge frequency
# 14. Asset defense scoring
# 15. Asset finding generation
# 16. Relationship finding generation
# 17. Path finding generation
# 18. Priority generation
# 19. Deduplication
# 20. Sorting
# 21. Empty / malformed input handling
#
# ==========================================


import unittest


from models.defense_analysis_model import (
    create_defense_analysis_document,
    create_defense_finding,
    create_defense_priority,
    create_defense_statistics,
    normalize_score,
    normalize_severity,
    normalize_priority_level,
    normalize_confidence,
    normalize_evidence,
    normalize_identifier_list,
    normalize_string,
    normalize_nullable_string
)


from services.defense_analysis_service import (
    generate_defense_analysis,
    normalize_assets,
    normalize_attack_graph,
    build_asset_index,
    calculate_asset_path_frequency,
    calculate_asset_edge_frequency,
    generate_asset_findings,
    should_create_asset_finding,
    calculate_asset_defense_score,
    generate_relationship_findings,
    calculate_edge_path_frequency,
    calculate_relationship_defense_score,
    generate_path_findings,
    generate_defense_priorities,
    determine_finding_severity,
    determine_priority_level,
    normalize_risk_score,
    normalize_risk_level,
    normalize_exposure,
    normalize_criticality,
    get_open_ports,
    get_sensitive_open_ports,
    get_vulnerability_count,
    normalize_port_number,
    normalize_non_negative_integer,
    deduplicate_findings,
    deduplicate_priorities,
    sort_findings,
    sort_priorities
)


# ==========================================
# TEST CLASS
# ==========================================

class TestDefenseAnalysisEngine(
    unittest.TestCase
):


    # ======================================
    # TEST DATA SETUP
    # ======================================

    def setUp(
        self
    ):

        self.user_id = (
            "user-001"
        )

        self.other_user_id = (
            "user-002"
        )


        # ==================================
        # LOW-RISK INTERNAL ASSET
        # ==================================

        self.low_risk_asset = {

            "_id":
                "asset-low",

            "created_by":
                self.user_id,

            "target":
                "127.0.0.1",

            "hostname":
                "localhost",

            "ports": [

                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http"
                },

                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "https"
                }

            ],

            "services": [

                {
                    "port": 80,
                    "name": "http"
                }

            ],

            "operating_system":
                "Unknown",

            "vulnerabilities":
                [],

            "vulnerability_count":
                0,

            "risk_score":
                12,

            "risk_level":
                "LOW",

            "criticality":
                "NORMAL",

            "exposure":
                "INTERNAL"

        }


        # ==================================
        # EXTERNALLY EXPOSED WEB ASSET
        # ==================================

        self.external_asset = {

            "_id":
                "asset-external",

            "created_by":
                self.user_id,

            "target":
                "192.0.2.10",

            "hostname":
                "public-web",

            "ports": [

                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http"
                },

                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https"
                }

            ],

            "services": [

                {
                    "port": 80,
                    "name": "http"
                },

                {
                    "port": 443,
                    "name": "https"
                }

            ],

            "operating_system":
                "Linux",

            "vulnerabilities":
                [],

            "vulnerability_count":
                0,

            "risk_score":
                35,

            "risk_level":
                "MEDIUM",

            "criticality":
                "NORMAL",

            "exposure":
                "EXTERNAL"

        }


        # ==================================
        # HIGH-RISK SENSITIVE ASSET
        # ==================================

        self.sensitive_asset = {

            "_id":
                "asset-sensitive",

            "created_by":
                self.user_id,

            "target":
                "10.0.0.20",

            "hostname":
                "file-server",

            "ports": [

                {
                    "port": 445,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "microsoft-ds"
                },

                {
                    "port": 3389,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ms-wbt-server"
                },

                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "https"
                }

            ],

            "services": [

                {
                    "port": 445,
                    "name": "microsoft-ds"
                },

                {
                    "port": 3389,
                    "name": "ms-wbt-server"
                }

            ],

            "operating_system":
                "Microsoft Windows",

            "vulnerabilities": [

                {
                    "cve_id":
                        "CVE-TEST-0001",

                    "severity":
                        "HIGH",

                    "confidence":
                        "HIGH",

                    "status":
                        "potential"
                }

            ],

            "vulnerability_count":
                1,

            "risk_score":
                65,

            "risk_level":
                "HIGH",

            "criticality":
                "HIGH",

            "exposure":
                "INTERNAL"

        }


        # ==================================
        # OTHER USER ASSET
        # ==================================

        self.other_user_asset = {

            "_id":
                "asset-other",

            "created_by":
                self.other_user_id,

            "target":
                "172.16.0.10",

            "hostname":
                "other-user-host",

            "ports": [

                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh"
                }

            ],

            "services":
                [],

            "vulnerabilities":
                [],

            "vulnerability_count":
                0,

            "risk_score":
                50,

            "risk_level":
                "HIGH",

            "criticality":
                "HIGH",

            "exposure":
                "EXTERNAL"

        }


        # ==================================
        # ATTACK GRAPH
        # ==================================

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
                        "asset-external",

                    "relationship":
                        "external_entry",

                    "confidence":
                        "HIGH",

                    "score":
                        55,

                    "evidence": [
                        "External exposure identified."
                    ]
                },

                {
                    "id":
                        "edge-pivot",

                    "source":
                        "asset-external",

                    "target":
                        "asset-sensitive",

                    "relationship":
                        "potential_pivot",

                    "confidence":
                        "MEDIUM",

                    "score":
                        65,

                    "evidence": [
                        "Sensitive services detected."
                    ]
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

            ]

        }


    # ======================================
    # MODEL TESTS
    # ======================================

    def test_create_empty_defense_analysis(
        self
    ):

        analysis = (
            create_defense_analysis_document(
                created_by=self.user_id
            )
        )

        self.assertEqual(
            analysis["created_by"],
            self.user_id
        )

        self.assertEqual(
            analysis["findings"],
            []
        )

        self.assertEqual(
            analysis["priorities"],
            []
        )

        self.assertIsInstance(
            analysis["statistics"],
            dict
        )

        self.assertIsNotNone(
            analysis["generated_at"]
        )


    def test_create_defense_finding(
        self
    ):

        finding = (
            create_defense_finding(

                finding_id=
                    "finding-1",

                finding_type=
                    "asset_security_priority",

                title=
                    "Test Finding",

                description=
                    "Test Description",

                asset_id=
                    "asset-1",

                target=
                    "10.0.0.1",

                severity=
                    "HIGH",

                confidence=
                    "MEDIUM",

                score=
                    70,

                evidence=[
                    "Evidence A"
                ]

            )
        )

        self.assertEqual(
            finding["id"],
            "finding-1"
        )

        self.assertEqual(
            finding["severity"],
            "HIGH"
        )

        self.assertEqual(
            finding["confidence"],
            "MEDIUM"
        )

        self.assertEqual(
            finding["score"],
            70
        )


    def test_create_defense_priority(
        self
    ):

        priority = (
            create_defense_priority(

                priority_id=
                    "priority-1",

                priority_type=
                    "asset_priority",

                title=
                    "Review Asset",

                description=
                    "Priority description",

                priority_level=
                    "CRITICAL",

                score=
                    85,

                confidence=
                    "HIGH",

                asset_id=
                    "asset-1",

                target=
                    "10.0.0.1",

                reason=
                    "High defensive significance."

            )
        )

        self.assertEqual(
            priority["priority_level"],
            "CRITICAL"
        )

        self.assertEqual(
            priority["score"],
            85
        )

        self.assertEqual(
            priority["confidence"],
            "HIGH"
        )


    # ======================================
    # NORMALIZATION TESTS
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
                -20
            ),
            0
        )

        self.assertEqual(
            normalize_score(
                "50"
            ),
            50
        )

        self.assertEqual(
            normalize_score(
                "invalid"
            ),
            0
        )


    def test_severity_normalization(
        self
    ):

        self.assertEqual(
            normalize_severity(
                "high"
            ),
            "HIGH"
        )

        self.assertEqual(
            normalize_severity(
                "invalid"
            ),
            "UNKNOWN"
        )


    def test_priority_level_normalization(
        self
    ):

        self.assertEqual(
            normalize_priority_level(
                "critical"
            ),
            "CRITICAL"
        )

        self.assertEqual(
            normalize_priority_level(
                "invalid"
            ),
            "UNKNOWN"
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

        self.assertEqual(
            normalize_confidence(
                "invalid"
            ),
            "UNKNOWN"
        )


    def test_evidence_deduplication(
        self
    ):

        evidence = (
            normalize_evidence(

                [
                    "Open port",
                    "open port",
                    "",
                    None,
                    "High risk"
                ]

            )
        )

        self.assertEqual(
            evidence,
            [
                "Open port",
                "High risk"
            ]
        )


    def test_identifier_deduplication(
        self
    ):

        identifiers = (
            normalize_identifier_list(

                [
                    "a",
                    "b",
                    "a",
                    "",
                    None
                ]

            )
        )

        self.assertEqual(
            identifiers,
            [
                "a",
                "b"
            ]
        )


    def test_string_normalization(
        self
    ):

        self.assertEqual(
            normalize_string(
                " test "
            ),
            "test"
        )

        self.assertEqual(
            normalize_nullable_string(
                ""
            ),
            None
        )


    # ======================================
    # ASSET NORMALIZATION
    # ======================================

    def test_assets_filtered_by_owner(
        self
    ):

        assets = (
            normalize_assets(

                [
                    self.low_risk_asset,
                    self.other_user_asset
                ],

                created_by=
                    self.user_id

            )
        )

        self.assertEqual(
            len(
                assets
            ),
            1
        )

        self.assertEqual(
            assets[0]["_id"],
            "asset-low"
        )


    def test_asset_without_id_rejected(
        self
    ):

        asset = dict(
            self.low_risk_asset
        )

        asset.pop(
            "_id"
        )

        assets = (
            normalize_assets(
                [asset],
                created_by=self.user_id
            )
        )

        self.assertEqual(
            assets,
            []
        )


    def test_asset_without_target_rejected(
        self
    ):

        asset = dict(
            self.low_risk_asset
        )

        asset["target"] = ""

        assets = (
            normalize_assets(
                [asset],
                created_by=self.user_id
            )
        )

        self.assertEqual(
            assets,
            []
        )


    # ======================================
    # ATTACK GRAPH NORMALIZATION
    # ======================================

    def test_invalid_attack_graph_safe(
        self
    ):

        graph = (
            normalize_attack_graph(
                None
            )
        )

        self.assertEqual(
            graph,
            {
                "nodes": [],
                "edges": [],
                "paths": []
            }
        )


    def test_build_asset_index(
        self
    ):

        index = (
            build_asset_index(

                [
                    self.external_asset,
                    self.sensitive_asset
                ]

            )
        )

        self.assertIn(
            "asset-external",
            index
        )

        self.assertIn(
            "asset-sensitive",
            index
        )


    # ======================================
    # PORT TESTS
    # ======================================

    def test_only_open_ports_returned(
        self
    ):

        ports = (
            get_open_ports(
                self.sensitive_asset
            )
        )

        port_numbers = [

            port["port"]

            for port
            in ports

        ]

        self.assertIn(
            445,
            port_numbers
        )

        self.assertIn(
            3389,
            port_numbers
        )

        self.assertNotIn(
            443,
            port_numbers
        )


    def test_sensitive_ports_detected(
        self
    ):

        sensitive_ports = (
            get_sensitive_open_ports(
                self.sensitive_asset
            )
        )

        self.assertEqual(
            sensitive_ports,
            [
                445,
                3389
            ]
        )


    def test_invalid_port_rejected(
        self
    ):

        self.assertIsNone(
            normalize_port_number(
                70000
            )
        )

        self.assertIsNone(
            normalize_port_number(
                "invalid"
            )
        )


    def test_negative_integer_normalization(
        self
    ):

        self.assertEqual(
            normalize_non_negative_integer(
                -5
            ),
            0
        )


    # ======================================
    # VULNERABILITY TESTS
    # ======================================

    def test_vulnerability_count(
        self
    ):

        count = (
            get_vulnerability_count(
                self.sensitive_asset
            )
        )

        self.assertEqual(
            count,
            1
        )


    def test_resolved_vulnerability_ignored(
        self
    ):

        asset = dict(
            self.sensitive_asset
        )

        asset[
            "vulnerabilities"
        ] = [

            {
                "status":
                    "resolved",

                "severity":
                    "CRITICAL"
            }

        ]

        count = (
            get_vulnerability_count(
                asset
            )
        )

        self.assertEqual(
            count,
            0
        )


    def test_rejected_vulnerability_ignored(
        self
    ):

        asset = dict(
            self.sensitive_asset
        )

        asset[
            "vulnerabilities"
        ] = [

            {
                "status":
                    "rejected",

                "severity":
                    "CRITICAL"
            }

        ]

        count = (
            get_vulnerability_count(
                asset
            )
        )

        self.assertEqual(
            count,
            0
        )


    # ======================================
    # PATH FREQUENCY TESTS
    # ======================================

    def test_asset_path_frequency(
        self
    ):

        frequency = (
            calculate_asset_path_frequency(
                self.attack_graph["paths"]
            )
        )

        self.assertEqual(
            frequency[
                "asset-external"
            ],
            1
        )

        self.assertEqual(
            frequency[
                "asset-sensitive"
            ],
            1
        )

        self.assertNotIn(
            "external-attacker",
            frequency
        )


    def test_asset_edge_frequency(
        self
    ):

        frequency = (
            calculate_asset_edge_frequency(
                self.attack_graph["edges"]
            )
        )

        self.assertEqual(
            frequency[
                "asset-external"
            ],
            2
        )

        self.assertEqual(
            frequency[
                "asset-sensitive"
            ],
            1
        )


    def test_edge_path_frequency(
        self
    ):

        frequency = (
            calculate_edge_path_frequency(
                self.attack_graph["paths"]
            )
        )

        self.assertEqual(
            frequency[
                "edge-entry"
            ],
            1
        )

        self.assertEqual(
            frequency[
                "edge-pivot"
            ],
            1
        )


    # ======================================
    # ASSET DEFENSE SCORE TESTS
    # ======================================

    def test_asset_defense_score_stays_in_range(
        self
    ):

        score = (
            calculate_asset_defense_score(

                self.sensitive_asset,

                path_count=5,

                relationship_count=5

            )
        )

        self.assertGreaterEqual(
            score,
            0
        )

        self.assertLessEqual(
            score,
            100
        )


    def test_external_asset_scores_higher_than_internal_copy(
        self
    ):

        external = dict(
            self.external_asset
        )

        internal = dict(
            self.external_asset
        )

        external[
            "exposure"
        ] = "EXTERNAL"

        internal[
            "exposure"
        ] = "INTERNAL"


        external_score = (
            calculate_asset_defense_score(
                external
            )
        )

        internal_score = (
            calculate_asset_defense_score(
                internal
            )
        )

        self.assertGreater(
            external_score,
            internal_score
        )


    def test_sensitive_asset_scores_higher_than_low_asset(
        self
    ):

        sensitive_score = (
            calculate_asset_defense_score(
                self.sensitive_asset
            )
        )

        low_score = (
            calculate_asset_defense_score(
                self.low_risk_asset
            )
        )

        self.assertGreater(
            sensitive_score,
            low_score
        )


    # ======================================
    # ASSET FINDING TESTS
    # ======================================

    def test_low_risk_internal_asset_not_forced_into_finding(
        self
    ):

        findings = (
            generate_asset_findings(
                [
                    self.low_risk_asset
                ]
            )
        )

        self.assertEqual(
            findings,
            []
        )


    def test_sensitive_asset_creates_finding(
        self
    ):

        findings = (
            generate_asset_findings(
                [
                    self.sensitive_asset
                ]
            )
        )

        self.assertEqual(
            len(
                findings
            ),
            1
        )

        self.assertEqual(
            findings[0][
                "asset_id"
            ],
            "asset-sensitive"
        )


    def test_external_asset_creates_finding(
        self
    ):

        findings = (
            generate_asset_findings(
                [
                    self.external_asset
                ]
            )
        )

        self.assertEqual(
            len(
                findings
            ),
            1
        )


    def test_should_create_asset_finding(
        self
    ):

        self.assertTrue(

            should_create_asset_finding(

                risk_score=
                    60,

                risk_level=
                    "HIGH",

                exposure=
                    "INTERNAL",

                vulnerability_count=
                    0,

                sensitive_ports=
                    [],

                path_count=
                    0,

                relationship_count=
                    0

            )

        )


        self.assertFalse(

            should_create_asset_finding(

                risk_score=
                    12,

                risk_level=
                    "LOW",

                exposure=
                    "INTERNAL",

                vulnerability_count=
                    0,

                sensitive_ports=
                    [],

                path_count=
                    0,

                relationship_count=
                    0

            )

        )


    # ======================================
    # RELATIONSHIP FINDING TESTS
    # ======================================

    def test_relationship_finding_generated(
        self
    ):

        findings = (
            generate_relationship_findings(

                edges=
                    self.attack_graph[
                        "edges"
                    ],

                paths=
                    self.attack_graph[
                        "paths"
                    ],

                asset_index=
                    build_asset_index(

                        [
                            self.external_asset,
                            self.sensitive_asset
                        ]

                    )

            )
        )

        self.assertEqual(
            len(
                findings
            ),
            2
        )


    def test_relationship_score_stays_in_range(
        self
    ):

        score = (
            calculate_relationship_defense_score(

                edge=
                    self.attack_graph[
                        "edges"
                    ][0],

                path_count=
                    5

            )
        )

        self.assertGreaterEqual(
            score,
            0
        )

        self.assertLessEqual(
            score,
            100
        )


    # ======================================
    # PATH FINDING TESTS
    # ======================================

    def test_path_finding_generated(
        self
    ):

        findings = (
            generate_path_findings(

                paths=
                    self.attack_graph[
                        "paths"
                    ],

                asset_index=
                    build_asset_index(

                        [
                            self.external_asset,
                            self.sensitive_asset
                        ]

                    )

            )
        )

        self.assertEqual(
            len(
                findings
            ),
            1
        )

        self.assertEqual(
            findings[0][
                "asset_id"
            ],
            "asset-sensitive"
        )

        self.assertEqual(
            findings[0][
                "severity"
            ],
            "HIGH"
        )


    # ======================================
    # PRIORITY TESTS
    # ======================================

    def test_generate_defense_priorities(
        self
    ):

        findings = (
            generate_asset_findings(
                [
                    self.sensitive_asset
                ]
            )
        )

        priorities = (
            generate_defense_priorities(
                findings
            )
        )

        self.assertEqual(
            len(
                priorities
            ),
            1
        )

        self.assertEqual(
            priorities[0][
                "priority_type"
            ],
            "asset_priority"
        )


    def test_priority_level_from_score(
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


    def test_finding_severity_from_score(
        self
    ):

        self.assertEqual(
            determine_finding_severity(
                10
            ),
            "LOW"
        )

        self.assertEqual(
            determine_finding_severity(
                30
            ),
            "MEDIUM"
        )

        self.assertEqual(
            determine_finding_severity(
                60
            ),
            "HIGH"
        )

        self.assertEqual(
            determine_finding_severity(
                80
            ),
            "CRITICAL"
        )


    # ======================================
    # FULL ANALYSIS TESTS
    # ======================================

    def test_empty_assets_generate_empty_analysis(
        self
    ):

        analysis = (
            generate_defense_analysis(

                assets=[],

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
                "findings"
            ],
            []
        )

        self.assertEqual(
            analysis[
                "priorities"
            ],
            []
        )

        self.assertEqual(
            analysis[
                "statistics"
            ][
                "total_findings"
            ],
            0
        )


    def test_low_risk_localhost_generates_no_false_priority(
        self
    ):

        analysis = (
            generate_defense_analysis(

                assets=[
                    self.low_risk_asset
                ],

                attack_graph={

                    "nodes": [

                        {
                            "id":
                                "asset-low",

                            "node_type":
                                "asset"
                        }

                    ],

                    "edges":
                        [],

                    "paths":
                        []

                },

                created_by=
                    self.user_id

            )
        )

        self.assertEqual(
            analysis[
                "findings"
            ],
            []
        )

        self.assertEqual(
            analysis[
                "priorities"
            ],
            []
        )


    def test_high_risk_environment_generates_priorities(
        self
    ):

        analysis = (
            generate_defense_analysis(

                assets=[
                    self.external_asset,
                    self.sensitive_asset
                ],

                attack_graph=
                    self.attack_graph,

                created_by=
                    self.user_id

            )
        )

        self.assertGreater(
            len(
                analysis[
                    "findings"
                ]
            ),
            0
        )

        self.assertGreater(
            len(
                analysis[
                    "priorities"
                ]
            ),
            0
        )

        self.assertGreater(
            analysis[
                "statistics"
            ][
                "total_findings"
            ],
            0
        )


    def test_other_user_asset_excluded(
        self
    ):

        analysis = (
            generate_defense_analysis(

                assets=[
                    self.low_risk_asset,
                    self.other_user_asset
                ],

                attack_graph={
                    "nodes": [],
                    "edges": [],
                    "paths": []
                },

                created_by=
                    self.user_id

            )
        )

        finding_asset_ids = [

            finding.get(
                "asset_id"
            )

            for finding
            in analysis[
                "findings"
            ]

        ]

        self.assertNotIn(
            "asset-other",
            finding_asset_ids
        )


    # ======================================
    # STATISTICS TEST
    # ======================================

    def test_defense_statistics(
        self
    ):

        findings = [

            create_defense_finding(

                finding_id=
                    "finding-1",

                finding_type=
                    "asset_security_priority",

                title=
                    "Finding",

                description=
                    "Description",

                severity=
                    "HIGH",

                score=
                    65

            ),

            create_defense_finding(

                finding_id=
                    "finding-2",

                finding_type=
                    "attack_path_priority",

                title=
                    "Finding 2",

                description=
                    "Description",

                severity=
                    "CRITICAL",

                score=
                    85

            )

        ]


        priorities = [

            create_defense_priority(

                priority_id=
                    "priority-1",

                priority_type=
                    "asset_priority",

                title=
                    "Priority",

                description=
                    "Description",

                priority_level=
                    "HIGH",

                score=
                    70

            )

        ]


        statistics = (
            create_defense_statistics(

                findings=
                    findings,

                priorities=
                    priorities

            )
        )

        self.assertEqual(
            statistics[
                "total_findings"
            ],
            2
        )

        self.assertEqual(
            statistics[
                "total_priorities"
            ],
            1
        )

        self.assertEqual(
            statistics[
                "high_findings"
            ],
            1
        )

        self.assertEqual(
            statistics[
                "critical_findings"
            ],
            1
        )

        self.assertEqual(
            statistics[
                "highest_finding_score"
            ],
            85
        )


    # ======================================
    # DEDUPLICATION TESTS
    # ======================================

    def test_duplicate_findings_removed(
        self
    ):

        finding = {

            "id":
                "finding-1",

            "score":
                50

        }

        findings = (
            deduplicate_findings(

                [
                    finding,
                    dict(
                        finding
                    )
                ]

            )
        )

        self.assertEqual(
            len(
                findings
            ),
            1
        )


    def test_duplicate_priorities_removed(
        self
    ):

        priority = {

            "id":
                "priority-1",

            "score":
                50

        }

        priorities = (
            deduplicate_priorities(

                [
                    priority,
                    dict(
                        priority
                    )
                ]

            )
        )

        self.assertEqual(
            len(
                priorities
            ),
            1
        )


    # ======================================
    # SORTING TESTS
    # ======================================

    def test_findings_sorted_highest_score_first(
        self
    ):

        findings = (

            sort_findings(

                [
                    {
                        "id":
                            "low",

                        "score":
                            10
                    },

                    {
                        "id":
                            "high",

                        "score":
                            90
                    }

                ]

            )

        )

        self.assertEqual(
            findings[0][
                "id"
            ],
            "high"
        )


    def test_priorities_sorted_highest_score_first(
        self
    ):

        priorities = (

            sort_priorities(

                [
                    {
                        "id":
                            "low",

                        "score":
                            20
                    },

                    {
                        "id":
                            "high",

                        "score":
                            80
                    }

                ]

            )

        )

        self.assertEqual(
            priorities[0][
                "id"
            ],
            "high"
        )


    # ======================================
    # MALFORMED INPUT TESTS
    # ======================================

    def test_invalid_assets_input_safe(
        self
    ):

        analysis = (
            generate_defense_analysis(

                assets=None,

                attack_graph=None,

                created_by=
                    self.user_id

            )
        )

        self.assertEqual(
            analysis[
                "findings"
            ],
            []
        )

        self.assertEqual(
            analysis[
                "priorities"
            ],
            []
        )


    def test_invalid_port_list_safe(
        self
    ):

        asset = dict(
            self.low_risk_asset
        )

        asset[
            "ports"
        ] = None

        self.assertEqual(
            get_open_ports(
                asset
            ),
            []
        )


    def test_invalid_vulnerability_list_safe(
        self
    ):

        asset = dict(
            self.low_risk_asset
        )

        asset[
            "vulnerabilities"
        ] = None

        asset[
            "vulnerability_count"
        ] = None

        self.assertEqual(
            get_vulnerability_count(
                asset
            ),
            0
        )


    # ======================================
    # NORMALIZATION HELPERS
    # ======================================

    def test_risk_level_normalization(
        self
    ):

        self.assertEqual(
            normalize_risk_level(
                "high"
            ),
            "HIGH"
        )

        self.assertEqual(
            normalize_risk_level(
                "invalid"
            ),
            "UNKNOWN"
        )


    def test_exposure_normalization(
        self
    ):

        self.assertEqual(
            normalize_exposure(
                "external"
            ),
            "EXTERNAL"
        )

        self.assertEqual(
            normalize_exposure(
                "invalid"
            ),
            "UNKNOWN"
        )


    def test_criticality_normalization(
        self
    ):

        self.assertEqual(
            normalize_criticality(
                "high"
            ),
            "HIGH"
        )

        self.assertEqual(
            normalize_criticality(
                None
            ),
            "NORMAL"
        )


    def test_risk_score_normalization(
        self
    ):

        self.assertEqual(
            normalize_risk_score(
                120
            ),
            100
        )


# ==========================================
# RUN TESTS
# ==========================================

if __name__ == "__main__":

    unittest.main()