# ==========================================
# ATTACK PATH ENGINE TESTS
# ==========================================
#
# Tests:
#
# 1. Attack Path model
# 2. Asset node generation
# 3. External attacker generation
# 4. Exposure handling
# 5. Open-port filtering
# 6. Sensitive-port detection
# 7. Entry-edge generation
# 8. Asset relationship generation
# 9. Attack-path discovery
# 10. Path scoring
# 11. Path confidence
# 12. Path risk levels
# 13. Ownership isolation
# 14. Deduplication
# 15. Empty / malformed data handling
#
# ==========================================


import unittest


from models.attack_path_model import (
    create_attack_graph_document,
    create_asset_node,
    create_external_attacker_node,
    create_attack_edge,
    create_attack_path,
    create_graph_statistics,
    normalize_score,
    normalize_risk_level,
    normalize_confidence,
    normalize_evidence,
    normalize_identifier_list,
    normalize_non_negative_integer
)


from services.attack_path_service import (
    generate_attack_graph,
    normalize_assets,
    build_asset_node,
    generate_external_entry_edges,
    generate_asset_relationships,
    evaluate_asset_relationship,
    calculate_asset_attack_score,
    calculate_vulnerability_contribution,
    discover_attack_paths,
    calculate_path_score,
    determine_path_risk_level,
    calculate_path_confidence,
    deduplicate_edges,
    deduplicate_paths,
    get_open_ports,
    get_sensitive_open_ports,
    get_vulnerability_count,
    normalize_exposure,
    normalize_criticality,
    normalize_port_number
)


# ==========================================
# TEST CLASS
# ==========================================

class TestAttackPathEngine(
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
        # INTERNAL LOW-RISK ASSET
        # ==================================

        self.internal_asset = {

            "_id": "asset-internal",

            "created_by": (
                self.user_id
            ),

            "target": "10.0.0.10",

            "hostname": "internal-host",

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
                    "name": "http",
                    "product": "nginx"
                }

            ],

            "operating_system": "Linux",

            "vulnerabilities": [],

            "vulnerability_count": 0,

            "risk_score": 12,

            "risk_level": "LOW",

            "criticality": "HIGH",

            "exposure": "INTERNAL"

        }


        # ==================================
        # EXTERNAL WEB ASSET
        # ==================================

        self.external_asset = {

            "_id": "asset-external",

            "created_by": (
                self.user_id
            ),

            "target": "192.0.2.10",

            "hostname": "public-web",

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

            "operating_system": "Linux",

            "vulnerabilities": [],

            "vulnerability_count": 0,

            "risk_score": 30,

            "risk_level": "MEDIUM",

            "criticality": "NORMAL",

            "exposure": "EXTERNAL"

        }


        # ==================================
        # INTERNAL SENSITIVE ASSET
        # ==================================

        self.sensitive_asset = {

            "_id": "asset-sensitive",

            "created_by": (
                self.user_id
            ),

            "target": "10.0.0.20",

            "hostname": "file-server",

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

            "operating_system": (
                "Microsoft Windows 11"
            ),

            "vulnerabilities": [

                {
                    "cve_id": "CVE-TEST-0001",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "status": "potential"
                }

            ],

            "vulnerability_count": 1,

            "risk_score": 65,

            "risk_level": "HIGH",

            "criticality": "HIGH",

            "exposure": "INTERNAL"

        }


        # ==================================
        # DIFFERENT OWNER ASSET
        # ==================================

        self.other_user_asset = {

            "_id": "asset-other-user",

            "created_by": (
                self.other_user_id
            ),

            "target": "172.16.0.10",

            "hostname": "other-user-host",

            "ports": [

                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh"
                }

            ],

            "services": [],

            "vulnerabilities": [],

            "vulnerability_count": 0,

            "risk_score": 50,

            "risk_level": "HIGH",

            "criticality": "HIGH",

            "exposure": "EXTERNAL"

        }


    # ======================================
    # MODEL TESTS
    # ======================================

    def test_create_empty_attack_graph(
        self
    ):

        graph = (
            create_attack_graph_document(
                created_by=self.user_id
            )
        )

        self.assertEqual(
            graph["created_by"],
            self.user_id
        )

        self.assertEqual(
            graph["nodes"],
            []
        )

        self.assertEqual(
            graph["edges"],
            []
        )

        self.assertEqual(
            graph["paths"],
            []
        )

        self.assertIsNotNone(
            graph["generated_at"]
        )


    def test_create_asset_node(
        self
    ):

        node = create_asset_node(

            asset_id="asset-1",

            target="10.0.0.1",

            hostname="server",

            risk_score=50,

            risk_level="HIGH",

            criticality="HIGH",

            exposure="INTERNAL",

            operating_system="Linux",

            open_ports=[],

            services=[],

            vulnerability_count=2

        )

        self.assertEqual(
            node["id"],
            "asset-1"
        )

        self.assertEqual(
            node["node_type"],
            "asset"
        )

        self.assertEqual(
            node["target"],
            "10.0.0.1"
        )

        self.assertEqual(
            node["vulnerability_count"],
            2
        )


    def test_external_attacker_node(
        self
    ):

        node = (
            create_external_attacker_node()
        )

        self.assertEqual(
            node["id"],
            "external-attacker"
        )

        self.assertEqual(
            node["node_type"],
            "attacker"
        )

        self.assertEqual(
            node["exposure"],
            "EXTERNAL"
        )


    def test_create_attack_edge(
        self
    ):

        edge = create_attack_edge(

            edge_id="edge-1",

            source="source",

            target="target",

            relationship="external_entry",

            confidence="HIGH",

            score=60,

            evidence=[
                "External exposure"
            ]

        )

        self.assertEqual(
            edge["source"],
            "source"
        )

        self.assertEqual(
            edge["target"],
            "target"
        )

        self.assertEqual(
            edge["confidence"],
            "HIGH"
        )

        self.assertEqual(
            edge["score"],
            60
        )


    def test_create_attack_path(
        self
    ):

        path = create_attack_path(

            path_id="path-1",

            node_ids=[
                "external-attacker",
                "asset-1"
            ],

            edge_ids=[
                "edge-1"
            ],

            score=50,

            risk_level="HIGH",

            confidence="MEDIUM",

            evidence=[
                "Evidence"
            ]

        )

        self.assertEqual(
            path["id"],
            "path-1"
        )

        self.assertEqual(
            path["risk_level"],
            "HIGH"
        )

        self.assertEqual(
            len(
                path["nodes"]
            ),
            2
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

        evidence = normalize_evidence(

            [
                "Open port",
                "open port",
                "",
                None,
                "High risk"
            ]

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


    def test_negative_integer_becomes_zero(
        self
    ):

        self.assertEqual(
            normalize_non_negative_integer(
                -10
            ),
            0
        )


    # ======================================
    # PORT TESTS
    # ======================================

    def test_only_open_ports_returned(
        self
    ):

        ports = get_open_ports(
            self.internal_asset[
                "ports"
            ]
        )

        self.assertEqual(
            len(
                ports
            ),
            1
        )

        self.assertEqual(
            ports[0]["port"],
            80
        )


    def test_duplicate_open_ports_removed(
        self
    ):

        ports = get_open_ports(

            [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open"
                },

                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open"
                }

            ]

        )

        self.assertEqual(
            len(
                ports
            ),
            1
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


    def test_sensitive_ports_detected(
        self
    ):

        ports = (
            get_sensitive_open_ports(
                self.sensitive_asset
            )
        )

        self.assertEqual(
            ports,
            [
                445,
                3389
            ]
        )


    # ======================================
    # ASSET NORMALIZATION TESTS
    # ======================================

    def test_assets_filtered_by_owner(
        self
    ):

        assets = normalize_assets(

            [
                self.internal_asset,
                self.other_user_asset
            ],

            created_by=self.user_id

        )

        self.assertEqual(
            len(
                assets
            ),
            1
        )

        self.assertEqual(
            assets[0]["_id"],
            "asset-internal"
        )


    def test_asset_without_id_rejected(
        self
    ):

        asset = dict(
            self.internal_asset
        )

        asset.pop(
            "_id"
        )

        assets = normalize_assets(
            [
                asset
            ],
            created_by=self.user_id
        )

        self.assertEqual(
            assets,
            []
        )


    def test_asset_without_target_rejected(
        self
    ):

        asset = dict(
            self.internal_asset
        )

        asset["target"] = ""

        assets = normalize_assets(
            [
                asset
            ],
            created_by=self.user_id
        )

        self.assertEqual(
            assets,
            []
        )


    def test_build_asset_node(
        self
    ):

        node = build_asset_node(
            self.internal_asset
        )

        self.assertEqual(
            node["id"],
            "asset-internal"
        )

        self.assertEqual(
            node["risk_score"],
            12
        )

        self.assertEqual(
            node["exposure"],
            "INTERNAL"
        )

        self.assertEqual(
            len(
                node["open_ports"]
            ),
            1
        )


    # ======================================
    # EXPOSURE TESTS
    # ======================================

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
                "internal"
            ),
            "INTERNAL"
        )


    def test_invalid_exposure_defaults_internal(
        self
    ):

        self.assertEqual(
            normalize_exposure(
                "invalid"
            ),
            "INTERNAL"
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


    def test_vulnerability_contribution(
        self
    ):

        score = (
            calculate_vulnerability_contribution(
                self.sensitive_asset
            )
        )

        self.assertGreater(
            score,
            0
        )


    def test_resolved_vulnerability_ignored(
        self
    ):

        asset = dict(
            self.sensitive_asset
        )

        asset["vulnerabilities"] = [

            {
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "status": "resolved"
            }

        ]

        score = (
            calculate_vulnerability_contribution(
                asset
            )
        )

        self.assertEqual(
            score,
            0
        )


    def test_rejected_vulnerability_ignored(
        self
    ):

        asset = dict(
            self.sensitive_asset
        )

        asset["vulnerabilities"] = [

            {
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "status": "rejected"
            }

        ]

        score = (
            calculate_vulnerability_contribution(
                asset
            )
        )

        self.assertEqual(
            score,
            0
        )


    # ======================================
    # EXTERNAL ENTRY TESTS
    # ======================================

    def test_external_asset_creates_entry_edge(
        self
    ):

        edges = (
            generate_external_entry_edges(
                [
                    self.external_asset
                ]
            )
        )

        self.assertEqual(
            len(
                edges
            ),
            1
        )

        self.assertEqual(
            edges[0]["source"],
            "external-attacker"
        )

        self.assertEqual(
            edges[0]["target"],
            "asset-external"
        )


    def test_internal_asset_does_not_create_entry_edge(
        self
    ):

        edges = (
            generate_external_entry_edges(
                [
                    self.internal_asset
                ]
            )
        )

        self.assertEqual(
            edges,
            []
        )


    # ======================================
    # ASSET RELATIONSHIP TESTS
    # ======================================

    def test_single_asset_has_no_relationship(
        self
    ):

        edges = (
            generate_asset_relationships(
                [
                    self.internal_asset
                ]
            )
        )

        self.assertEqual(
            edges,
            []
        )


    def test_sensitive_target_can_create_potential_relationship(
        self
    ):

        relationship = (
            evaluate_asset_relationship(
                self.external_asset,
                self.sensitive_asset
            )
        )

        self.assertIsNotNone(
            relationship
        )

        self.assertIn(
            relationship[
                "confidence"
            ],
            [
                "LOW",
                "MEDIUM"
            ]
        )


    def test_low_evidence_target_rejected(
        self
    ):

        relationship = (
            evaluate_asset_relationship(
                self.external_asset,
                self.internal_asset
            )
        )

        self.assertIsNone(
            relationship
        )


    def test_asset_relationship_never_high_confidence(
        self
    ):

        relationship = (
            evaluate_asset_relationship(
                self.external_asset,
                self.sensitive_asset
            )
        )

        self.assertIsNotNone(
            relationship
        )

        self.assertNotEqual(
            relationship[
                "confidence"
            ],
            "HIGH"
        )


    # ======================================
    # ATTACK SCORE TESTS
    # ======================================

    def test_attack_score_stays_in_range(
        self
    ):

        score = (
            calculate_asset_attack_score(
                self.sensitive_asset,
                confidence="HIGH"
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
            calculate_asset_attack_score(
                external,
                confidence="MEDIUM"
            )
        )

        internal_score = (
            calculate_asset_attack_score(
                internal,
                confidence="MEDIUM"
            )
        )


        self.assertGreater(
            external_score,
            internal_score
        )


    # ======================================
    # PATH SCORE TESTS
    # ======================================

    def test_path_score_empty_edges_zero(
        self
    ):

        self.assertEqual(
            calculate_path_score(
                []
            ),
            0
        )


    def test_path_score_single_edge(
        self
    ):

        score = calculate_path_score(

            [
                {
                    "score": 60
                }
            ]

        )

        self.assertEqual(
            score,
            60
        )


    def test_path_score_does_not_exceed_100(
        self
    ):

        score = calculate_path_score(

            [
                {
                    "score": 100
                },

                {
                    "score": 100
                },

                {
                    "score": 100
                }

            ]

        )

        self.assertLessEqual(
            score,
            100
        )


    # ======================================
    # PATH RISK LEVEL TESTS
    # ======================================

    def test_low_path_risk(
        self
    ):

        self.assertEqual(
            determine_path_risk_level(
                10
            ),
            "LOW"
        )


    def test_medium_path_risk(
        self
    ):

        self.assertEqual(
            determine_path_risk_level(
                30
            ),
            "MEDIUM"
        )


    def test_high_path_risk(
        self
    ):

        self.assertEqual(
            determine_path_risk_level(
                60
            ),
            "HIGH"
        )


    def test_critical_path_risk(
        self
    ):

        self.assertEqual(
            determine_path_risk_level(
                80
            ),
            "CRITICAL"
        )


    # ======================================
    # PATH CONFIDENCE TESTS
    # ======================================

    def test_path_confidence_weakest_edge_wins(
        self
    ):

        confidence = (
            calculate_path_confidence(

                [
                    {
                        "confidence": "HIGH"
                    },

                    {
                        "confidence": "LOW"
                    }

                ]

            )
        )

        self.assertEqual(
            confidence,
            "LOW"
        )


    def test_medium_path_confidence(
        self
    ):

        confidence = (
            calculate_path_confidence(

                [
                    {
                        "confidence": "HIGH"
                    },

                    {
                        "confidence": "MEDIUM"
                    }

                ]

            )
        )

        self.assertEqual(
            confidence,
            "MEDIUM"
        )


    # ======================================
    # GRAPH GENERATION TESTS
    # ======================================

    def test_empty_assets_generate_empty_graph(
        self
    ):

        graph = generate_attack_graph(

            assets=[],

            created_by=self.user_id

        )

        self.assertEqual(
            graph["statistics"][
                "total_assets"
            ],
            0
        )

        self.assertEqual(
            graph["statistics"][
                "total_nodes"
            ],
            0
        )

        self.assertEqual(
            graph["statistics"][
                "total_paths"
            ],
            0
        )


    def test_internal_asset_has_no_attacker_node(
        self
    ):

        graph = generate_attack_graph(

            assets=[
                self.internal_asset
            ],

            created_by=self.user_id

        )

        self.assertEqual(
            graph["statistics"][
                "total_assets"
            ],
            1
        )

        self.assertEqual(
            graph["statistics"][
                "total_nodes"
            ],
            1
        )

        self.assertEqual(
            graph["statistics"][
                "total_edges"
            ],
            0
        )

        self.assertEqual(
            graph["statistics"][
                "total_paths"
            ],
            0
        )


    def test_external_asset_adds_attacker_node(
        self
    ):

        graph = generate_attack_graph(

            assets=[
                self.external_asset
            ],

            created_by=self.user_id

        )

        node_ids = [

            node["id"]

            for node
            in graph["nodes"]

        ]


        self.assertIn(
            "external-attacker",
            node_ids
        )

        self.assertEqual(
            graph["statistics"][
                "total_assets"
            ],
            1
        )

        self.assertEqual(
            graph["statistics"][
                "total_nodes"
            ],
            2
        )


    def test_external_asset_generates_attack_path(
        self
    ):

        graph = generate_attack_graph(

            assets=[
                self.external_asset
            ],

            created_by=self.user_id

        )

        self.assertEqual(
            graph["statistics"][
                "total_paths"
            ],
            1
        )

        self.assertEqual(

            graph["paths"][0][
                "nodes"
            ],

            [
                "external-attacker",
                "asset-external"
            ]

        )


    def test_multi_asset_attack_path_generation(
        self
    ):

        graph = generate_attack_graph(

            assets=[
                self.external_asset,
                self.sensitive_asset
            ],

            created_by=self.user_id

        )


        self.assertGreaterEqual(
            graph["statistics"][
                "total_assets"
            ],
            2
        )

        self.assertGreaterEqual(
            graph["statistics"][
                "total_edges"
            ],
            2
        )

        self.assertGreaterEqual(
            graph["statistics"][
                "total_paths"
            ],
            1
        )


        discovered = False


        for path in graph["paths"]:

            if (

                "external-attacker"
                in path["nodes"]

                and

                "asset-external"
                in path["nodes"]

                and

                "asset-sensitive"
                in path["nodes"]

            ):

                discovered = True


        self.assertTrue(
            discovered
        )


    # ======================================
    # OWNERSHIP ISOLATION TESTS
    # ======================================

    def test_other_user_asset_not_in_graph(
        self
    ):

        graph = generate_attack_graph(

            assets=[
                self.internal_asset,
                self.other_user_asset
            ],

            created_by=self.user_id

        )


        node_ids = [

            node["id"]

            for node
            in graph["nodes"]

        ]


        self.assertIn(
            "asset-internal",
            node_ids
        )

        self.assertNotIn(
            "asset-other-user",
            node_ids
        )


    def test_different_users_never_connected(
        self
    ):

        graph = generate_attack_graph(

            assets=[
                self.external_asset,
                self.other_user_asset
            ],

            created_by=self.user_id

        )


        for edge in graph["edges"]:

            self.assertNotEqual(
                edge["source"],
                "asset-other-user"
            )

            self.assertNotEqual(
                edge["target"],
                "asset-other-user"
            )


    # ======================================
    # DEDUPLICATION TESTS
    # ======================================

    def test_duplicate_edges_removed(
        self
    ):

        edge = {

            "id": "edge-1",

            "source": "a",

            "target": "b",

            "score": 20

        }


        edges = deduplicate_edges(

            [
                edge,
                dict(
                    edge
                )
            ]

        )


        self.assertEqual(
            len(
                edges
            ),
            1
        )


    def test_duplicate_paths_removed(
        self
    ):

        path = {

            "id": "path-1",

            "nodes": [
                "a",
                "b"
            ]

        }


        paths = deduplicate_paths(

            [
                path,
                dict(
                    path
                )
            ]

        )


        self.assertEqual(
            len(
                paths
            ),
            1
        )


    # ======================================
    # GRAPH STATISTICS TEST
    # ======================================

    def test_graph_statistics(
        self
    ):

        nodes = [

            create_external_attacker_node(),

            create_asset_node(

                asset_id="asset-1",

                target="10.0.0.1"

            )

        ]


        edges = [

            create_attack_edge(

                edge_id="edge-1",

                source="external-attacker",

                target="asset-1",

                relationship="external_entry",

                confidence="HIGH",

                score=80

            )

        ]


        paths = [

            create_attack_path(

                path_id="path-1",

                node_ids=[
                    "external-attacker",
                    "asset-1"
                ],

                edge_ids=[
                    "edge-1"
                ],

                score=80,

                risk_level="CRITICAL",

                confidence="HIGH"

            )

        ]


        statistics = (
            create_graph_statistics(

                nodes=nodes,

                edges=edges,

                paths=paths

            )
        )


        self.assertEqual(
            statistics[
                "total_nodes"
            ],
            2
        )

        self.assertEqual(
            statistics[
                "total_assets"
            ],
            1
        )

        self.assertEqual(
            statistics[
                "total_edges"
            ],
            1
        )

        self.assertEqual(
            statistics[
                "total_paths"
            ],
            1
        )

        self.assertEqual(
            statistics[
                "critical_risk_paths"
            ],
            1
        )


    # ======================================
    # MALFORMED INPUT TESTS
    # ======================================

    def test_invalid_assets_input_returns_empty_graph(
        self
    ):

        graph = generate_attack_graph(

            assets=None,

            created_by=self.user_id

        )

        self.assertEqual(
            graph["nodes"],
            []
        )

        self.assertEqual(
            graph["edges"],
            []
        )

        self.assertEqual(
            graph["paths"],
            []
        )


    def test_invalid_port_list_returns_empty(
        self
    ):

        self.assertEqual(
            get_open_ports(
                None
            ),
            []
        )


    def test_invalid_vulnerability_list_safe(
        self
    ):

        asset = dict(
            self.internal_asset
        )

        asset[
            "vulnerabilities"
        ] = None

        asset[
            "vulnerability_count"
        ] = None


        count = (
            get_vulnerability_count(
                asset
            )
        )


        self.assertEqual(
            count,
            0
        )


# ==========================================
# RUN TESTS
# ==========================================

if __name__ == "__main__":

    unittest.main()