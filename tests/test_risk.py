import unittest

from services.risk_service import (
    calculate_risk_score,
    calculate_vulnerability_risk,
    calculate_attack_surface_risk,
    normalize_cvss_score,
    normalize_confidence,
    normalize_severity,
    determine_risk_level
)


class TestRiskEngine(unittest.TestCase):


    def test_empty_scan_has_zero_risk(self):

        result = calculate_risk_score(
            vulnerabilities=[],
            ports=[]
        )

        self.assertEqual(
            result["risk_score"],
            0
        )

        self.assertEqual(
            result["risk_level"],
            "LOW"
        )


    def test_open_ports_create_attack_surface_risk(self):

        ports = [
            {
                "port": 80,
                "state": "open"
            },
            {
                "port": 443,
                "state": "open"
            }
        ]

        result = calculate_attack_surface_risk(
            ports
        )

        self.assertGreater(
            result["score"],
            0
        )


    def test_sensitive_ports_add_more_risk(self):

        ports = [
            {
                "port": 445,
                "state": "open"
            },
            {
                "port": 3389,
                "state": "open"
            }
        ]

        result = calculate_attack_surface_risk(
            ports
        )

        self.assertIn(
            445,
            result["sensitive_ports"]
        )

        self.assertIn(
            3389,
            result["sensitive_ports"]
        )

        self.assertGreater(
            result["score"],
            0
        )


    def test_closed_ports_are_ignored(self):

        ports = [
            {
                "port": 445,
                "state": "closed"
            }
        ]

        result = calculate_attack_surface_risk(
            ports
        )

        self.assertEqual(
            result["score"],
            0
        )


    def test_high_confidence_cve_contributes_risk(self):

        vulnerabilities = [
            {
                "cve_id": "CVE-TEST-0001",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "status": "potential"
            }
        ]

        result = calculate_vulnerability_risk(
            vulnerabilities
        )

        self.assertGreater(
            result["score"],
            0
        )

        self.assertEqual(
            result["critical_findings"],
            1
        )


    def test_medium_confidence_scores_lower_than_high(self):

        high = [
            {
                "cve_id": "CVE-HIGH",
                "cvss_score": 8.0,
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "potential"
            }
        ]

        medium = [
            {
                "cve_id": "CVE-MEDIUM",
                "cvss_score": 8.0,
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "status": "potential"
            }
        ]

        high_result = calculate_vulnerability_risk(
            high
        )

        medium_result = calculate_vulnerability_risk(
            medium
        )

        self.assertGreater(
            high_result["score"],
            medium_result["score"]
        )


    def test_low_confidence_scores_lower_than_medium(self):

        medium = [
            {
                "cve_id": "CVE-MEDIUM",
                "cvss_score": 8.0,
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "status": "potential"
            }
        ]

        low = [
            {
                "cve_id": "CVE-LOW",
                "cvss_score": 8.0,
                "severity": "HIGH",
                "confidence": "LOW",
                "status": "potential"
            }
        ]

        medium_result = calculate_vulnerability_risk(
            medium
        )

        low_result = calculate_vulnerability_risk(
            low
        )

        self.assertGreater(
            medium_result["score"],
            low_result["score"]
        )


    def test_rejected_finding_has_no_risk(self):

        vulnerabilities = [
            {
                "cve_id": "CVE-REJECTED",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "status": "rejected"
            }
        ]

        result = calculate_vulnerability_risk(
            vulnerabilities
        )

        self.assertEqual(
            result["score"],
            0
        )


    def test_resolved_finding_has_no_risk(self):

        vulnerabilities = [
            {
                "cve_id": "CVE-RESOLVED",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "status": "resolved"
            }
        ]

        result = calculate_vulnerability_risk(
            vulnerabilities
        )

        self.assertEqual(
            result["score"],
            0
        )


    def test_score_does_not_exceed_100(self):

        vulnerabilities = []

        for index in range(20):

            vulnerabilities.append(
                {
                    "cve_id": f"CVE-TEST-{index}",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "status": "potential"
                }
            )

        ports = []

        for port in [
            21,
            22,
            23,
            25,
            53,
            135,
            139,
            445,
            1433,
            3306,
            3389,
            5432,
            5900,
            6379,
            27017
        ]:

            ports.append(
                {
                    "port": port,
                    "state": "open"
                }
            )

        result = calculate_risk_score(
            vulnerabilities=vulnerabilities,
            ports=ports
        )

        self.assertLessEqual(
            result["risk_score"],
            100
        )


    def test_cvss_normalization(self):

        self.assertEqual(
            normalize_cvss_score(15),
            10.0
        )

        self.assertEqual(
            normalize_cvss_score(-5),
            0.0
        )

        self.assertEqual(
            normalize_cvss_score("7.5"),
            7.5
        )


    def test_confidence_normalization(self):

        self.assertEqual(
            normalize_confidence("high"),
            "HIGH"
        )

        self.assertEqual(
            normalize_confidence("invalid"),
            "UNKNOWN"
        )


    def test_severity_normalization(self):

        self.assertEqual(
            normalize_severity("critical"),
            "CRITICAL"
        )

        self.assertEqual(
            normalize_severity("invalid"),
            "UNKNOWN"
        )


    def test_low_risk_level(self):

        self.assertEqual(
            determine_risk_level(10),
            "LOW"
        )


    def test_medium_risk_level(self):

        self.assertEqual(
            determine_risk_level(30),
            "MEDIUM"
        )


    def test_high_risk_level(self):

        self.assertEqual(
            determine_risk_level(60),
            "HIGH"
        )


    def test_critical_risk_level(self):

        self.assertEqual(
            determine_risk_level(85),
            "CRITICAL"
        )


    def test_combined_scan_risk(self):

        vulnerabilities = [
            {
                "cve_id": "CVE-TEST-1000",
                "cvss_score": 8.8,
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "potential"
            }
        ]

        ports = [
            {
                "port": 80,
                "state": "open"
            },
            {
                "port": 445,
                "state": "open"
            }
        ]

        result = calculate_risk_score(
            vulnerabilities=vulnerabilities,
            ports=ports
        )

        self.assertGreater(
            result["risk_score"],
            0
        )

        self.assertIn(
            result["risk_level"],
            {
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            }
        )

        self.assertIn(
            "risk_breakdown",
            result
        )


if __name__ == "__main__":
    unittest.main()