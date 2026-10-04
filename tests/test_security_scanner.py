import unittest

from models.security_finding_model import (
    create_security_finding,
    normalize_severity,
    normalize_confidence,
    normalize_status,
    normalize_port,
    normalize_cvss_score
)

from services.security_scanner_service import (
    analyze_security_findings,
    analyze_network_services,
    analyze_application_services,
    analyze_host_security,
    analyze_web_services,
    deduplicate_findings
)


class TestSecurityFindingModel(unittest.TestCase):

    # ======================================
    # BASIC FINDING CREATION
    # ======================================

    def test_create_security_finding(self):

        finding = create_security_finding(
            finding_type="SERVICE",
            category="INSECURE_PROTOCOL",
            title="Telnet Service Exposed",
            target="192.168.56.101",
            port=23,
            protocol="tcp",
            service="telnet",
            severity="HIGH",
            confidence="HIGH",
            status="OBSERVED",
            evidence=[
                "TCP/23 was observed open."
            ],
            evidence_source="Nmap"
        )

        self.assertEqual(
            finding["finding_type"],
            "SERVICE"
        )

        self.assertEqual(
            finding["port"],
            23
        )

        self.assertEqual(
            finding["severity"],
            "HIGH"
        )

        self.assertEqual(
            finding["confidence"],
            "HIGH"
        )

        self.assertEqual(
            finding["status"],
            "OBSERVED"
        )

        self.assertIsNotNone(
            finding["finding_id"]
        )


    # ======================================
    # NORMALIZATION
    # ======================================

    def test_normalization(self):

        self.assertEqual(
            normalize_severity("high"),
            "HIGH"
        )

        self.assertEqual(
            normalize_confidence("medium"),
            "MEDIUM"
        )

        self.assertEqual(
            normalize_status("potential"),
            "POTENTIAL"
        )

        self.assertEqual(
            normalize_port("443"),
            443
        )

        self.assertEqual(
            normalize_cvss_score("9.8"),
            9.8
        )


    # ======================================
    # INVALID PORT
    # ======================================

    def test_invalid_port(self):

        self.assertIsNone(
            normalize_port(70000)
        )

        self.assertIsNone(
            normalize_port("invalid")
        )


    # ======================================
    # CVE COMPATIBILITY
    # ======================================

    def test_cve_compatibility(self):

        finding = create_security_finding(
            finding_type="CVE",
            category="KNOWN_CVE",
            title="CVE-2011-2523",
            target="192.168.56.101",
            port=21,
            service="ftp",
            product="vsftpd",
            version="2.3.4",
            severity="CRITICAL",
            confidence="HIGH",
            status="POTENTIAL",
            cve_id="CVE-2011-2523",
            cvss_score=9.8,
            cvss_version="3.1",
            evidence_source="NVD"
        )

        self.assertEqual(
            finding["cve_id"],
            "CVE-2011-2523"
        )

        self.assertEqual(
            finding["cvss_score"],
            9.8
        )

        self.assertEqual(
            finding["product"],
            "vsftpd"
        )

        self.assertEqual(
            finding["version"],
            "2.3.4"
        )


class TestSecurityScanner(unittest.TestCase):

    def setUp(self):

        # Simulated Nmap evidence matching the
        # structure produced by AttackLens.

        self.target = "192.168.56.101"

        self.ports = [

            {
                "port": 21,
                "protocol": "tcp",
                "state": "open",
                "service": "ftp",
                "product": "vsftpd",
                "version": "2.3.4"
            },

            {
                "port": 23,
                "protocol": "tcp",
                "state": "open",
                "service": "telnet",
                "product": "Linux telnetd",
                "version": None
            },

            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.2.8"
            },

            {
                "port": 3306,
                "protocol": "tcp",
                "state": "open",
                "service": "mysql",
                "product": "MySQL",
                "version": "5.0.51a"
            }
        ]

        self.services = [

            {
                "port": 21,
                "name": "ftp",
                "product": "vsftpd",
                "version": "2.3.4"
            },

            {
                "port": 23,
                "name": "telnet",
                "product": "Linux telnetd",
                "version": None
            },

            {
                "port": 80,
                "name": "http",
                "product": "Apache httpd",
                "version": "2.2.8"
            },

            {
                "port": 3306,
                "name": "mysql",
                "product": "MySQL",
                "version": "5.0.51a"
            }
        ]


    # ======================================
    # TELNET DETECTION
    # ======================================

    def test_telnet_detection(self):

        findings = analyze_network_services(
            target=self.target,
            ports=self.ports,
            services=self.services
        )

        telnet = [
            finding
            for finding in findings
            if finding.get("port") == 23
        ]

        self.assertEqual(
            len(telnet),
            1
        )

        self.assertEqual(
            telnet[0]["category"],
            "INSECURE_PROTOCOL"
        )

        self.assertEqual(
            telnet[0]["severity"],
            "HIGH"
        )

        self.assertEqual(
            telnet[0]["status"],
            "OBSERVED"
        )


    # ======================================
    # FTP DETECTION
    # ======================================

    def test_ftp_detection(self):

        findings = analyze_network_services(
            target=self.target,
            ports=self.ports,
            services=self.services
        )

        ftp = [
            finding
            for finding in findings
            if finding.get("port") == 21
        ]

        self.assertEqual(
            len(ftp),
            1
        )

        self.assertEqual(
            ftp[0]["category"],
            "FTP_EXPOSURE"
        )


    # ======================================
    # DATABASE EXPOSURE
    # ======================================

    def test_database_exposure(self):

        findings = analyze_network_services(
            target=self.target,
            ports=self.ports,
            services=self.services
        )

        mysql = [
            finding
            for finding in findings
            if finding.get("port") == 3306
        ]

        self.assertEqual(
            len(mysql),
            1
        )

        self.assertEqual(
            mysql[0]["category"],
            "DATABASE_EXPOSURE"
        )

        self.assertEqual(
            mysql[0]["severity"],
            "HIGH"
        )


    # ======================================
    # WEB SURFACE DETECTION
    # ======================================

    def test_web_surface_detection(self):

        findings = analyze_web_services(
            target=self.target,
            ports=self.ports,
            services=self.services
        )

        web = [
            finding
            for finding in findings
            if finding.get("port") == 80
        ]

        self.assertEqual(
            len(web),
            1
        )

        self.assertEqual(
            web[0]["category"],
            "WEB_APPLICATION_SURFACE"
        )

        self.assertEqual(
            web[0]["product"],
            "Apache httpd"
        )


    # ======================================
    # APPLICATION VERSION EVIDENCE
    # ======================================

    def test_missing_application_version(self):

        findings = analyze_application_services(
            target=self.target,
            services=self.services
        )

        telnet = [
            finding
            for finding in findings
            if finding.get("port") == 23
        ]

        self.assertEqual(
            len(telnet),
            1
        )

        self.assertEqual(
            telnet[0]["category"],
            "LIMITED_VERSION_EVIDENCE"
        )


    # ======================================
    # HOST ATTACK SURFACE
    # ======================================

    def test_large_host_attack_surface(self):

        ports = []

        services = []

        for port in range(
            1000,
            1011
        ):

            ports.append({
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": "unknown"
            })

        findings = analyze_host_security(
            target=self.target,
            ports=ports,
            services=services,
            os_detection="Linux",
            os_accuracy=98
        )

        attack_surface = [
            finding
            for finding in findings
            if finding.get("category")
            ==
            "LARGE_ATTACK_SURFACE"
        ]

        self.assertEqual(
            len(attack_surface),
            1
        )

        self.assertEqual(
            attack_surface[0]["status"],
            "OBSERVED"
        )


    # ======================================
    # LOW OS CONFIDENCE
    # ======================================

    def test_low_os_detection_confidence(self):

        findings = analyze_host_security(
            target=self.target,
            ports=[],
            services=[],
            os_detection="Linux",
            os_accuracy=65
        )

        os_findings = [
            finding
            for finding in findings
            if finding.get("category")
            ==
            "LOW_CONFIDENCE_OS_DETECTION"
        ]

        self.assertEqual(
            len(os_findings),
            1
        )


    # ======================================
    # DEDUPLICATION
    # ======================================

    def test_deduplication(self):

        finding = create_security_finding(
            finding_type="SERVICE",
            category="INSECURE_PROTOCOL",
            title="Telnet Service Exposed",
            target=self.target,
            port=23,
            service="telnet",
            severity="HIGH"
        )

        findings = deduplicate_findings(
            [
                finding,
                finding.copy()
            ]
        )

        self.assertEqual(
            len(findings),
            1
        )


    # ======================================
    # COMPLETE SCANNER
    # ======================================

    def test_complete_security_scanner(self):

        findings = analyze_security_findings(
            target=self.target,
            ports=self.ports,
            services=self.services,
            os_detection="Linux 2.6.X",
            os_accuracy=98
        )

        self.assertIsInstance(
            findings,
            list
        )

        self.assertGreater(
            len(findings),
            0
        )

        categories = {
            finding.get("category")
            for finding in findings
        }

        self.assertIn(
            "INSECURE_PROTOCOL",
            categories
        )

        self.assertIn(
            "DATABASE_EXPOSURE",
            categories
        )

        self.assertIn(
            "WEB_APPLICATION_SURFACE",
            categories
        )


if __name__ == "__main__":

    unittest.main()