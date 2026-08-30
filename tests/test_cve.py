import unittest


from services.vulnerability_service import (

    normalize_service,

    normalize_text,

    meaningful_tokens,

    normalize_version,

    version_to_tuple,

    compare_versions,

    versions_equal,

    product_matches_cpe,

    evaluate_version_match,

    extract_windows_version,

    evaluate_os_cpes,

    evaluate_cve_applicability,

    sort_findings_by_severity

)


# ==========================================
# CVE / VULNERABILITY ENGINE TESTS
# ==========================================


class TestCVEEngine(unittest.TestCase):


    # ======================================
    # SERVICE NORMALIZATION
    # ======================================

    def test_normalize_service(self):

        service = {

            "port": 5000,

            "name": "http",

            "product": "Werkzeug httpd",

            "version": "3.1.8"

        }


        result = normalize_service(
            service
        )


        self.assertIsNotNone(
            result
        )


        self.assertEqual(
            result["port"],
            5000
        )


        self.assertEqual(
            result["service"],
            "http"
        )


        self.assertEqual(
            result["product"],
            "Werkzeug httpd"
        )


        self.assertEqual(
            result["version"],
            "3.1.8"
        )


    # ======================================
    # EMPTY PRODUCT
    # ======================================

    def test_service_without_product_is_rejected(self):

        service = {

            "port": 445,

            "name": "microsoft-ds",

            "product": "",

            "version": ""

        }


        result = normalize_service(
            service
        )


        self.assertIsNone(
            result
        )


    # ======================================
    # UNKNOWN VERSION NORMALIZATION
    # ======================================

    def test_unknown_version_becomes_none(self):

        service = {

            "port": 135,

            "name": "msrpc",

            "product": "Microsoft Windows RPC",

            "version": "-"

        }


        result = normalize_service(
            service
        )


        self.assertIsNotNone(
            result
        )


        self.assertIsNone(
            result["version"]
        )


    # ======================================
    # TEXT NORMALIZATION
    # ======================================

    def test_normalize_text(self):

        result = normalize_text(
            "VMware-Authentication_Daemon"
        )


        self.assertEqual(
            result,
            "vmware authentication daemon"
        )


    # ======================================
    # TOKEN NORMALIZATION
    # ======================================

    def test_meaningful_tokens(self):

        result = meaningful_tokens(
            "Werkzeug HTTP Server"
        )


        self.assertIn(
            "werkzeug",
            result
        )


        self.assertNotIn(
            "http",
            result
        )


        self.assertNotIn(
            "server",
            result
        )


    # ======================================
    # VERSION NORMALIZATION
    # ======================================

    def test_normalize_version(self):

        self.assertEqual(

            normalize_version(
                "v3.1.8"
            ),

            "3.1.8"

        )


    # ======================================
    # VERSION TUPLE
    # ======================================

    def test_version_to_tuple(self):

        result = version_to_tuple(
            "3.1.8"
        )


        self.assertEqual(
            result,
            (3, 1, 8)
        )


    # ======================================
    # VERSION COMPARISON
    # ======================================

    def test_version_comparison_equal(self):

        result = compare_versions(
            "3.1.8",
            "3.1.8"
        )


        self.assertEqual(
            result,
            0
        )


    def test_version_comparison_lower(self):

        result = compare_versions(
            "3.1.7",
            "3.1.8"
        )


        self.assertEqual(
            result,
            -1
        )


    def test_version_comparison_higher(self):

        result = compare_versions(
            "3.2.0",
            "3.1.8"
        )


        self.assertEqual(
            result,
            1
        )


    def test_versions_equal_padding(self):

        self.assertTrue(

            versions_equal(
                "1.0",
                "1.0.0"
            )

        )


    # ======================================
    # PRODUCT MATCHING
    # ======================================

    def test_werkzeug_product_match(self):

        affected_product = {

            "vendor": "palletsprojects",

            "product": "werkzeug",

            "version": None

        }


        result = product_matches_cpe(

            "Werkzeug httpd",

            affected_product

        )


        self.assertTrue(
            result
        )


    def test_vmware_product_match(self):

        affected_product = {

            "vendor": "vmware",

            "product": (
                "vmware authentication daemon"
            ),

            "version": None

        }


        result = product_matches_cpe(

            "VMware Authentication Daemon",

            affected_product

        )


        self.assertTrue(
            result
        )


    # ======================================
    # VERSION RANGE MATCHING
    # ======================================

    def test_version_inside_affected_range(self):

        affected_product = {

            "version": None,

            "version_start_including": "1.0",

            "version_start_excluding": None,

            "version_end_including": "2.0",

            "version_end_excluding": None

        }


        result = evaluate_version_match(

            discovered_version="1.5",

            affected_product=affected_product

        )


        self.assertTrue(
            result
        )


    def test_version_outside_affected_range(self):

        affected_product = {

            "version": None,

            "version_start_including": "1.0",

            "version_start_excluding": None,

            "version_end_including": "2.0",

            "version_end_excluding": None

        }


        result = evaluate_version_match(

            discovered_version="3.0",

            affected_product=affected_product

        )


        self.assertFalse(
            result
        )


    def test_version_end_excluding(self):

        affected_product = {

            "version": None,

            "version_start_including": None,

            "version_start_excluding": None,

            "version_end_including": None,

            "version_end_excluding": "3.1.8"

        }


        result = evaluate_version_match(

            discovered_version="3.1.8",

            affected_product=affected_product

        )


        self.assertFalse(
            result
        )


    # ======================================
    # WINDOWS VERSION DETECTION
    # ======================================

    def test_windows_11_detection(self):

        result = extract_windows_version(
            "Microsoft Windows 11 24H2 - 25H2"
        )


        self.assertEqual(
            result,
            "windows_11"
        )


    def test_windows_xp_detection(self):

        result = extract_windows_version(
            "Microsoft Windows XP"
        )


        self.assertEqual(
            result,
            "windows_xp"
        )


    # ======================================
    # PLATFORM MATCHING
    # ======================================

    def test_windows_11_platform_matches(self):

        os_cpes = [

            {

                "part": "o",

                "vendor": "microsoft",

                "product": "windows 11",

                "version": None

            }

        ]


        result = evaluate_os_cpes(

            os_cpes=os_cpes,

            os_detection=(
                "Microsoft Windows 11 "
                "24H2 - 25H2"
            )

        )


        self.assertTrue(
            result
        )


    def test_windows_xp_platform_rejected_for_windows_11(self):

        os_cpes = [

            {

                "part": "o",

                "vendor": "microsoft",

                "product": "windows xp",

                "version": None

            }

        ]


        result = evaluate_os_cpes(

            os_cpes=os_cpes,

            os_detection=(
                "Microsoft Windows 11 "
                "24H2 - 25H2"
            )

        )


        self.assertFalse(
            result
        )


    # ======================================
    # OLD WINDOWS RPC FALSE POSITIVE TEST
    # ======================================

    def test_old_windows_rpc_cve_rejected(self):

        cve = {

            "cve_id": "CVE-2003-TEST",

            "description": (
                "A vulnerability affecting "
                "Microsoft Windows XP and "
                "Windows 2000 RPC services."
            ),

            "cvss_score": 7.5,

            "severity": "HIGH",

            "affected_products": [

                {

                    "part": "o",

                    "vendor": "microsoft",

                    "product": "windows xp",

                    "version": None,

                    "version_start_including": None,

                    "version_start_excluding": None,

                    "version_end_including": None,

                    "version_end_excluding": None

                }

            ]

        }


        result = evaluate_cve_applicability(

            cve=cve,

            product="Microsoft Windows RPC",

            version=None,

            os_detection=(
                "Microsoft Windows 11 "
                "24H2 - 25H2"
            )

        )


        self.assertFalse(
            result["accepted"]
        )


    # ======================================
    # VALID PRODUCT + VERSION TEST
    # ======================================

    def test_valid_product_version_candidate(self):

        cve = {

            "cve_id": "CVE-TEST-0001",

            "description": (
                "Test vulnerability for Werkzeug."
            ),

            "cvss_score": 7.5,

            "severity": "HIGH",

            "affected_products": [

                {

                    "part": "a",

                    "vendor": "palletsprojects",

                    "product": "werkzeug",

                    "version": None,

                    "version_start_including": "3.0.0",

                    "version_start_excluding": None,

                    "version_end_including": "3.1.8",

                    "version_end_excluding": None

                }

            ]

        }


        result = evaluate_cve_applicability(

            cve=cve,

            product="Werkzeug httpd",

            version="3.1.8",

            os_detection=(
                "Microsoft Windows 11"
            )

        )


        self.assertTrue(
            result["accepted"]
        )


        self.assertTrue(
            result["product_match"]
        )


        self.assertTrue(
            result["version_match"]
        )


        self.assertEqual(
            result["confidence"],
            "HIGH"
        )


    # ======================================
    # VERSION OUTSIDE RANGE REJECTION
    # ======================================

    def test_candidate_rejected_when_version_is_fixed(self):

        cve = {

            "cve_id": "CVE-TEST-0002",

            "description": (
                "Example Werkzeug vulnerability."
            ),

            "cvss_score": 8.0,

            "severity": "HIGH",

            "affected_products": [

                {

                    "part": "a",

                    "vendor": "palletsprojects",

                    "product": "werkzeug",

                    "version": None,

                    "version_start_including": None,

                    "version_start_excluding": None,

                    "version_end_including": None,

                    "version_end_excluding": "3.0.0"

                }

            ]

        }


        result = evaluate_cve_applicability(

            cve=cve,

            product="Werkzeug httpd",

            version="3.1.8",

            os_detection=(
                "Microsoft Windows 11"
            )

        )


        self.assertFalse(
            result["accepted"]
        )


        self.assertFalse(
            result["version_match"]
        )


    # ======================================
    # PRODUCT ONLY REJECTION
    # ======================================

    def test_product_only_candidate_not_accepted(self):

        cve = {

            "cve_id": "CVE-TEST-0003",

            "description": (
                "VMware Authentication Daemon "
                "vulnerability."
            ),

            "cvss_score": 5.0,

            "severity": "MEDIUM",

            "affected_products": [

                {

                    "part": "a",

                    "vendor": "vmware",

                    "product": (
                        "vmware authentication daemon"
                    ),

                    "version": None,

                    "version_start_including": None,

                    "version_start_excluding": None,

                    "version_end_including": None,

                    "version_end_excluding": None

                }

            ]

        }


        result = evaluate_cve_applicability(

            cve=cve,

            product=(
                "VMware Authentication Daemon"
            ),

            version=None,

            os_detection=(
                "Microsoft Windows 11"
            )

        )


        self.assertFalse(
            result["accepted"]
        )


        self.assertEqual(
            result["confidence"],
            "LOW"
        )


    # ======================================
    # SEVERITY SORTING
    # ======================================

    def test_findings_sorted_by_severity(self):

        findings = [

            {

                "severity": "LOW",

                "cvss_score": 3.0,

                "confidence": "HIGH"

            },

            {

                "severity": "CRITICAL",

                "cvss_score": 9.8,

                "confidence": "HIGH"

            },

            {

                "severity": "HIGH",

                "cvss_score": 8.0,

                "confidence": "MEDIUM"

            }

        ]


        result = sort_findings_by_severity(
            findings
        )


        self.assertEqual(

            result[0]["severity"],

            "CRITICAL"

        )


        self.assertEqual(

            result[1]["severity"],

            "HIGH"

        )


        self.assertEqual(

            result[2]["severity"],

            "LOW"

        )


# ==========================================
# RUN TESTS
# ==========================================


if __name__ == "__main__":

    unittest.main()