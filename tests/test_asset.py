# ==========================================
# ATTACKLENS
# ASSET SERVICE TESTS
# ==========================================

import unittest

from datetime import (
    datetime,
    timezone,
    timedelta
)

from bson import ObjectId


from services.asset_service import (
    normalize_list,
    get_open_ports,
    normalize_risk_level,
    get_scan_timestamp,
    build_asset_update_from_scan,
    upsert_asset_from_scan,
    get_asset_statistics
)


# ==========================================
# FAKE MONGODB RESULT
# ==========================================

class FakeInsertResult:

    def __init__(
        self,
        inserted_id
    ):

        self.inserted_id = inserted_id


class FakeUpdateResult:

    def __init__(
        self,
        matched_count=0
    ):

        self.matched_count = matched_count


# ==========================================
# FAKE MONGODB COLLECTION
# ==========================================

class FakeCollection:

    def __init__(
        self
    ):

        self.documents = []


    # ======================================
    # FIND ONE
    # ======================================

    def find_one(
        self,
        query
    ):

        for document in self.documents:

            if self._matches(
                document,
                query
            ):

                return document.copy()

        return None


    # ======================================
    # INSERT ONE
    # ======================================

    def insert_one(
        self,
        document
    ):

        stored_document = (
            document.copy()
        )


        if "_id" not in stored_document:

            stored_document["_id"] = (
                ObjectId()
            )


        self.documents.append(
            stored_document
        )


        return FakeInsertResult(
            stored_document["_id"]
        )


    # ======================================
    # UPDATE ONE
    # ======================================

    def update_one(
        self,
        query,
        update
    ):

        for index, document in enumerate(
            self.documents
        ):

            if not self._matches(
                document,
                query
            ):

                continue


            set_values = update.get(
                "$set",
                {}
            )


            updated_document = (
                document.copy()
            )


            updated_document.update(
                set_values
            )


            self.documents[
                index
            ] = updated_document


            return FakeUpdateResult(
                matched_count=1
            )


        return FakeUpdateResult(
            matched_count=0
        )


    # ======================================
    # MATCH QUERY
    # ======================================

    @staticmethod
    def _matches(
        document,
        query
    ):

        for key, value in query.items():

            if document.get(
                key
            ) != value:

                return False


        return True


# ==========================================
# FAKE DATABASE
# ==========================================

class FakeDatabase:

    def __init__(
        self
    ):

        self.assets = FakeCollection()


# ==========================================
# ASSET SERVICE TESTS
# ==========================================

class TestAssetService(
    unittest.TestCase
):

    # ======================================
    # HELPER: BASE SCAN
    # ======================================

    def build_scan(
        self,
        target="127.0.0.1",
        created_by="user-1",
        status="completed",
        completed_at=None,
        risk_score=12,
        risk_level="LOW",
        hostname="localhost"
    ):

        if completed_at is None:

            completed_at = datetime(
                2026,
                8,
                31,
                12,
                0,
                tzinfo=timezone.utc
            )


        return {

            "_id": ObjectId(),

            "target": target,

            "scan_profile": "detailed",

            "status": status,

            "created_by": created_by,

            "created_at": (
                completed_at
                -
                timedelta(
                    minutes=2
                )
            ),

            "started_at": (
                completed_at
                -
                timedelta(
                    minutes=1
                )
            ),

            "completed_at": completed_at,

            "hostname": hostname,

            "host_status": "up",

            "mac_address": None,

            "ports": [

                {
                    "port": 135,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "msrpc",
                    "product": (
                        "Microsoft Windows RPC"
                    ),
                    "version": ""
                },

                {
                    "port": 445,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "microsoft-ds",
                    "product": "",
                    "version": ""
                },

                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "http",
                    "product": "",
                    "version": ""
                }

            ],

            "services": [

                {
                    "port": 135,
                    "name": "msrpc",
                    "product": (
                        "Microsoft Windows RPC"
                    ),
                    "version": ""
                },

                {
                    "port": 445,
                    "name": "microsoft-ds",
                    "product": "",
                    "version": ""
                }

            ],

            "os_detection": (
                "Microsoft Windows 11"
            ),

            "os_accuracy": 100,

            "vulnerabilities": [],

            "vulnerability_count": 0,

            "highest_severity": None,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "risk_breakdown": {

                "vulnerability_score": 0.0,

                "attack_surface_score": 11.5,

                "open_ports": [
                    135,
                    445
                ],

                "sensitive_ports": [
                    135,
                    445
                ]

            },

            "error_message": None
        }


    # ======================================
    # NORMALIZE LIST
    # ======================================

    def test_normalize_list_returns_list(
        self
    ):

        value = [
            1,
            2,
            3
        ]


        result = normalize_list(
            value
        )


        self.assertEqual(
            result,
            value
        )


    def test_normalize_list_invalid_becomes_empty(
        self
    ):

        result = normalize_list(
            None
        )


        self.assertEqual(
            result,
            []
        )


    # ======================================
    # OPEN PORT FILTER
    # ======================================

    def test_get_open_ports_only_returns_open(
        self
    ):

        ports = [

            {
                "port": 22,
                "state": "open"
            },

            {
                "port": 80,
                "state": "closed"
            },

            {
                "port": 443,
                "state": "open"
            }

        ]


        result = get_open_ports(
            ports
        )


        self.assertEqual(
            len(result),
            2
        )


        self.assertEqual(
            result[0]["port"],
            22
        )


        self.assertEqual(
            result[1]["port"],
            443
        )


    # ======================================
    # RISK LEVEL
    # ======================================

    def test_normalize_risk_level(
        self
    ):

        self.assertEqual(
            normalize_risk_level(
                "low"
            ),
            "LOW"
        )


        self.assertEqual(
            normalize_risk_level(
                "critical"
            ),
            "CRITICAL"
        )


        self.assertIsNone(
            normalize_risk_level(
                "invalid"
            )
        )


    # ======================================
    # SCAN TIMESTAMP
    # ======================================

    def test_scan_timestamp_prefers_completed_at(
        self
    ):

        completed_at = datetime(
            2026,
            8,
            31,
            10,
            0,
            tzinfo=timezone.utc
        )


        scan = self.build_scan(
            completed_at=completed_at
        )


        result = get_scan_timestamp(
            scan
        )


        self.assertEqual(
            result,
            completed_at
        )


    # ======================================
    # BUILD ASSET UPDATE
    # ======================================

    def test_build_asset_update_from_scan(
        self
    ):

        scan = self.build_scan()


        result = (
            build_asset_update_from_scan(
                scan
            )
        )


        self.assertEqual(
            result["target"],
            "127.0.0.1"
        )


        self.assertEqual(
            result["hostname"],
            "localhost"
        )


        self.assertEqual(
            result["open_port_count"],
            2
        )


        self.assertEqual(
            result["service_count"],
            2
        )


        self.assertEqual(
            result["risk_score"],
            12
        )


        self.assertEqual(
            result["risk_level"],
            "LOW"
        )


    # ======================================
    # COMPLETED SCAN CREATES ASSET
    # ======================================

    def test_completed_scan_creates_asset(
        self
    ):

        db = FakeDatabase()


        scan = self.build_scan()


        asset = upsert_asset_from_scan(

            db=db,

            scan=scan

        )


        self.assertIsNotNone(
            asset
        )


        self.assertEqual(
            len(
                db.assets.documents
            ),
            1
        )


        self.assertEqual(
            asset["target"],
            "127.0.0.1"
        )


    # ======================================
    # INCOMPLETE SCAN DOES NOT CREATE ASSET
    # ======================================

    def test_non_completed_scan_rejected(
        self
    ):

        db = FakeDatabase()


        scan = self.build_scan(
            status="failed"
        )


        asset = upsert_asset_from_scan(

            db=db,

            scan=scan

        )


        self.assertIsNone(
            asset
        )


        self.assertEqual(
            len(
                db.assets.documents
            ),
            0
        )


    # ======================================
    # SAME TARGET DOES NOT DUPLICATE
    # ======================================

    def test_same_owner_and_target_updates_asset(
        self
    ):

        db = FakeDatabase()


        first_scan = self.build_scan()


        second_scan = self.build_scan(

            completed_at=datetime(
                2026,
                8,
                31,
                13,
                0,
                tzinfo=timezone.utc
            ),

            risk_score=25,

            risk_level="MEDIUM"

        )


        upsert_asset_from_scan(

            db=db,

            scan=first_scan

        )


        upsert_asset_from_scan(

            db=db,

            scan=second_scan

        )


        self.assertEqual(
            len(
                db.assets.documents
            ),
            1
        )


        asset = (
            db.assets.documents[
                0
            ]
        )


        self.assertEqual(
            asset[
                "risk_score"
            ],
            25
        )


        self.assertEqual(
            asset[
                "risk_level"
            ],
            "MEDIUM"
        )


    # ======================================
    # NEWER SCAN UPDATES LAST SEEN
    # ======================================

    def test_newer_scan_updates_last_seen(
        self
    ):

        db = FakeDatabase()


        first_time = datetime(
            2026,
            8,
            27,
            10,
            0,
            tzinfo=timezone.utc
        )


        second_time = datetime(
            2026,
            8,
            31,
            10,
            0,
            tzinfo=timezone.utc
        )


        first_scan = self.build_scan(
            completed_at=first_time
        )


        second_scan = self.build_scan(
            completed_at=second_time
        )


        upsert_asset_from_scan(
            db,
            first_scan
        )


        asset = upsert_asset_from_scan(
            db,
            second_scan
        )


        self.assertEqual(
            asset[
                "first_seen"
            ],
            first_time
        )


        self.assertEqual(
            asset[
                "last_seen"
            ],
            second_time
        )


    # ======================================
    # OLD SCAN CANNOT REPLACE NEW STATE
    # ======================================

    def test_older_scan_does_not_overwrite_newer_asset(
        self
    ):

        db = FakeDatabase()


        newer_time = datetime(
            2026,
            8,
            31,
            15,
            0,
            tzinfo=timezone.utc
        )


        older_time = datetime(
            2026,
            8,
            27,
            15,
            0,
            tzinfo=timezone.utc
        )


        newer_scan = self.build_scan(

            completed_at=newer_time,

            risk_score=40,

            risk_level="MEDIUM",

            hostname="latest-host"

        )


        older_scan = self.build_scan(

            completed_at=older_time,

            risk_score=5,

            risk_level="LOW",

            hostname="old-host"

        )


        upsert_asset_from_scan(
            db,
            newer_scan
        )


        asset = upsert_asset_from_scan(
            db,
            older_scan
        )


        self.assertEqual(
            asset[
                "hostname"
            ],
            "latest-host"
        )


        self.assertEqual(
            asset[
                "risk_score"
            ],
            40
        )


        self.assertEqual(
            asset[
                "last_seen"
            ],
            newer_time
        )


        self.assertEqual(
            asset[
                "first_seen"
            ],
            older_time
        )


    # ======================================
    # MANUAL CONTEXT IS PRESERVED
    # ======================================

    def test_asset_context_survives_new_scan(
        self
    ):

        db = FakeDatabase()


        first_scan = self.build_scan(

            completed_at=datetime(
                2026,
                8,
                30,
                10,
                0,
                tzinfo=timezone.utc
            )

        )


        asset = upsert_asset_from_scan(

            db,
            first_scan

        )


        db.assets.update_one(

            {
                "_id": asset[
                    "_id"
                ]
            },

            {
                "$set": {

                    "criticality": "HIGH",

                    "exposure": "INTERNAL"
                }
            }

        )


        second_scan = self.build_scan(

            completed_at=datetime(
                2026,
                8,
                31,
                10,
                0,
                tzinfo=timezone.utc
            ),

            risk_score=25,

            risk_level="MEDIUM"

        )


        updated_asset = (
            upsert_asset_from_scan(

                db,

                second_scan

            )
        )


        self.assertEqual(
            updated_asset[
                "criticality"
            ],
            "HIGH"
        )


        self.assertEqual(
            updated_asset[
                "exposure"
            ],
            "INTERNAL"
        )


        self.assertEqual(
            updated_asset[
                "risk_score"
            ],
            25
        )


    # ======================================
    # SAME TARGET / DIFFERENT USER
    # ======================================

    def test_same_target_different_users_create_separate_assets(
        self
    ):

        db = FakeDatabase()


        first_scan = self.build_scan(
            created_by="user-1"
        )


        second_scan = self.build_scan(
            created_by="user-2"
        )


        upsert_asset_from_scan(
            db,
            first_scan
        )


        upsert_asset_from_scan(
            db,
            second_scan
        )


        self.assertEqual(
            len(
                db.assets.documents
            ),
            2
        )


    # ======================================
    # ASSET STATISTICS
    # ======================================

    def test_asset_statistics(
        self
    ):

        assets = [

            {
                "criticality": "CRITICAL",
                "risk_level": "HIGH",
                "vulnerability_count": 2,
                "open_port_count": 5
            },

            {
                "criticality": "NORMAL",
                "risk_level": "LOW",
                "vulnerability_count": 0,
                "open_port_count": 3
            }

        ]


        result = get_asset_statistics(
            assets
        )


        self.assertEqual(
            result[
                "total_assets"
            ],
            2
        )


        self.assertEqual(
            result[
                "critical_assets"
            ],
            1
        )


        self.assertEqual(
            result[
                "high_risk_assets"
            ],
            1
        )


        self.assertEqual(
            result[
                "vulnerable_assets"
            ],
            1
        )


        self.assertEqual(
            result[
                "total_open_ports"
            ],
            8
        )


        self.assertEqual(
            result[
                "total_vulnerabilities"
            ],
            2
        )


# ==========================================
# RUN TESTS
# ==========================================

if __name__ == "__main__":

    unittest.main()