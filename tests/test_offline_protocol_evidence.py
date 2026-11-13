"""Tests for evidence metadata validation, not AOW wire compatibility."""
import unittest

from server.offline_protocol_evidence import (
    ALLOWED_KINDS, EvidenceError, validate_record, validate_manifest,
)
from server.protocol_evidence_registry import ALLOWED_TOPICS, VERIFIED_METHODS, VERIFIED_METHODS


def sample(**changes):
    record = {
        "id": "offline-test-001",
        "kind": "framing",
        "status": "unverified",
        "artifact_sha256": "a" * 64,
        "method": "Authorized local offline inspection",
        "reproduction": "Run isolated local fixture tests",
        "test_reference": "tests/test_offline_protocol_evidence.py",
        "notes": "Synthetic metadata only; no packet assertion",
    }
    record.update(changes)
    return record


class EvidenceManifestTests(unittest.TestCase):
    def test_manifest_and_gate_topics_share_one_allowlist(self):
        self.assertIs(ALLOWED_KINDS, ALLOWED_TOPICS)
        self.assertIn("player", ALLOWED_KINDS)
        self.assertIn("map", ALLOWED_KINDS)
        self.assertIn("serialization", ALLOWED_KINDS)

    def test_manifest_and_registry_share_verified_method_allowlist(self):
        self.assertEqual(
            VERIFIED_METHODS,
            frozenset({
                "apk_zip_inventory", "jadx_offline", "il2cpp_offline",
                "authorized_local_test",
            }),
        )

    def test_accepts_synthetic_unverified_metadata(self):
        self.assertEqual(validate_record(sample())["status"], "unverified")

    def test_accepts_unverified_primitive_serialization_metadata(self):
        item = validate_record(sample(kind="serialization"))
        self.assertEqual(item["kind"], "serialization")
        self.assertEqual(item["status"], "unverified")

    def test_rejects_raw_capture_field(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(packet_bytes="deadbeef"))

    def test_rejects_invalid_hash(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(artifact_sha256="not-a-sha"))

    def test_rejects_unknown_kind(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(kind="invented_opcode"))

    def test_rejects_unapproved_method_for_verified_record(self):
        for method in ("web_search", "synthetic_test", "guess", "Authorized local offline inspection"):
            with self.subTest(method=method), self.assertRaisesRegex(
                EvidenceError, "approved offline or authorized method"
            ):
                validate_record(sample(status="verified", method=method))

    def test_accepts_only_allowlisted_methods_for_verified_records(self):
        for method in VERIFIED_METHODS:
            with self.subTest(method=method):
                item = validate_record(sample(
                    status="verified",
                    method=method,
                ))
                self.assertEqual(item["status"], "verified")
                self.assertEqual(item["method"], method)

    def test_rejects_missing_reproduction_for_verified(self):
        with self.assertRaisesRegex(EvidenceError, "reproduction instructions"):
            validate_record(sample(
                status="verified",
                method="authorized_local_test",
                reproduction="pending",
            ))

    def test_rejects_missing_test_for_verified(self):
        with self.assertRaisesRegex(EvidenceError, "reproducible test reference"):
            validate_record(sample(
                status="verified",
                method="authorized_local_test",
                test_reference="n/a",
            ))

    def test_rejects_duplicate_identifiers(self):
        with self.assertRaises(EvidenceError):
            validate_manifest([sample(), sample(kind="login")])

    def test_rejects_control_characters(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(notes="unsafe\\nmetadata".replace("\\n", "\n")))

    def test_rejects_invisible_unicode_metadata(self):
        for invisible in ("\\u200b", "\\u202e", "\\u2060"):
            with self.subTest(invisible=repr(invisible)):
                with self.assertRaises(EvidenceError):
                    validate_record(sample(notes="safe" + invisible + "text"))

    def test_manifest_does_not_mutate_input(self):
        original = sample(notes="  local-only  ")
        result = validate_manifest([original])
        self.assertEqual(original["notes"], "  local-only  ")
        self.assertEqual(result[0]["notes"], "local-only")

    def test_rejects_urls_in_every_free_text_field(self):
        for field in ("method", "reproduction", "test_reference", "notes"):
            with self.subTest(field=field):
                with self.assertRaises(EvidenceError):
                    validate_record(sample(**{
                        field: "review https://example.invalid/private?q=token"
                    }))

    def test_rejects_ipv4_endpoints_in_free_text(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(notes="observed endpoint 192.0.2.10"))

    def test_rejects_credential_assignments(self):
        for value in ("token=abc123", "password:secret", "api_key=xyz",
                      "Authorization:Bearer abc123"):
            with self.subTest(value=value):
                with self.assertRaises(EvidenceError):
                    validate_record(sample(notes=value))

    def test_rejects_bearer_values_and_raw_byte_markers(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(notes="Bearer abcdefghijklmnop"))
        with self.assertRaises(EvidenceError):
            validate_record(sample(notes="packet_bytes=00112233"))

    def test_rejects_private_key_pem_marker(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(notes="-----BEGIN PRIVATE KEY-----"))

    def test_accepts_redacted_provenance_without_endpoint_values(self):
        item = validate_record(sample(
            method="Authorized local offline inspection",
            reproduction="Replay synthetic fixture; endpoint redacted",
            notes="Credentials and endpoint values omitted",
        ))
        self.assertEqual(item["status"], "unverified")

    def test_rejects_non_http_uri_schemes(self):
        examples = (
            "ftp://capture.example.invalid/trace",
            "file:///private/capture.pcap",
            "wss://capture.example.invalid/socket",
        )
        for value in examples:
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                validate_record(sample(notes=value))

    def test_rejects_dns_hostnames_and_host_ports(self):
        examples = (
            "capture.example.invalid",
            "capture.example.invalid:443",
            "private-host.internal",
            "localhost:8765",
        )
        for value in examples:
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                validate_record(sample(notes=value))

    def test_rejects_ipv6_literals(self):
        for value in ("2001:db8::1", "[2001:db8::1]:443", "::1"):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                validate_record(sample(notes=value))

    def test_allows_local_repository_file_references(self):
        for value in (
            "tests/test_offline_protocol_evidence.py",
            "docs/PROTOCOL.md",
            "server/offline_protocol_evidence.py",
        ):
            with self.subTest(value=value):
                item = validate_record(sample(test_reference=value))
                self.assertEqual(item["test_reference"], value)


if __name__ == "__main__":
    unittest.main()
