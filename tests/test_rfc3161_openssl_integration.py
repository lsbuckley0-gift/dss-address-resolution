"""End-to-end RFC 3161 checks using an ephemeral synthetic TSA hierarchy.

The generated CA and TSA keys/certificates exist only in a temporary directory.
This is cryptographic plumbing coverage, not evidence of an operational authority.
"""
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from experiments.rfc3161_timestamp import (
    _extract_signer_certificate_identity,
    trust_anchor_sha256,
    verify_rfc3161_timestamp,
)
from experiments.rfc3161_anchor_provenance import (
    canonical_provenance_payload,
    verify_rfc3161_timestamp_with_provenance,
)


def _certificate(subject, issuer, public_key, signer_key, serial, *, is_ca, timestamp_signer=False):
    now = datetime(2020, 1, 1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(datetime(2040, 1, 1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=timestamp_signer,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    if timestamp_signer:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
    if is_ca:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()),
            critical=False,
        )
    return builder.sign(signer_key, hashes.SHA256())


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable is required")
class RFC3161OpenSSLIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dss-rfc3161-integration-")
        self.root = Path(self.temp.name)
        self.openssl = shutil.which("openssl")
        self.data = b"synthetic canonical checkpoint payload for timestamp test"
        self.data_path = self.root / "payload.bin"
        self.data_path.write_bytes(self.data)

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_key = ca_key
        tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic DSS Test Root")])
        self.ca_name = ca_name
        tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic DSS Test TSA")])
        ca_cert = _certificate(ca_name, ca_name, ca_key.public_key(), ca_key, 1001, is_ca=True)
        tsa_cert = _certificate(
            tsa_name, ca_name, tsa_key.public_key(), ca_key, 1002,
            is_ca=False, timestamp_signer=True,
        )
        self.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        self.tsa_pem = tsa_cert.public_bytes(serialization.Encoding.PEM)
        tsa_pem = self.tsa_pem
        tsa_key_pem = tsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        (self.root / "ca.pem").write_bytes(self.ca_pem)
        (self.root / "tsa.pem").write_bytes(tsa_pem)
        (self.root / "tsa.key").write_bytes(tsa_key_pem)
        (self.root / "serial").write_text("01\n", encoding="ascii")
        config = f"""[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
serial = {self.root / 'serial'}
signer_cert = {self.root / 'tsa.pem'}
certs = {self.root / 'tsa.pem'}
signer_key = {self.root / 'tsa.key'}
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
"""
        (self.root / "tsa.cnf").write_text(config, encoding="utf-8")
        request = self.root / "request.tsq"
        response = self.root / "response.tsr"
        token = self.root / "token.der"
        self._run([self.openssl, "ts", "-query", "-data", str(self.data_path), "-sha256", "-cert", "-out", str(request)])
        self._run([self.openssl, "ts", "-reply", "-config", str(self.root / "tsa.cnf"), "-queryfile", str(request), "-out", str(response)])
        self._run([self.openssl, "ts", "-reply", "-in", str(response), "-token_out", "-out", str(token)])
        self.token_der = token.read_bytes()

        request_without_cert = self.root / "request-without-cert.tsq"
        response_without_cert = self.root / "response-without-cert.tsr"
        token_without_cert = self.root / "token-without-cert.der"
        self._run([
            self.openssl, "ts", "-query", "-data", str(self.data_path),
            "-sha256", "-out", str(request_without_cert),
        ])
        self._run([
            self.openssl, "ts", "-reply", "-config", str(self.root / "tsa.cnf"),
            "-queryfile", str(request_without_cert), "-out", str(response_without_cert),
        ])
        self._run([
            self.openssl, "ts", "-reply", "-in", str(response_without_cert),
            "-token_out", "-out", str(token_without_cert),
        ])
        self.token_without_embedded_signer_der = token_without_cert.read_bytes()
        self.pin = {
            "sha256": trust_anchor_sha256(self.ca_pem),
            "source_reference": "synthetic-test-only://ephemeral-root",
        }

    def tearDown(self):
        self.temp.cleanup()

    def _run(self, command):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            self.fail("Synthetic OpenSSL fixture setup failed: " + result.stderr)

    def test_openssl_cms_extracts_the_verified_timestamp_signer_certificate(self):
        signer_path = self.root / "extracted-signer.pem"
        content_path = self.root / "extracted-tst-info.der"
        result = subprocess.run(
            [
                self.openssl, "cms", "-verify", "-binary", "-inform", "DER",
                "-in", str(self.root / "token.der"), "-noverify",
                "-signer", str(signer_path), "-out", str(content_path),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        extracted = x509.load_pem_x509_certificate(signer_path.read_bytes())
        expected = x509.load_pem_x509_certificate(self.tsa_pem)
        self.assertEqual(
            extracted.fingerprint(hashes.SHA256()),
            expected.fingerprint(hashes.SHA256()),
        )
        self.assertTrue(content_path.read_bytes())

    def test_real_token_signature_imprint_purpose_and_chain_verify(self):
        result = verify_rfc3161_timestamp(
            self.token_der, self.data, self.ca_pem, self.pin,
            intermediates_pem=(self.root / "tsa.pem").read_bytes(),
            openssl_binary=self.openssl,
        )
        self.assertEqual(result["timestamp_verification"], "VALID", result)
        self.assertEqual(result["message_imprint"], "MATCH")
        self.assertEqual(result["timestamp_authentication"], "CRYPTOGRAPHICALLY_VALID_RELATIVE_TO_CALLER_ANCHOR")
        self.assertEqual(result["anchor_provenance"], "NOT_ESTABLISHED")
        self.assertEqual(result["tsa_certificate_revocation"], "NOT_CHECKED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")
        self.assertEqual(result["tsa_signer_certificate_identity"], "EXTRACTED")
        extracted_identity = result["tsa_signer_certificate"]
        tsa_certificate = x509.load_pem_x509_certificate(self.tsa_pem)
        self.assertEqual(
            extracted_identity["certificate_der_sha256"],
            hashlib.sha256(
                tsa_certificate.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        )
        self.assertEqual(
            extracted_identity["issuer_name_der_sha256"],
            hashlib.sha256(tsa_certificate.issuer.public_bytes()).hexdigest(),
        )
        self.assertEqual(
            extracted_identity["subject_spki_sha256"],
            hashlib.sha256(
                tsa_certificate.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest(),
        )
        issuer_certificate = x509.load_pem_x509_certificate(self.ca_pem)
        issuer_spki = issuer_certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(
            extracted_identity["issuer_certificate_der_sha256"],
            hashlib.sha256(
                issuer_certificate.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        )
        self.assertEqual(
            extracted_identity["issuer_spki_sha256"],
            hashlib.sha256(issuer_spki).hexdigest(),
        )
        self.assertEqual(
            extracted_identity["serial_hex"],
            format(tsa_certificate.serial_number, "x"),
        )

    def test_signer_identity_can_be_resolved_from_supplied_untrusted_certificates(self):
        result = verify_rfc3161_timestamp(
            self.token_without_embedded_signer_der,
            self.data,
            self.ca_pem,
            self.pin,
            intermediates_pem=self.tsa_pem,
            openssl_binary=self.openssl,
        )
        self.assertEqual(result["timestamp_verification"], "VALID", result)
        self.assertEqual(result["tsa_signer_certificate_identity"], "EXTRACTED")
        expected = x509.load_pem_x509_certificate(self.tsa_pem)
        self.assertEqual(
            result["tsa_signer_certificate"]["certificate_der_sha256"],
            hashlib.sha256(
                expected.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        )

    def test_signer_issuer_selection_uses_authority_key_identifier(self):
        unrelated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        unrelated_ca = _certificate(
            self.ca_name, self.ca_name, unrelated_key.public_key(),
            unrelated_key, 1003, is_ca=True,
        )
        unrelated_pem = unrelated_ca.public_bytes(serialization.Encoding.PEM)
        identity = _extract_signer_certificate_identity(
            self.root / "token.der",
            self.root,
            self.openssl,
            10,
            self.ca_pem + unrelated_pem,
        )
        expected_issuer = x509.load_pem_x509_certificate(self.ca_pem)
        self.assertEqual(
            identity["issuer_certificate_der_sha256"],
            hashlib.sha256(
                expected_issuer.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        )

    def test_signer_issuer_selection_rejects_ambiguous_same_key_certificates(self):
        alternate_issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alternate_issuer_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Alternate Issuer")
        ])
        duplicate_subject_key = _certificate(
            self.ca_name, alternate_issuer_name, self.ca_key.public_key(),
            alternate_issuer_key, 1004, is_ca=True,
        )
        duplicate_pem = duplicate_subject_key.public_bytes(serialization.Encoding.PEM)
        with self.assertRaisesRegex(ValueError, "could not be identified uniquely"):
            _extract_signer_certificate_identity(
                self.root / "token.der",
                self.root,
                self.openssl,
                10,
                self.ca_pem + duplicate_pem,
            )

    def test_signer_extraction_failure_does_not_upgrade_revocation_or_invalidate_token(self):
        from unittest.mock import patch

        with patch(
            "experiments.rfc3161_timestamp._extract_signer_certificate_identity",
            side_effect=ValueError("synthetic extraction failure"),
        ):
            result = verify_rfc3161_timestamp(
                self.token_der, self.data, self.ca_pem, self.pin,
                intermediates_pem=self.tsa_pem,
                openssl_binary=self.openssl,
            )
        self.assertEqual(result["timestamp_verification"], "VALID", result)
        self.assertEqual(result["tsa_signer_certificate_identity"], "NOT_EXTRACTED")
        self.assertIsNone(result["tsa_signer_certificate"])
        self.assertEqual(
            result["tsa_signer_certificate_identity_error"],
            "synthetic extraction failure",
        )
        self.assertEqual(result["tsa_certificate_revocation"], "NOT_CHECKED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def test_real_token_verifies_after_ephemeral_anchor_provenance(self):
        governance_private = Ed25519PrivateKey.generate()
        governance_public = governance_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        governance_store = {
            "record_version": "audit-trust-store/v1",
            "keys": [{
                "key_id": "synthetic-integration-governance",
                "authority_name": "Synthetic integration authority",
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(governance_public).decode("ascii"),
                "purposes": ["RFC3161_TRUST_ANCHOR_PROVENANCE"],
                "valid_from_utc": "2020-01-01T00:00:00Z",
                "valid_until_utc": "2040-01-01T00:00:00Z",
                "status": "ACTIVE",
                "trust_basis_reference": "ephemeral integration fixture",
            }],
        }
        now = datetime.now(timezone.utc).replace(microsecond=0)
        at_utc = now.isoformat().replace("+00:00", "Z")
        attestation = {
            "record_version": "rfc3161-tsa-anchor-provenance/v1",
            "attestation_id": "ephemeral-openssl-integration",
            "authority_name": "Synthetic integration authority",
            "anchor_sha256": hashlib.sha256(self.ca_pem).hexdigest(),
            "intended_usage": "RFC3161_TSA_TRUST_ANCHOR",
            "policy_version": "rfc3161-tsa-anchor-policy/v1",
            "sequence": 1,
            "issued_at_utc": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            "expires_at_utc": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
            "source_reference": "ephemeral integration fixture only",
        }
        signature = governance_private.sign(canonical_provenance_payload(attestation))
        envelope = {
            "record_version": "rfc3161-tsa-anchor-provenance-signature/v1",
            "key_id": "synthetic-integration-governance",
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
        result = verify_rfc3161_timestamp_with_provenance(
            self.token_der,
            self.data,
            self.ca_pem,
            self.pin,
            attestation,
            envelope,
            governance_store,
            at_utc=at_utc,
            minimum_sequence=1,
            intermediates_pem=(self.root / "tsa.pem").read_bytes(),
            openssl_binary=self.openssl,
        )
        self.assertEqual(result["combined_verification"], "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE", result)
        self.assertEqual(
            result["anchor_provenance"]["provenance_verification"],
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE",
        )
        self.assertEqual(result["timestamp_evidence"]["timestamp_verification"], "VALID")
        self.assertEqual(result["timestamp_evidence"]["message_imprint"], "MATCH")
        self.assertEqual(result["timestamp_evidence"]["tsa_certificate_revocation"], "NOT_CHECKED")
        self.assertEqual(result["timestamp_evidence"]["historical_revocation_assurance"], "NOT_ESTABLISHED")
        self.assertEqual(result["governance_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(result["event_truth"], "NOT_ESTABLISHED")

    def test_real_token_rejects_changed_payload(self):
        result = verify_rfc3161_timestamp(
            self.token_der, self.data + b"tampered", self.ca_pem, self.pin,
            intermediates_pem=(self.root / "tsa.pem").read_bytes(),
            openssl_binary=self.openssl,
        )
        self.assertEqual(result["timestamp_verification"], "INVALID", result)
        self.assertEqual(result["message_imprint"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
