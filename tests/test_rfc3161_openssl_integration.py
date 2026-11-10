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
import time
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from experiments.rfc3161_timestamp import (
    _extract_signer_certificate_identity,
    trust_anchor_sha256,
    verify_rfc3161_timestamp,
)
from experiments.rfc3161_crl_status import verify_tsa_crl_evidence
from experiments.rfc3161_ocsp_status import verify_tsa_ocsp_evidence
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
                digital_signature=timestamp_signer or is_ca,
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

    def _verified_timestamp_result(self):
        return verify_rfc3161_timestamp(
            self.token_der, self.data, self.ca_pem, self.pin,
            intermediates_pem=self.tsa_pem,
            openssl_binary=self.openssl,
        )

    def _build_tsa_crl(
        self, *, revoked_at=None, signer_key=None, include_number=True,
        include_aki=True, delta=False, this_update=None, next_update=None,
        revocation_reason=None, duplicate_target_entry=False,
        crl_aki_issuer_serial=None,
    ):
        issuer = x509.load_pem_x509_certificate(self.ca_pem)
        now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
        this_update = this_update or (now - timedelta(days=1))
        next_update = next_update or (now + timedelta(days=1))
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer.subject)
            .last_update(this_update)
            .next_update(next_update)
        )
        if include_number:
            builder = builder.add_extension(x509.CRLNumber(7), critical=False)
        if include_aki:
            if crl_aki_issuer_serial is None:
                crl_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()
                )
            else:
                crl_aki = x509.AuthorityKeyIdentifier(
                    x509.SubjectKeyIdentifier.from_public_key(
                        self.ca_key.public_key()
                    ).digest,
                    [x509.DirectoryName(issuer.issuer)],
                    crl_aki_issuer_serial,
                )
            builder = builder.add_extension(crl_aki, critical=False)
        if delta:
            builder = builder.add_extension(
                x509.DeltaCRLIndicator(6), critical=True
            )
        if revoked_at is not None:
            tsa = x509.load_pem_x509_certificate(self.tsa_pem)
            revoked_builder = (
                x509.RevokedCertificateBuilder()
                .serial_number(tsa.serial_number)
                .revocation_date(revoked_at.replace(tzinfo=None))
            )
            if revocation_reason is not None:
                revoked_builder = revoked_builder.add_extension(
                    x509.CRLReason(revocation_reason), critical=False
                )
            revoked = revoked_builder.build()
            builder = builder.add_revoked_certificate(revoked)
            if duplicate_target_entry:
                builder = builder.add_revoked_certificate(revoked)
        crl = builder.sign(
            private_key=signer_key or self.ca_key,
            algorithm=hashes.SHA256(),
        )
        return crl.public_bytes(serialization.Encoding.DER)

    def test_complete_direct_crl_authenticates_but_absence_does_not_prove_non_revocation(self):
        timestamp_result = self._verified_timestamp_result()
        crl_der = self._build_tsa_crl()
        result = verify_tsa_crl_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, crl_der
        )
        self.assertEqual(
            result["crl_evidence_verification"],
            "VALID_RELATIVE_TO_BOUND_ISSUER_CERTIFICATE",
        )
        self.assertEqual(result["crl_signature"], "VALID")
        self.assertEqual(result["crl_scope"], "DIRECT_COMPLETE_ALL_REASONS_ONLY")
        self.assertEqual(result["crl_der_sha256"], hashlib.sha256(crl_der).hexdigest())
        self.assertTrue(result["crl_time_window_covers_target"])
        self.assertEqual(
            result["evidence_time_basis"],
            "ISSUER_ASSERTED_CRL_THIS_UPDATE_NEXT_UPDATE",
        )
        self.assertEqual(result["status_at_target_time"], "NOT_LISTED_AT_CRL_THIS_UPDATE")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")
        self.assertIn("NOT_PROOF_OF_HISTORICAL_NON_REVOCATION", result["absence_interpretation"])

    def test_signed_revocation_time_at_or_before_token_time_is_reported(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        crl_der = self._build_tsa_crl(
            revoked_at=target - timedelta(hours=1),
            this_update=(target - timedelta(minutes=30)).replace(tzinfo=None),
        )
        result = verify_tsa_crl_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, crl_der
        )
        self.assertEqual(result["status_at_target_time"], "REVOKED_AT_OR_BEFORE_TARGET")
        self.assertEqual(
            result["historical_revocation_assurance"],
            "REVOKED_BY_TARGET_TIME_UNDER_SIGNED_CRL_ASSERTION",
        )

    def test_crl_rejects_wrong_issuer_certificate_binding(self):
        timestamp_result = self._verified_timestamp_result()
        unrelated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        unrelated_cert = _certificate(
            self.ca_name, self.ca_name, unrelated_key.public_key(),
            unrelated_key, 9001, is_ca=True,
        )
        with self.assertRaisesRegex(ValueError, "do not match the prior timestamp identity"):
            verify_tsa_crl_evidence(
                timestamp_result,
                self.tsa_pem,
                unrelated_cert.public_bytes(serialization.Encoding.PEM),
                self._build_tsa_crl(),
            )

    def test_crl_rejects_invalid_signature_even_when_issuer_name_matches(self):
        timestamp_result = self._verified_timestamp_result()
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaisesRegex(ValueError, "signature does not verify"):
            verify_tsa_crl_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem,
                self._build_tsa_crl(signer_key=wrong_key),
            )

    def test_crl_requires_number_and_authority_key_identifier(self):
        timestamp_result = self._verified_timestamp_result()
        with self.assertRaisesRegex(ValueError, "CRLNumber"):
            verify_tsa_crl_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem,
                self._build_tsa_crl(include_number=False),
            )
        with self.assertRaisesRegex(ValueError, "Authority Key Identifier"):
            verify_tsa_crl_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem,
                self._build_tsa_crl(include_aki=False),
            )

    def test_duplicate_tsa_serial_entries_are_rejected(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        crl_der = self._build_tsa_crl(
            revoked_at=target - timedelta(hours=1),
            this_update=(target - timedelta(minutes=30)).replace(tzinfo=None),
            duplicate_target_entry=True,
        )
        with self.assertRaisesRegex(ValueError, "duplicate entries"):
            verify_tsa_crl_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, crl_der
            )

    def test_certificate_hold_does_not_become_permanent_historical_revocation(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        crl_der = self._build_tsa_crl(
            revoked_at=target - timedelta(hours=1),
            this_update=(target - timedelta(minutes=30)).replace(tzinfo=None),
            revocation_reason=x509.ReasonFlags.certificate_hold,
        )
        result = verify_tsa_crl_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, crl_der
        )
        self.assertEqual(
            result["status_at_target_time"],
            "CERTIFICATE_HOLD_REPORTED_TARGET_STATUS_NOT_ESTABLISHED",
        )
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def test_remove_from_crl_reason_is_rejected_without_delta_support(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        crl_der = self._build_tsa_crl(
            revoked_at=target - timedelta(hours=1),
            this_update=(target - timedelta(minutes=30)).replace(tzinfo=None),
            revocation_reason=x509.ReasonFlags.remove_from_crl,
        )
        with self.assertRaisesRegex(ValueError, "removeFromCRL is unsupported"):
            verify_tsa_crl_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, crl_der
            )

    def test_crl_aki_issuer_serial_must_match_bound_issuer_certificate(self):
        timestamp_result = self._verified_timestamp_result()
        issuer = x509.load_pem_x509_certificate(self.ca_pem)
        crl_der = self._build_tsa_crl(
            crl_aki_issuer_serial=issuer.serial_number + 1
        )
        with self.assertRaisesRegex(ValueError, "issuer/serial does not match"):
            verify_tsa_crl_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, crl_der
            )

    def test_delta_crl_is_rejected_by_narrow_complete_crl_profile(self):
        timestamp_result = self._verified_timestamp_result()
        with self.assertRaisesRegex(ValueError, "delta or freshest-CRL"):
            verify_tsa_crl_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem,
                self._build_tsa_crl(delta=True),
            )

    def test_crl_revocation_after_token_time_is_not_backdated(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        crl_der = self._build_tsa_crl(
            revoked_at=(target + timedelta(hours=1)),
            this_update=(target + timedelta(hours=2)).replace(tzinfo=None),
        )
        result = verify_tsa_crl_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, crl_der
        )
        self.assertEqual(result["status_at_target_time"], "REVOCATION_AFTER_TARGET_REPORTED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def test_stale_unlisted_crl_is_not_assessed(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        crl_der = self._build_tsa_crl(
            this_update=(target - timedelta(days=2)).replace(tzinfo=None),
            next_update=(target - timedelta(days=1)).replace(tzinfo=None),
        )
        result = verify_tsa_crl_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, crl_der
        )
        self.assertEqual(result["status_at_target_time"], "NOT_ESTABLISHED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def test_unlisted_certificate_outside_crl_interval_is_not_assessed(self):
        timestamp_result = self._verified_timestamp_result()
        now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
        crl_der = self._build_tsa_crl(
            this_update=now + timedelta(days=1),
            next_update=now + timedelta(days=2),
        )
        result = verify_tsa_crl_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, crl_der
        )
        self.assertEqual(result["status_at_target_time"], "NOT_ESTABLISHED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def _build_tsa_ocsp_request(self, nonce=None, cert=None):
        issuer = x509.load_pem_x509_certificate(self.ca_pem)
        tsa = cert or x509.load_pem_x509_certificate(self.tsa_pem)
        builder = ocsp.OCSPRequestBuilder().add_certificate(
            tsa, issuer, hashes.SHA256()
        )
        if nonce is not None:
            builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
        return builder.build().public_bytes(serialization.Encoding.DER)

    def _build_tsa_ocsp_response(
        self, *, status=ocsp.OCSPCertStatus.GOOD, revocation_time=None,
        revocation_reason=None, nonce=None, cert=None, signer_key=None,
        responder_cert=None, responder_encoding=ocsp.OCSPResponderEncoding.NAME,
        included_certificates=None, this_update=None, next_update=None,
        omit_next_update=False, extra_response_extension=None,
    ):
        issuer = x509.load_pem_x509_certificate(self.ca_pem)
        tsa = cert or x509.load_pem_x509_certificate(self.tsa_pem)
        now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
        this_update = this_update or (now - timedelta(days=1))
        if not omit_next_update:
            next_update = next_update or (now + timedelta(days=1))
        else:
            next_update = None
        responder_cert = responder_cert or issuer
        builder = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=tsa,
                issuer=issuer,
                algorithm=hashes.SHA256(),
                cert_status=status,
                this_update=this_update,
                next_update=next_update,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason,
            )
            .responder_id(responder_encoding, responder_cert)
        )
        if nonce is not None:
            builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
        if extra_response_extension is not None:
            builder = builder.add_extension(extra_response_extension, critical=False)
        if included_certificates is not None:
            builder = builder.certificates(included_certificates)
        response = builder.sign(
            private_key=signer_key or self.ca_key,
            algorithm=hashes.SHA256(),
        )
        return response.public_bytes(serialization.Encoding.DER)

    def test_issuer_signed_ocsp_good_is_not_historical_non_revocation_proof(self):
        timestamp_result = self._verified_timestamp_result()
        response_der = self._build_tsa_ocsp_response()
        result = verify_tsa_ocsp_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, response_der
        )
        self.assertEqual(result["ocsp_evidence_verification"], "VALID_RELATIVE_TO_BOUND_ISSUER_CERTIFICATE")
        self.assertEqual(result["ocsp_signature"], "VALID")
        self.assertEqual(result["responder_authorization"], "ISSUING_CA_DIRECTLY_SIGNED")
        self.assertEqual(result["ocsp_cert_id_binding"], "MATCH")
        self.assertEqual(result["status_at_evidence_time"], "GOOD")
        self.assertEqual(result["status_at_target_time"], "GOOD_AT_OCSP_THIS_UPDATE_ONLY")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")
        self.assertEqual(
            result["good_status_limitation"],
            "OCSP_GOOD_AT_THIS_UPDATE_DOES_NOT_ESTABLISH_HISTORICAL_NON_REVOCATION",
        )

    def test_issuer_signed_ocsp_revocation_before_token_time_is_reported(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        response_der = self._build_tsa_ocsp_response(
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=(target - timedelta(hours=1)).replace(tzinfo=None),
            revocation_reason=x509.ReasonFlags.key_compromise,
            this_update=(target - timedelta(minutes=30)).replace(tzinfo=None),
        )
        result = verify_tsa_ocsp_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, response_der
        )
        self.assertEqual(result["status_at_target_time"], "REVOKED_AT_OR_BEFORE_TARGET")
        self.assertEqual(
            result["historical_revocation_assurance"],
            "REVOKED_BY_TARGET_TIME_UNDER_SIGNED_OCSP_ASSERTION",
        )

    def test_ocsp_certificate_hold_remains_historically_indeterminate(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        response_der = self._build_tsa_ocsp_response(
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=(target - timedelta(hours=1)).replace(tzinfo=None),
            revocation_reason=x509.ReasonFlags.certificate_hold,
            this_update=(target - timedelta(minutes=30)).replace(tzinfo=None),
        )
        result = verify_tsa_ocsp_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, response_der
        )
        self.assertEqual(
            result["status_at_target_time"],
            "CERTIFICATE_HOLD_REPORTED_TARGET_STATUS_NOT_ESTABLISHED",
        )
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def test_ocsp_unknown_status_is_not_promoted_to_good(self):
        timestamp_result = self._verified_timestamp_result()
        response_der = self._build_tsa_ocsp_response(
            status=ocsp.OCSPCertStatus.UNKNOWN
        )
        result = verify_tsa_ocsp_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, response_der
        )
        self.assertEqual(result["status_at_target_time"], "UNKNOWN")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def test_ocsp_cert_id_must_match_exact_tsa_certificate(self):
        timestamp_result = self._verified_timestamp_result()
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_tsa = _certificate(
            self.ca_name, self.ca_name, other_key.public_key(),
            self.ca_key, 9101, is_ca=False,
        )
        response_der = self._build_tsa_ocsp_response(cert=other_tsa)
        with self.assertRaisesRegex(ValueError, "CertID does not identify"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

    def test_ocsp_response_signature_must_verify_under_bound_issuer(self):
        timestamp_result = self._verified_timestamp_result()
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_issuer = _certificate(
            self.ca_name, self.ca_name, wrong_key.public_key(),
            wrong_key, 9102, is_ca=True,
        )
        response_der = self._build_tsa_ocsp_response(
            signer_key=wrong_key, responder_cert=wrong_issuer
        )
        with self.assertRaisesRegex(ValueError, "signature does not verify"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

    def test_ocsp_future_dated_status_interval_is_rejected(self):
        timestamp_result = self._verified_timestamp_result()
        now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
        response_der = self._build_tsa_ocsp_response(
            this_update=now + timedelta(days=1),
            next_update=now + timedelta(days=2),
        )
        with self.assertRaisesRegex(ValueError, "producedAt must fall within"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

    def test_ocsp_stale_status_interval_is_rejected(self):
        timestamp_result = self._verified_timestamp_result()
        now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
        response_der = self._build_tsa_ocsp_response(
            this_update=now - timedelta(days=2),
            next_update=now - timedelta(days=1),
        )
        with self.assertRaisesRegex(ValueError, "producedAt must fall within"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

    def test_ocsp_requires_next_update(self):
        timestamp_result = self._verified_timestamp_result()
        response_der = self._build_tsa_ocsp_response(omit_next_update=True)
        with self.assertRaisesRegex(ValueError, "increasing thisUpdate/nextUpdate"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

    def test_ocsp_unknown_response_extension_is_rejected(self):
        timestamp_result = self._verified_timestamp_result()
        unknown = x509.UnrecognizedExtension(
            ObjectIdentifier("1.2.3.4.5.6"), b"\\x05\\x00"
        )
        response_der = self._build_tsa_ocsp_response(
            extra_response_extension=unknown
        )
        with self.assertRaisesRegex(ValueError, "unsupported extension"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

    def test_ocsp_revocation_after_token_time_is_not_backdated(self):
        timestamp_result = self._verified_timestamp_result()
        target = datetime.fromisoformat(
            timestamp_result["tsa_asserted_gen_time_utc"].replace("Z", "+00:00")
        )
        time.sleep(2)
        response_der = self._build_tsa_ocsp_response(
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=(target + timedelta(seconds=1)).replace(tzinfo=None),
            revocation_reason=x509.ReasonFlags.key_compromise,
            this_update=(target + timedelta(seconds=1)).replace(tzinfo=None),
            next_update=(target + timedelta(days=1)).replace(tzinfo=None),
        )
        result = verify_tsa_ocsp_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem, response_der
        )
        self.assertEqual(result["status_at_target_time"], "REVOCATION_AFTER_TARGET_REPORTED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    def test_ocsp_nonce_must_match_the_supplied_request(self):
        timestamp_result = self._verified_timestamp_result()
        request_der = self._build_tsa_ocsp_request(nonce=b"nonce-A")
        response_der = self._build_tsa_ocsp_response(nonce=b"nonce-A")
        result = verify_tsa_ocsp_evidence(
            timestamp_result, self.tsa_pem, self.ca_pem,
            response_der, request_der,
        )
        self.assertEqual(result["nonce_binding"], "MATCH")
        mismatched_response = self._build_tsa_ocsp_response(nonce=b"nonce-B")
        with self.assertRaisesRegex(ValueError, "nonce does not match"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem,
                mismatched_response, request_der,
            )

    def test_ocsp_nonce_without_request_is_rejected(self):
        timestamp_result = self._verified_timestamp_result()
        response_der = self._build_tsa_ocsp_response(nonce=b"unsolicited")
        with self.assertRaisesRegex(ValueError, "cannot be matched without a request"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

    def test_delegated_ocsp_responder_is_rejected_by_initial_profile(self):
        timestamp_result = self._verified_timestamp_result()
        delegate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer = x509.load_pem_x509_certificate(self.ca_pem)
        delegate = _certificate(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic OCSP Delegate")]),
            issuer.subject,
            delegate_key.public_key(),
            self.ca_key,
            9103,
            is_ca=False,
        )
        response_der = self._build_tsa_ocsp_response(
            signer_key=delegate_key,
            responder_cert=delegate,
            responder_encoding=ocsp.OCSPResponderEncoding.HASH,
            included_certificates=[delegate],
        )
        with self.assertRaisesRegex(ValueError, "delegated OCSP responder certificates are unsupported"):
            verify_tsa_ocsp_evidence(
                timestamp_result, self.tsa_pem, self.ca_pem, response_der
            )

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
