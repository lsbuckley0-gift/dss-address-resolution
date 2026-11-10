"""End-to-end RFC 3161 checks using an ephemeral synthetic TSA hierarchy.

The generated CA and TSA keys/certificates exist only in a temporary directory.
This is cryptographic plumbing coverage, not evidence of an operational authority.
"""
from datetime import datetime
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from experiments.rfc3161_timestamp import trust_anchor_sha256, verify_rfc3161_timestamp


def _certificate(subject, issuer, public_key, signer_key, serial, *, is_ca, timestamp_signer=False):
    now = datetime(2026, 1, 1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(datetime(2036, 1, 1))
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
        tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic DSS Test Root")])
        tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic DSS Test TSA")])
        ca_cert = _certificate(ca_name, ca_name, ca_key.public_key(), ca_key, 1001, is_ca=True)
        tsa_cert = _certificate(
            tsa_name, ca_name, tsa_key.public_key(), ca_key, 1002,
            is_ca=False, timestamp_signer=True,
        )
        self.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        tsa_pem = tsa_cert.public_bytes(serialization.Encoding.PEM)
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
