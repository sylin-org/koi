"""Cross-language CSR conformance (skipped when `cryptography` is absent).

The TypeScript client generates PKCS#10 CSRs via node:crypto + hand-rolled DER
serialization. This test executes that exact generator (through node), then
verifies the result with an independent X.509 library: signature validity,
subject CN, and the P-256 SPKI algorithm. One keypair, three opinions.
"""

import json
import importlib.util
import os
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TS_DIR = REPO_ROOT / "packages" / "ts"


def node_available() -> bool:
    return shutil.which("node") is not None


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


@unittest.skipUnless(node_available(), "node is not installed")
@unittest.skipUnless(cryptography_available(), "cryptography is not installed")
class TestTsCsrCrossLanguage(unittest.IsolatedAsyncioTestCase):
    def test_generated_csr_verifies_with_cryptography(self):
        cryptography = __import__("cryptography")
        del cryptography
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        script = (
            "import('./lib/client.js').then((m) => {"
            "  const g = m.generateKeyPairAndCsr('cross-lang-agent');"
            "  process.stdout.write(JSON.stringify({ csr: g.csrPem }));"
            "})"
        )
        result = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            cwd=TS_DIR,
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "NODE_NO_WARNINGS": "1"},
        )
        csr_pem = json.loads(result.stdout)["csr"]

        csr = x509.load_pem_x509_csr(csr_pem.encode())
        # Signature verifies against the CSR's own embedded public key...
        csr.public_key().verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        self.assertTrue(csr.is_signature_valid)
        # ...the subject CN is exactly the requested hostname...
        subjects = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        self.assertEqual([a.value for a in subjects], ["cross-lang-agent"])
        # ...and the key is EC P-256 (Koi's pinned curve).
        self.assertIsInstance(csr.public_key(), ec.EllipticCurvePublicKey)
        self.assertEqual(csr.public_key().curve.name, "secp256r1")


if __name__ == "__main__":
    unittest.main()
