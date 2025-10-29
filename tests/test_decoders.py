import unittest

from analyzers.ctf.ctf_analyzer import EncodingDecoder
from features.cryptanalysis_suite import ModernCryptoAnalyzer

# Helper: simple Base45 encoder for test vectors (RFC 9285-compliant)
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

def base45_encode(data: bytes) -> str:
    out = []
    i = 0
    while i < len(data):
        if i + 1 < len(data):
            x = data[i] * 256 + data[i+1]
            c0 = x % 45
            c1 = (x // 45) % 45
            c2 = (x // (45 * 45))
            out.append(ALPHABET[c0])
            out.append(ALPHABET[c1])
            out.append(ALPHABET[c2])
            i += 2
        else:
            x = data[i]
            c0 = x % 45
            c1 = x // 45
            out.append(ALPHABET[c0])
            out.append(ALPHABET[c1])
            i += 1
    return ''.join(out)

class TestDecoders(unittest.TestCase):
    def test_base45_known_vector(self):
        dec = EncodingDecoder()
        # RFC example: "BB8" -> "AB"
        self.assertEqual(dec.decode_base45("BB8"), "AB")

    def test_base45_roundtrip(self):
        dec = EncodingDecoder()
        original = b"ABCDE"  # odd length to test 2-char tail
        encoded = base45_encode(original)
        decoded = dec.decode_base45(encoded)
        self.assertEqual(decoded, original.decode('utf-8'))

    def test_repeating_xor_break_cryptopals(self):
        mca = ModernCryptoAnalyzer()
        plaintext = (
            "Burning 'em, if you ain't quick and nimble\n"
            "I go crazy when I hear a cymbal"
        ).encode('utf-8')
        key = b"ICE"
        # Encrypt with repeating-key XOR
        ct = bytes([b ^ key[i % len(key)] for i, b in enumerate(plaintext)])
        # Focus on known key size for a deterministic test
        cands = mca.repeating_xor_break(ct, min_key=3, max_key=3, top_k=1)
        self.assertTrue(cands, "No candidates returned")
        # Verify that at least one candidate's decryption equals the plaintext
        ok = any(c.get('decrypted') == plaintext for c in cands)
        self.assertTrue(ok, "No candidate produced the correct plaintext")

if __name__ == '__main__':
    unittest.main()
