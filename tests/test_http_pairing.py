import unittest
from apps.web_analyzer import pair_http_by_index

CRLF = "\r\n"

class TestHttpPairing(unittest.TestCase):
    def test_pairing_basic(self):
        req1 = (
            f"GET /pixel.gif?id=123 HTTP/1.1{CRLF}"
            f"Host: tracker.com{CRLF}"
            f"User-Agent: UA{CRLF}{CRLF}"
        )
        resp1 = (
            f"HTTP/1.1 200 OK{CRLF}"
            f"Content-Length: 43{CRLF}"
            f"Content-Type: image/gif{CRLF}{CRLF}"
            f"GIF89a...data"
        )
        req2 = (
            f"POST /submit HTTP/1.1{CRLF}"
            f"Host: ex.com{CRLF}{CRLF}"
        )
        resp2 = (
            f"HTTP/1.1 201 Created{CRLF}"
            f"Content-Type: text/plain{CRLF}"
            f"Content-Length: 2{CRLF}{CRLF}"
            f"OK"
        )
        pairs = pair_http_by_index([req1, req2], [resp1, resp2])
        self.assertEqual(len(pairs), 2)
        self.assertIsNotNone(pairs[0]['req'])
        self.assertIsNotNone(pairs[0]['resp'])
        self.assertEqual(pairs[0]['req']['host'], 'tracker.com')
        self.assertEqual(pairs[0]['req']['path'], '/pixel.gif?id=123')
        self.assertEqual(pairs[0]['resp']['content_length'], 43)
        self.assertEqual(pairs[0]['resp']['content_type'], 'image/gif')
        self.assertEqual(pairs[1]['req']['host'], 'ex.com')
        self.assertEqual(pairs[1]['resp']['content_type'], 'text/plain')
        self.assertEqual(pairs[1]['resp']['content_length'], 2)

if __name__ == "__main__":
    unittest.main()
