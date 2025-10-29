import unittest
from apps.tshark_ai import sanitize_args

class TestTsharkSanitizer(unittest.TestCase):
    def test_disallow_unexpected_flags(self):
        args = ["-r", "file.pcap", "--write", "out.pcap", "-X", "lua_script:bad.lua", "-T", "json"]
        safe = sanitize_args(args)
        self.assertIn("-r", safe)
        self.assertIn("file.pcap", safe)
        # --write and -X should be removed
        self.assertNotIn("--write", safe)
        self.assertNotIn("-X", safe)
        # -T json retained
        self.assertIn("-T", safe)
        self.assertIn("json", safe)

    def test_enforce_json_output(self):
        args = ["-r", "f.pcap", "-T", "psml"]
        safe = sanitize_args(args)
        # psml should be replaced with json
        t_index = safe.index("-T")
        self.assertEqual(safe[t_index+1], "json")

    def test_allow_o_tls_keylog(self):
        args = ["-o", "tls.keylog_file:C:/path/to/keylog.txt"]
        safe = sanitize_args(args)
        self.assertEqual(safe, ["-o", "tls.keylog_file:C:/path/to/keylog.txt"]) 

if __name__ == '__main__':
    unittest.main()
