import unittest

from analyzers.web.flag_reassembly import reassemble_flag_chunks


class TestFlagReassembly(unittest.TestCase):
    def test_reassemble_spanning_findings(self):
        # Two findings across same stream that together form a valid flag
        findings = [
            {'data': 'prefix flag{part1_', 'stream_id': 's1', 'packet_index': 10},
            {'data': 'cont_part2}', 'stream_id': 's1', 'packet_index': 12},
        ]
        res = reassemble_flag_chunks(findings)
        self.assertIsInstance(res, list)
        self.assertEqual(len(res), 1)
        r = res[0]
        self.assertTrue(r['reassembled_flag'].startswith('flag{'))
        self.assertTrue(r['reassembled_flag'].endswith('}'))
        # Ensure indices and chunks recorded
        self.assertEqual(r['packet_indices'], [10, 12])
        self.assertGreaterEqual(len(r['flag_chunks']), 2)

    def test_single_complete_flag(self):
        findings = [
            {'data': 'foo CTF{hello_world}', 'stream_id': 's2', 'packet_index': 3},
        ]
        res = reassemble_flag_chunks(findings)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['reassembled_flag'], 'CTF{hello_world}')


if __name__ == '__main__':
    unittest.main()
