from secretfinderr import rules, detector, cli
from pathlib import Path
import tempfile
import unittest


class TestBasic(unittest.TestCase):
    def test_detect_aws(self):
        d = tempfile.mkdtemp()
        p = Path(d) / 's.txt'
        p.write_text('AKIAIOSFODNN7EXAMPLE')
        res = detector.scan_path(Path(d), rules.load_rules())
        self.assertTrue(res.matches)
        self.assertEqual(res.matches[0].rule_name, 'AWS Access Key')

    def test_no_secrets(self):
        d = tempfile.mkdtemp()
        p = Path(d) / 'clean.txt'
        p.write_text('hello world')
        res = detector.scan_path(Path(d), rules.load_rules())
        self.assertEqual(len(res.matches), 0)

    def test_exit_codes(self):
        d = tempfile.mkdtemp()
        p = Path(d) / 's.txt'
        p.write_text('AKIAIOSFODNN7EXAMPLE')
        rc = cli.main(['scan', str(p)])
        self.assertEqual(rc, 1)
        p2 = Path(d) / 'c.txt'
        p2.write_text('ok')
        rc2 = cli.main(['scan', str(p2)])
        self.assertEqual(rc2, 0)


if __name__ == '__main__':
    unittest.main()
