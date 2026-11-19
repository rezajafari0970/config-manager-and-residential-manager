import importlib.util
import ipaddress
import pathlib
import unittest


spec = importlib.util.spec_from_file_location("kddi_access", pathlib.Path(__file__).with_name("egress-network-kddi.py"))
kddi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kddi)
PAGE = """<script>192.0.2.0/24</script><p>{scope}は以下となります。</p><p>{notice}</p>
<ul><li>27.81.160.0/20</li><li>106.128.0.0/13 <sup>※1</sup></li>
<li>106.135.64.0/22</li><li>2001:268:9000::/36</li></ul>
<ol><li>以下のアドレスを除く<div><p>106.134.0.0/16</p><p>106.135.0.0/16</p></div></li></ol>
<footer><ul><li>45.76.115.0/24</li></ul></footer>""".format(scope=kddi.SCOPE, notice=kddi.DATA_NOTICE)


class MobilePools(unittest.TestCase):
    def test_only_published_service_and_no_exceptions_even_in_overlapping_row(self):
        pools = kddi.prefixes(PAGE.encode())
        for ip in ("27.81.160.3", "106.128.0.2", "2001:268:9000::3"):
            self.assertTrue(any(ipaddress.ip_address(ip) in pool for pool in pools))
        for ip in ("106.134.0.3", "106.135.64.2", "45.76.115.243", "192.0.2.1"):
            self.assertFalse(any(ipaddress.ip_address(ip) in pool for pool in pools))

    def test_drift_or_ambiguous_exceptions_fail_closed(self):
        for original, replacement in ((kddi.SCOPE, ""), (kddi.DATA_NOTICE, ""), ("※1", "※2"),
                                      ("以下のアドレスを除く", ""), ("106.134.0.0/16", "8.8.0.0/16"),
                                      ("2001:268:9000::/36", "garbage"), ("</ol>", "")):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                kddi.prefixes(PAGE.replace(original, replacement).encode())


if __name__ == "__main__":
    unittest.main()
