import json
import unittest

from trail_evidence.jcs import canonicalize, format_number


class NumberFormatting(unittest.TestCase):
    def test_es6_cases(self):
        cases = {
            1.0: "1", 1: "1", 1e21: "1e+21", 1e-7: "1e-7", 0.000001: "0.000001",
            -0.0: "0", 0: "0", 100.0: "100", 0.1: "0.1", 1.5e300: "1.5e+300",
            5e-324: "5e-324", 123456789012345680000.0: "123456789012345680000",
            9007199254740993: "9007199254740992", -42.25: "-42.25",
            1e22: "1e+22", 1.25e-6: "0.00000125", 333333333.3333333: "333333333.3333333",
        }
        for value, want in cases.items():
            self.assertEqual(format_number(value), want, repr(value))

    def test_rejects_non_finite(self):
        with self.assertRaises(ValueError):
            format_number(float("nan"))
        with self.assertRaises(ValueError):
            format_number(float("inf"))


class Canonicalisation(unittest.TestCase):
    def test_sorting_by_utf16(self):
        # U+1F680 is encoded as surrogates D83D DE80 and sorts before U+FF01.
        self.assertEqual(canonicalize({"！": 1, "\U0001F680": 2, "a": 3}),
                         '{"a":3,"\U0001F680":2,"！":1}'.encode("utf-8"))

    def test_escaping(self):
        self.assertEqual(canonicalize({"s": "\u0001\u001f/ä\"\\\n\x7f"}),
                         '{"s":"\\u0001\\u001f/ä\\"\\\\\\n\x7f"}'.encode("utf-8"))

    def test_rfc8785_sample(self):
        # Input and expected output from RFC 8785, section 3.2.3 / appendix.
        source = r'''{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\u002f",
            "literals": [null, true, false]}'''
        want = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                '"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
        self.assertEqual(canonicalize(json.loads(source)), want.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
