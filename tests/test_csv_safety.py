import unittest

from csv_safety import csv_safe


class CsvSafetyTest(unittest.TestCase):
    def test_formula_prefixes_are_neutralized(self):
        for value in (
            "=HYPERLINK(\"https://evil\")",
            "+1+1",
            "-2+3",
            "@SUM(1,2)",
            "  =1+1",
            "\t=1+1",
        ):
            with self.subTest(value=value):
                self.assertTrue(csv_safe(value).startswith("'"))

    def test_normal_text_is_unchanged(self):
        self.assertEqual(csv_safe("normal"), "normal")
        self.assertEqual(csv_safe(None), "")


if __name__ == "__main__":
    unittest.main()
