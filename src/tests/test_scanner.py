import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import WebScanner
from report_generator import ReportGenerator
from utils.helpers import validate_url, is_valid_http_url, extract_domain

class TestURLValidation(unittest.TestCase):
    
    def test_valid_http_url(self):
        self.assertTrue(is_valid_http_url("http://testphp.vulnweb.com"))
        self.assertTrue(is_valid_http_url("https://example.com"))
    
    def test_invalid_url(self):
        self.assertFalse(is_valid_http_url("not_a_url"))
        self.assertFalse(is_valid_http_url("ftp://example.com"))
        self.assertFalse(is_valid_http_url(""))
    
    def test_extract_domain(self):
        self.assertEqual(extract_domain("http://example.com/path"), "example.com")
        self.assertEqual(extract_domain("https://subdomain.example.com"), "subdomain.example.com")

class TestScanner(unittest.TestCase):
    
    def setUp(self):
        self.test_url = "http://testphp.vulnweb.com"
        self.scanner = WebScanner(self.test_url)
    
    def test_scanner_initialization(self):
        self.assertEqual(self.scanner.url, self.test_url)
        self.assertEqual(len(self.scanner.vulnerabilities), 0)
        self.assertIsInstance(self.scanner.xss_payloads, list)
        self.assertIsInstance(self.scanner.sqli_payloads, list)
    
    def test_payloads_not_empty(self):
        self.assertGreater(len(self.scanner.xss_payloads), 0)
        self.assertGreater(len(self.scanner.sqli_payloads), 0)
    
    def test_form_details_extraction(self):
        from bs4 import BeautifulSoup
        html = '''
        <form action="/login" method="post">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" name="submit" value="Login">
        </form>
        '''
        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form')
        
        details = self.scanner.get_form_details(form)
        
        self.assertEqual(details['action'], '/login')
        self.assertEqual(details['method'], 'post')
        self.assertEqual(len(details['inputs']), 3)

class TestReportGenerator(unittest.TestCase):
    
    def setUp(self):
        self.test_vulns = [
            {
                "type": "XSS",
                "severity": "MÉDIA",
                "url": "http://testphp.vulnweb.com",
                "method": "GET",
                "parameter": "q",
                "payload": "<script>alert(1)</script>"
            }
        ]
        self.generator = ReportGenerator(
            self.test_vulns,
            "http://testphp.vulnweb.com",
            scan_duration=10.5
        )
    
    def test_json_report_generation(self):
        import json
        report_json = self.generator.generate_json_report()
        report_dict = json.loads(report_json)
        
        self.assertIn("scan_info", report_dict)
        self.assertIn("vulnerabilities", report_dict)
        self.assertEqual(len(report_dict["vulnerabilities"]), 1)
    
    def test_severity_count(self):
        count = self.generator._count_by_severity()
        self.assertEqual(count.get("MÉDIA"), 1)

class TestReportFormats(unittest.TestCase):
    
    def test_empty_vulnerabilities_report(self):
        import json
        generator = ReportGenerator([], "http://testphp.vulnweb.com")
        report_json = generator.generate_json_report()
        report_dict = json.loads(report_json)
        
        self.assertEqual(report_dict["scan_info"]["total_vulnerabilities"], 0)

def run_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestURLValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestReportGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestReportFormats))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)