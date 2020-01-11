from django.test import SimpleTestCase
import json
from lib.nvd_cve import Parser

# Create your tests here.
class NvdCveParserTests(SimpleTestCase):

    with open('./jsons/nvd_cve_feed_json_1.1.schema', 'r') as schema_file:
        schema_string = schema_file.read()
        schema = json.loads(schema_string)

    with open('./jsons/nvdcve-1.1-modified', 'r') as json_file:
        json_string = json_file.read()
        cve_json = json.loads(json_string)

    def test_json_is_valid(self):
        nvd_cve_parser = Parser(self.schema)
        self.assertTrue(nvd_cve_parser.is_valid(self.cve_json))

    def test_feed(self):
        nvd_cve_parser = Parser(self.schema)
        cves = nvd_cve_parser.parse(self.cve_json)
        for cve in cves:
            print(cve['references'])
        self.assertTrue(nvd_cve_parser.is_valid(self.cve_json))
