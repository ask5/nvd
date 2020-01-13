import jsonschema
import datetime

'''
    class to parse the NVD CVE JSON feed 
'''


class Parser:

    def __init__(self, schema):
        self.schema = schema

    '''
        validates json against the draft-04 schema
        http://json-schema.org/draft-04/schema#         
        currenly its using an external library for validation
        but this needs to revisited and made robust
    '''
    def is_valid(self, json):
        if self.schema:
            return jsonschema.Draft4Validator(self.schema).is_valid(json)
        else:
            raise ValueError("Schema not defined")

    '''
        parses the json and extracts attributes we care about.
        and returns a list of CVEs
    '''
    def parse(self, json):
        result = []

        for item in json['CVE_Items']:
            c = dict()
            if 'cve' in item and 'CVE_data_meta' in item['cve'] and 'ID' in item['cve']['CVE_data_meta']:
                c['id'] = item['cve']['CVE_data_meta']['ID']

            summary = ''
            if 'description' in item['cve'] and 'description_data' in item['cve']['description']:
                summary = item['cve']['description']['description_data'][0]['value']
            c['summary'] = summary

            pd = item['publishedDate'].split('T')
            c['published_date'] = datetime.datetime.strptime(pd[0], "%Y-%m-%d").date()

            lmd = item['lastModifiedDate'].split('T')
            c['last_modified_date'] = datetime.datetime.strptime(lmd[0], "%Y-%m-%d").date()

            if 'baseMetricV2' in item['impact']:
                c['cvss_v2_base_score'] = item['impact']['baseMetricV2']['cvssV2']['baseScore']
                c['cvss_v2_severity'] = item['impact']['baseMetricV2']['severity']
                c['cvss_v2_vector_string'] = item['impact']['baseMetricV2']['cvssV2']['vectorString']

            if 'baseMetricV3' in item['impact']:
                c['cvss_v3_base_score'] = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                c['cvss_v3_severity'] = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                c['cvss_v3_vector_string'] = item['impact']['baseMetricV3']['cvssV3']['vectorString']

            affected_products = []
            if 'configurations' in item and len(item['configurations']['nodes']) > 0:
                for node in item['configurations']['nodes']:
                    if 'cpe_match' in node:
                        for n in node['cpe_match']:
                            affected_products.append(n)
                    elif 'children' in node:
                        for child in node['children']:
                            if 'cpe_match' in child:
                                for n in child['cpe_match']:
                                    affected_products.append(n)

            c['affected_products'] = affected_products

            if 'references' in item['cve'] and 'reference_data' in item['cve']['references']:
                c['references'] = item['cve']['references']['reference_data']
            else:
                c['references'] = []

            result.append(c)

        return result