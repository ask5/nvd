from django.core.management.base import BaseCommand, CommandError
from io import BytesIO
from zipfile import ZipFile
import urllib.request
import json
from lib.nvd_cve import Parser
from app.models import CVE, AffectedProduct, Reference

class Command(BaseCommand):
    help = 'Imports a CVE File'

    def add_arguments(self, parser):

        parser.add_argument('-u', '--url', type=str,
                            help='URL of the CVE JSON ZIP file hosted on the website')

        parser.add_argument('-f', '--file', type=str,
                            help='Local file path to CVE Json file')

        parser.add_argument('-l', '--log',
                            action='store_true',
                            help='Show log')

    def handle(self, *args, **options):
        log = options['log']
        if options['url']:
            self.stdout.write(self.style.SUCCESS('Downloading file'))
            url = urllib.request.urlopen(options['url'])

            with ZipFile(BytesIO(url.read())) as zip_file:
                if log:
                    self.stdout.write(self.style.SUCCESS('Unzipping'))
                for file in zip_file.namelist():
                    content = zip_file.open(file).read()
                    self.load_tables(content, log)
        elif options['file']:
            with open(options['file']) as json_file:
                content = json.load(json_file)
                self.load_tables(content, log)

    def load_tables(self, content, log):
        if content:
            try:
                cve_json = json.loads(content)

                with open('./jsons/nvd_cve_feed_json_1.1.schema', 'r') as schema_file:
                    schema_string = schema_file.read()
                    schema = json.loads(schema_string)

                cve_parser = Parser(schema)

                # validate JSON
                if not cve_parser.is_valid(cve_json):
                    self.stderr.write(self.style.ERROR("Invaid JSON"))
                    return

                # validate Parse JSON
                if log:
                    self.stdout.write(self.style.SUCCESS('Parsing JSON'))
                cve_list = cve_parser.parse(cve_json)

                if cve_list:
                    count = 1
                    for cve in cve_list:
                        self.stdout.write(self.style.SUCCESS('Processing %d/%d: "%s"' %
                                                             (count, len(cve_list), cve['id'])))

                        cvss_v2_base_score = cve['cvss_v2_base_score'] if 'cvss_v2_base_score' in cve else None
                        cvss_v2_severity = cve['cvss_v2_severity'] if 'cvss_v2_severity' in cve else None
                        cvss_v2_vector_string = cve['cvss_v2_vector_string'] if 'cvss_v2_vector_string' in cve else None
                        cvss_v3_base_score = cve['cvss_v3_base_score'] if 'cvss_v3_base_score' in cve else None
                        cvss_v3_severity = cve['cvss_v3_severity'] if 'cvss_v3_severity' in cve else None
                        cvss_v3_vector_string = cve['cvss_v3_vector_string'] if 'cvss_v3_vector_string' in cve else None

                        cve_instance = None
                        # If CVE exists, then updated otherwise create
                        try:
                            cve_instance = CVE.objects.get(cve_id = cve['id'])
                            cve_instance.cve_id = cve['id']
                            cve_instance.summary = cve['summary']
                            cve_instance.published_date = cve['published_date']
                            cve_instance.last_modified_date = cve['last_modified_date']
                            cve_instance.affected_products = len(cve['affected_products'])
                            cve_instance.cvss_v2_base_score = cvss_v2_base_score
                            cve_instance.cvss_v2_severity = cvss_v2_severity
                            cve_instance.cvss_v2_vector_string = cvss_v2_vector_string
                            cve_instance.cvss_v3_base_score = cvss_v3_base_score
                            cve_instance.cvss_v3_severity = cvss_v3_severity
                            cve_instance.cvss_v3_vector_string = cvss_v3_vector_string
                            cve_instance.save()

                        except CVE.DoesNotExist:
                            cve_instance = CVE(
                                cve_id=cve['id'],
                                summary=cve['summary'],
                                published_date=cve['published_date'],
                                last_modified_date=cve['last_modified_date'],
                                affected_products=len(cve['affected_products']),
                                cvss_v2_base_score=cvss_v2_base_score,
                                cvss_v2_severity=cvss_v2_severity,
                                cvss_v2_vector_string=cvss_v2_vector_string,
                                cvss_v3_base_score=cvss_v3_base_score,
                                cvss_v3_severity=cvss_v3_severity,
                                cvss_v3_vector_string=cvss_v3_vector_string
                            )
                            cve_instance.save()

                        count = count + 1

                        if cve_instance:
                            if log:
                                self.stdout.write(self.style.SUCCESS('.... Populating Affected Products (%d)' %
                                                                 len(cve['affected_products'])))
                            AffectedProduct.objects.filter(cve_id=cve['id']).delete()
                            for product in cve['affected_products']:
                                ap = AffectedProduct(
                                    cve_id=cve_instance,
                                    vulnerable=product['vulnerable'],
                                    uri=product['cpe23Uri']
                                )
                                ap.save()

                            if log:
                                self.stdout.write(self.style.SUCCESS('.... Populating References (%d)' %
                                                                 len(cve['references'])))
                            Reference.objects.filter(cve_id=cve['id']).delete()
                            for ref in cve['references']:
                                r = Reference(
                                    cve_id=cve_instance,
                                    url= ref['url'],
                                    name=ref['name'],
                                    source= ref['refsource'],
                                    tags=','.join(ref['tags'])
                                )
                                r.save()

                self.stdout.write(self.style.SUCCESS('Data loaded successfully'))
            except Exception as e:
                self.stderr.write(self.style.ERROR(str(e)))
        else:
            self.stderr.write(self.style.ERROR("No content"))
