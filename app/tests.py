from django.test import TestCase
from app.models import CVE, AffectedProduct, Reference
import datetime


class ViewTests(TestCase):

    @classmethod
    def setUpTestData(self):
        self.cve_id = 'CVE-1999-1593'
        self.cve = CVE.objects.create(
            cve_id=self.cve_id,
            summary='testing cve model',
            published_date=datetime.datetime.now().date(),
            last_modified_date=datetime.datetime.now().date(),
            affected_products=2,
            cvss_v2_base_score=4.5,
            cvss_v2_severity='LOW',
            cvss_v2_vector_string='(AV:N/AC:H/Au:N/C:C/I:C/A:C)',
            cvss_v3_base_score=3.4,
            cvss_v3_severity='LOW',
            cvss_v3_vector_string='(AV:N/AC:H/Au:N/C:C/I:C/A:C)'
        )

        self.ap = AffectedProduct.objects.create(
            cve_id=self.cve,
            vulnerable=True,
            uri='cpe:2.3:o:microsoft:windows_2000:-:*:*:*:*:*:*:*'
        )

        self.ref = Reference.objects.create(
            cve_id=self.cve,
            url='http://archives.neohapsis.com/archives/ntbugtraq/1998-1999/msg00371.html',
            name='http://archives.neohapsis.com/archives/ntbugtraq/1998-1999/msg00371.html',
            source='MISC',
            tags='Third Party Advisory, "Mailing List"'
        )

    # Test the index page
    def test_list_view(self):
        response = self.client.get('/app/cves/list/')
        self.assertEqual(response.status_code, 200)

    # Test the detail page
    def test_detail_view(self):
        response = self.client.get('/app/cves/detail/'+ self.cve_id)
        self.assertEqual(response.status_code, 200)
