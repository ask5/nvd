from django.db import models

# Create your models here.
class CVE(models.Model):
    cve_id = models.CharField(primary_key=True, verbose_name="CVE Id")
    summary = models.TextField(verbose_name="Summary")
    published_date = models.DateTimeField("Published Date")
    last_modified_date = models.DateTimeField("Last Modified Date")
    affected_products = models.IntegerField("Number of Affected Products")
    cvss_v2_base_score = models.DecimalField("CVSS V2 Base Score")
    cvss_v2_severity = models.DecimalField("CVSS V2 Severity")
    cvss_v2_vector_string = models.DecimalField("CVSS V2 Vector String")
    cvss_v3_base_score = models.DecimalField("CVSS V3 Base Score")
    cvss_v3_severity = models.DecimalField("CVSS V3 Severity")
    cvss_v3_vector_string = models.DecimalField("CVSS V3 Vector String")
