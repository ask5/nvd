from django.db import models


class CVE(models.Model):
    cve_id = models.CharField(primary_key=True, verbose_name="CVE Id", max_length=20)
    summary = models.TextField(verbose_name="Summary")
    published_date = models.DateField("Published Date", blank=True, null=True)
    last_modified_date = models.DateField("Last Modified Date", blank=True, null=True)
    affected_products = models.IntegerField("Number of Affected Products", blank=True, null=True)
    cvss_v2_base_score = models.DecimalField("CVSS V2 Base Score", max_digits=3, decimal_places=1, blank=True, null=True)
    cvss_v2_severity = models.CharField("CVSS V2 Severity", max_length=20, blank=True, null=True)
    cvss_v2_vector_string = models.CharField("CVSS V2 Vector String", max_length=255, blank=True, null=True)
    cvss_v3_base_score = models.DecimalField("CVSS V3 Base Score", max_digits=3, decimal_places=1, blank=True, null=True)
    cvss_v3_severity = models.CharField("CVSS V3 Severity", max_length=20, blank=True, null=True)
    cvss_v3_vector_string = models.CharField("CVSS V3 Vector String", max_length=255, blank=True, null=True)


class AffectedProduct(models.Model):
    id = models.AutoField(primary_key=True)
    cve_id = models.ForeignKey(CVE, on_delete=models.CASCADE)
    vulnerable = models.BooleanField()
    uri = models.CharField("cpe23Uri", max_length=500)


class Reference(models.Model):
    id = models.AutoField(primary_key=True)
    cve_id = models.ForeignKey(CVE, on_delete=models.CASCADE)
    url = models.CharField("URL", max_length=500)
    name = models.CharField("Name", max_length=500)
    source = models.CharField("Ref Source", max_length=20)
    tags = models.CharField("Tags", max_length=255, blank=True, null=True)
