from rest_framework import  serializers
from app.models import CVE, Reference, AffectedProduct


class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields='__all__'


class ReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reference
        fields='__all__'


class AffectedProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = AffectedProduct
        fields='__all__'


class ChartSerializer(serializers.ModelSerializer):
    cve_count = serializers.IntegerField()

    class Meta:
        model = CVE
        fields = ('last_modified_date', 'cve_count')