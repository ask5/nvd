from rest_framework import  serializers
from app.models import CVE, Reference, AffectedProduct

# this file consists of serializer for all models

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