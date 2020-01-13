from rest_framework import viewsets
from rest_framework import filters
from app.models import CVE, AffectedProduct, Reference
from api.serializers import CVESerializer, AffectedProductSerializer, ReferenceSerializer


class CVEViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CVE.objects.all()
    serializer_class = CVESerializer
    filter_backends = (filters.SearchFilter, filters.OrderingFilter)
    search_fields = ('cve_id', 'summary')
    ordering_fields = ('cve_id', 'published_date', 'last_modified_date', 'affected_products', 'cvss_v2_base_score')

class AffectedProductViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AffectedProduct.objects.all()
    serializer_class = AffectedProductSerializer
    filter_backends = (filters.SearchFilter,)
    search_fields = ('uri',)


class ReferenceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Reference.objects.all()
    serializer_class = ReferenceSerializer
    filter_backends = (filters.SearchFilter,)
    search_fields = ('url',)
