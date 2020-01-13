from django.shortcuts import render
from django.db.models import Count
from rest_framework import generics
from api.serializers import ChartSerializer
from app.models import CVE


class ChartView(generics.ListAPIView):
    serializer_class = ChartSerializer

    def get_queryset(self):

        from_date = self.kwargs['from']
        to_date = self.kwargs['to']

        if not to_date:
            to_date = from_date

        return CVE.objects.filter(last_modified_date__gte=from_date, last_modified_date__lte=to_date).\
            values('last_modified_date').annotate(cve_count=Count('cve_id')
        )
