from django.shortcuts import render
from .models import CVE
from django.core import serializers
from django.http import HttpResponse


def index(request):
    return render(request, 'app/index.html')


def detail(request, id):
    context = {}
    cve = CVE.objects.get(cve_id=id)
    context['cve'] = cve
    return render(request, 'app/detail.html', context)


def download(request, id):
    cve = CVE.objects.get(cve_id=id)
    serialized_cve = serializers.serialize('json', [cve, ])
    response = HttpResponse(serialized_cve, content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename="'+ id +'.json"'
    return response


def chart(request):
    return render(request, 'app/chart.html')
