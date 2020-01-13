from django.urls import re_path, path

from . import views

app_name = 'app'

urlpatterns = [
    path('cves/list/', views.index, name='index'),
    path('cves/chart/', views.chart, name='chart'),
    re_path(r'cves/detail/(?P<id>[-\w]+)', views.detail, name='detail'),
    re_path(r'cves/download/(?P<id>[-\w]+)', views.download, name='download'),
]
