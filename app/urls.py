from django.urls import re_path, path

from . import views

app_name = 'app'

urlpatterns = [
    path('$', views.index, name='index'),
    re_path(r'cve/(?P<id>[-\w]+)', views.detail, name='detail'),
    re_path(r'download/(?P<id>[-\w]+)', views.download, name='download')

]
