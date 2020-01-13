from django.urls import path, include, re_path
from api.routers import api_router
from api.views import ChartView

app_name = 'api'

urlpatterns = [
    path('', include(api_router.urls)),
    re_path(r'chart/(?P<from>[\w\-\.]+)/(?P<to>[\w\-\.]+)/$', ChartView.as_view()),
]