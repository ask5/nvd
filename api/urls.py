from django.urls import path, include
from api.routers import api_router

app_name = 'api'

urlpatterns = [
    path('', include(api_router.urls)),
]