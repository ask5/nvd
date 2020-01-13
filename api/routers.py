from rest_framework import routers
from api.viewsets import CVEViewSet, AffectedProductViewSet, ReferenceViewSet

api_router = routers.DefaultRouter()
api_router.register(r'cve', CVEViewSet)
api_router.register(r'product', AffectedProductViewSet)
api_router.register(r'reference', ReferenceViewSet)
#api_router.register(r'chart_data', ChartViewSet.as_view())