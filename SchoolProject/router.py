from login.viewsets import AccountViewset
from rest_framework import routers


router = routers.DefaultRouter()
router.register('view', AccountViewset)
