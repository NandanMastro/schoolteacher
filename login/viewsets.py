from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import BasePermission
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny

from rest_framework.permissions import IsAuthenticated
from .permissions import IsTeacher

from . import models
from . import serializers


class IsActive(BasePermission):
    """
    Allows access only to "is_active" users.
    """
    def has_permission(self, request, view):
        print(request.user)
        if request.user.is_authenticated:
            return request.user.is_teacher
        else:
            return False


class AccountViewset(viewsets.ModelViewSet):
    queryset = models.account.objects.all()
    serializer_class = serializers.AccountSerializer
    permission_classes = (IsActive,)
    # permission_classes_by_action = {'list': (IsTeacher,)}

    def list(self, request):
        queryset = models.account.objects.all()
        serializer = serializers.AccountSerializer(queryset, many=True)
        # print(serializer.data)
        # print(request.user.is_teacher)
        # user = models.account.objects.get(first_name='Amrik')
        # print(user.has_perm)
        return Response(serializer.data)

    # def get_permissions(self):
    #     try:
    #         # return permission_classes depending on `action`
    #         return [permission() for permission in self.permission_classes_by_action[self.action]]
    #     except KeyError:
    #         # action is not set return default permission_classes
    #         return [permission() for permission in self.permission_classes]