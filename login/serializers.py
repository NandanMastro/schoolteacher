from rest_framework import serializers
from .models import account
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import Group
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required


class AccountSerializer(serializers.ModelSerializer):

    class Meta:
        model = account
        # fields = '__all__'
        fields = ['id', 'first_name', 'last_name', 'email', 'password', 'is_admin', 'is_teacher', 'groups',
                  'user_permissions']
        extra_kwargs = {'password': {'write_only': True}}

    # @method_decorator(login_required)
    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        return super(AccountSerializer, self).create(validated_data)

    # @method_decorator(login_required)
    # def list(self, request):
    #     print()
