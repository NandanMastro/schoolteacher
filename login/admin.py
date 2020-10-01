from django.contrib import admin
from .models import account
from django.contrib.auth.models import Group, User

# Register your models here.

admin.site.register(account)

