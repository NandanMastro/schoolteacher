from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.models import Group


class MyAccountManager(BaseUserManager):
    def create_user(self, email, password):
        if not email:
            raise ValueError('Users must have an email address')
        if not password:
            raise ValueError('Users must have a password')

        print('Details received by model')
        print('email = ', email)
        print('password = ', password)

        user = self.model(email=self.normalize_email(email), password=password)
        user.set_password(password)
        # print(user.password)

        user.save(using=self._db)
        return user

        # user.set_password(password)
        # user.save(using=self._db)
        # return user

    def create_superuser(self, email, password):
        user = self.create_user(email=self.normalize_email(email), password=password)
        print('superuser')
        user.is_verified = True
        user.is_active = True
        user.is_superuser = True
        user.is_admin = True

        user.save(using=self._db)
        return user


# Create your models here.
class account(AbstractBaseUser,PermissionsMixin):
    first_name = models.CharField(verbose_name="First name", max_length=60, null=True)
    last_name = models.CharField(verbose_name="last name", max_length=60, null=True)
    email = models.EmailField(verbose_name="email", max_length=60, unique=True)
    password = models.CharField(verbose_name="password", max_length=255)

    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)

    is_admin = models.BooleanField(default=False)
    is_teacher = models.BooleanField(default=False)

    # groups = models.ManyToManyField(Group, verbose_name=('groups'),
    #                                 blank=True,
    #                                 help_text=(
    #                                     'The groups this user belongs to. A user will get all permissions '
    #                                     'granted to each of their groups.'
    #                                 ),
    #                                 related_name="user_set",
    #                                 related_query_name="user",
    #                                 )

    USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = ['password']

    objects = MyAccountManager()

    def __str__(self):
        return self.email

    # @property
    # def is_staff(self):
    #     "Is the user a member of staff?"
    #     return self.staff
    #
    # @property
    # def is_admin(self):
    #     "Is the user a admin member?"
    #     return self.admin
    #
    # @property
    # def is_active(self):
    #     "Is the user active?"
    #     return self.active
    def get_group_permissions(self):
        print(self.groups)
        return self.groups

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True
