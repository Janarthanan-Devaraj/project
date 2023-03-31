from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, student=False, alumni=False, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)

        user = self.model(email=email, student=student, alumni=alumni, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, student=False, alumni=False, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('student', student)
        extra_fields.setdefault('alumni', alumni)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password=password, **extra_fields)


class CustomUser(AbstractBaseUser):
    email = models.EmailField(verbose_name='email', max_length=255, unique=True)
    student = models.BooleanField(default=False)
    alumni = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
