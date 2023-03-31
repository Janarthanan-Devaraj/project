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


class DateAbstract(models.Model):
    
    created_at = models.DateTimeField(auto_now_add= True)
    updated_at = models.DateTimeField(auto_now= True)
    
    class Meta:
        abstract = True


class CustomUser(AbstractBaseUser, DateAbstract):
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

class UserProfile(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="user_profile", on_delete= models.CASCADE)
    avatar = models.ImageField(upload_to="user_avatar", blank=True, null=True, default='https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460__340.png')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    username = models.CharField(max_length=100, unique= True)
    gender = models.CharField(max_length=6, choices=(("male", "male"), ("female", "female")))
    dob = models.DateField()
    
    def __str__(self):
        return self.user.email
    
class AcademicInfo(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="student_model", on_delete= models.CASCADE)
    roll_number = models.CharField(max_length=7)
    degree = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    current_semester = models.PositiveSmallIntegerField()
    cgpa = models.FloatField(max_length=3)

    
    def __str__(self):
        return self.user.email

class CompanyInfo(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="alumni_model", on_delete= models.CASCADE)
    company = models.CharField(max_length=200)
    designation = models.CharField(max_length=100)
    location = models.CharField( max_length=20)
    
    def __str__(self):
        return self.user.email
    

class ClubInfo(DateAbstract):
    user = models.OneToOneField(CustomUser, related_name="club_model", on_delete= models.CASCADE)
    club_name = models.TextField()
    