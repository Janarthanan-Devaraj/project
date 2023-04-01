from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import CustomUser, UserProfile, AcademicInfo, CompanyInfo

admin.site.register(UserProfile)
admin.site.register(AcademicInfo)
admin.site.register(CompanyInfo)

class CustomUserAdmin(BaseUserAdmin):
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserModelAdmin
    # that reference specific fields on auth.User.
    list_display = ('id','username', 'email', 'student', 'alumni','is_verified', 'is_superuser')
    list_filter = ('is_superuser',)
    fieldsets = (
        ('User Credentials', {'fields': ('username','email', 'password')}),
        ('Personal info', {'fields': ('student', 'alumni', 'is_verified')}),
        ('Permissions', {'fields': ('is_superuser',)}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username','email', 'student', 'alumni', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email', 'id')
    filter_horizontal = ()

# Register the CustomUser model with the admin site
admin.site.register(CustomUser, CustomUserAdmin)
