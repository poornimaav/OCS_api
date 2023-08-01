from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(User)
admin.site.register(Teacher)
admin.site.register(Student)
admin.site.register(Course)
admin.site.register(Content)
admin.site.register(Purchase)