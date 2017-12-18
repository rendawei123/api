from django.contrib import admin
from . import models

# Register your models here.

admin.site.register(models.UserInfo)
admin.site.register(models.Token)
admin.site.register(models.CourseCategory)
admin.site.register(models.CourseSubCategory)
admin.site.register(models.DegreeCourse)
admin.site.register(models.Course)
admin.site.register(models.CourseDetail)
admin.site.register(models.OftenAskedQuestion)
admin.site.register(models.CourseOutline)
admin.site.register(models.CourseChapter)
admin.site.register(models.Teacher)
admin.site.register(models.PricePolicy)
admin.site.register(models.CourseSection)
