from django.db import models


# Create your models here.
class UserGroup(models.Model):
    title = models.CharField(max_length=32)


class UserInfo(models.Model):
    username = models.CharField(max_length=32)
    password = models.CharField(max_length=64)
    email = models.CharField(max_length=64)
    user_type_choices = (
        (1, '游客'),
        (2, '登录用户'),
        (3, '活动会员'),
        (4, '充钱会员'),
    )
    user_type_id = models.IntegerField(choices=user_type_choices, default=1)
    ug = models.ForeignKey(UserGroup, default=1)


class Token(models.Model):
    user = models.OneToOneField('UserInfo')   # 表示只能在一个终端登录
    token = models.CharField(max_length=64)   # 相当于访问验证码
