from django.shortcuts import render, HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from . import models
import json
from rest_framework import serializers
# Create your views here.


def gen_token(username):
    import time
    import hashlib
    ctime = str(time.time())
    hash = hashlib.md5(username.encode('utf-8'))
    hash.update(ctime.encode('utf-8'))
    return hash.hexdigest()


class Login(APIView):

    def post(self, request, *args, **kwargs):
        print(request.body)

        info = json.loads(request.body)
        user = info.get('name')
        pwd = info.get('password')
        ret = {'code': 1000, 'username': None, 'password': None, 'msg': None}
        """
        获取用户提交的用户名和密码，如果用户名密码正确，则生成token，并且返回给客户
            code: 1000  表示登录失败
            code: 1001  表示登录成功
            msg：错误信息
            token ：用户token
        """
        user_obj = models.UserInfo.objects.filter(username=user, password=pwd).first()
        # print(user_obj)

        if user_obj:
            tk = gen_token(user)
            # print(tk)
            models.Token.objects.update_or_create(user=user_obj, defaults={'token': tk})
            ret['code'] = 1001
            ret['token'] = tk
            ret['username'] = user
            ret['password'] = pwd
        else:
            ret['code'] = 1000
            ret['msg'] = '用户名或密码错误'
        return JsonResponse(ret)


class CourseSerializers(serializers.ModelSerializer):
    price_policy = serializers.SerializerMethodField()

    class Meta:
        model = models.Course
        fields = ['id', 'name', 'course_img', 'period', 'price_policy']

    def get_price_policy(self, obj):
        ret = []
        policy = obj.price_policy.all()
        for item in policy:
            ret.append({'price': item.price, 'period': item.valid_period})
        return ret


class CourseDetailSerializers(serializers.ModelSerializer):
    course_name = serializers.CharField(source='course.name')
    recommend_course_list = serializers.SerializerMethodField()
    course_price_policy = serializers.SerializerMethodField()

    class Meta:
        model = models.CourseDetail
        # fields = ['id', 'course_name']
        fields = [
            'id',
            'hours',
            'course_slogan',
            'video_brief_link',
            'course_name',
            'recommend_course_list',
            'course_price_policy'
        ]

    def get_recommend_course_list(self, obj):
        ret = []
        course_list = obj.recommend_courses.all()
        for item in course_list:
            ret.append({'id': item.id, 'name': item.name})
        return ret

    def get_course_price_policy(self, obj):
        ret = []
        price_policy_list = obj.course.price_policy.all()
        for item in price_policy_list:
            ret.append({'price': item.price, 'period': item.valid_period})
        return ret


class Index(APIView):

    def get(self, request, *args, **kwargs):

        # from django.core.exceptions import ObjectDoesNotExist
        response = {'code': 1000, 'msg': None, 'data': None}

        # try:
        pk = kwargs.get('pk')
        if pk:
            detail = models.CourseDetail.objects.get(course_id=pk)
            ser = CourseDetailSerializers(instance=detail, many=False)
        else:
            queryset = models.Course.objects.exclude(course_type=2)
            ser = CourseSerializers(instance=queryset, many=True)

        response['data'] = ser.data

        #
        # except ObjectDoesNotExist as e:
        #     response['code'] = 1001
        #     response['msg'] = '查询课程不存在'
        #
        # except IndexError as e:
        #     pass
        #
        # except Exception as e:
        #     response['msg'] = '查询课程失败'
        #     response['code'] = 1001

        return Response(response)

