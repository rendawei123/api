from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.versioning import URLPathVersioning
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from app01 import models
from django.http import JsonResponse
from rest_framework import serializers
from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.request import Request
from rest_framework.throttling import BaseThrottle, AnonRateThrottle,SimpleRateThrottle
from rest_framework.parsers import JSONParser, FormParser
from rest_framework.negotiation import DefaultContentNegotiation
from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination
# Create your views here.


# ####################认证相关################
# 生成token
def gen_token(username):
    import time
    import hashlib
    ctime = str(time.time())
    hash = hashlib.md5(username.encode('utf-8'))
    hash.update(ctime.encode('utf-8'))
    return hash.hexdigest()


class CustomAuthentication(BaseAuthentication):
    """
    用户认证类
    """
    def authenticate(self, request):
        """
        Authenticate the request and return a two-tuple of (user, token).
        """
        tk = request.query_params.get('tk')  # query_params获取get请求
        # print(tk)
        token_obj = models.Token.objects.filter(token=tk).first()
        # print(token_obj)
        if token_obj:
            return (token_obj.user, token_obj)
        raise exceptions.AuthenticationFailed('认证失败')

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        pass


class AuthJudgeView(object):
    """
    用户认证类，以后凡是涉及到用户认证的都继承它，但是必须要放在最前面
    """
    authentication_classes = [CustomAuthentication, ]


# ######################权限相关#####################
class CustomPermission(BasePermission):
    message = '无权限'

    # view表示当前访问的哪个视图
    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        if request.user.user_type_id == 1 and isinstance(view, GroupView):
            return False
        return True


# #####################限制访问次数##################
"""
如果用户已经登录，则按照用户名进行限制，
如果用户未登录，则按照IP进行限制
"""


class CustomAnonRateThrottle(SimpleRateThrottle):
    """
    未登录使用IP进行限制
    如何判断是未登录用户呢： request.user=用户对象，request.user=None
    """
    scope = 'luffy_anon'

    def allow_request(self, request, view):
        # # 如果用户已经登录
        if request.user:
            return True
        # 获取唯一标识：IP+格式化
        self.key = self.get_cache_key(request, view)

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop any requests from the history which have now passed the
        # throttle duration
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()
        if len(self.history) >= self.num_requests:
            return self.throttle_failure()
        return self.throttle_success()

    def get_cache_key(self, request, view):
        # format其实就是做字符串格式化
        return self.cache_format % {
            # 自己设置成anon
            'scope': self.scope,
            # 获取ip
            'ident': self.get_ident(request)
        }


class CustomUserRateThrottle(SimpleRateThrottle):
    """
    已登录使用用户名进行限制
    """
    scope = 'luffy_user'

    def allow_request(self, request, view):
        # 如果用户未登录
        if not request.user:
            return True
        # 获取唯一标识：
        self.key = request.user.username

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop any requests from the history which have now passed the
        # throttle duration
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()
        if len(self.history) >= self.num_requests:
            return self.throttle_failure()
        return self.throttle_success()


class UserView(APIView):
    """
    普通请求
    """
    throttle_classes = [CustomAnonRateThrottle, CustomUserRateThrottle]

    def get(self, request, *args, **kwargs):
        return Response('111')


class VersionView(APIView):
    """
    版本控制
    """
    def get(self, request, *args, **kwargs):
        print(self.dispatch)
        print(request.version)
        print(request)
        reverse_url = request.versioning_scheme.reverse('aaa', request=request)
        print(reverse_url)
        return Response('222')


class AuthView(APIView):
    """
    允许匿名用户登录,post请求中带用户名和密码，如果正确，创造一个token，如果不正确，返回错误
    """
    def post(self, request, *args, **kwargs):
        ret = {'code': 1000, 'msg': None}
        """
        获取用户提交的用户名和密码，如果用户名密码正确，则生成token，并且返回给客户
            code: 1000  表示登录失败
            code: 1001  表示登录成功
            msg：错误信息
            token ：用户token
        """
        user = request.data.get('user')
        pwd = request.data.get('pwd')
        user_obj = models.UserInfo.objects.filter(username=user, password=pwd).first()
        print(user_obj)

        if user_obj:
            tk = gen_token(user)
            print(tk)
            # 先找，找到类再更新，没找到就创建，前面的是条件，后面的是操作
            models.Token.objects.update_or_create(user=user_obj, defaults={'token': tk})
            ret['code'] = 1001
            ret['token'] = tk
        else:
            ret['msg'] = '用户名或密码错误'
        print(request.data)
        print(user, pwd)

        return JsonResponse(ret)


class AuthenticationView(AuthJudgeView, APIView):
    """
    不允许匿名用户
    发送get请求http://127.0.0.1:8000/authentication/?tk=9e49406f211628a30bb9c359f7e9331f
    """
    permission_classes = [CustomPermission, ]
    throttle_classes = [CustomAnonRateThrottle, CustomUserRateThrottle]

    def get(self, request, *args, **kwargs):
        # print(self.permission_classes)
        print(request.user.username)
        print(request.user.password)
        print(request.user.email)
        return Response('访问成功')


# 组管理也需要用户登录
class GroupView(AuthJudgeView, APIView):
    """
    用户组管理
    """
    permission_classes = [CustomPermission, ]

    def get(self, request, *args, **kwargs):
        print(request.user.username)
        print(request.user.password)
        print(request.user.email)
        return Response('访问成功')


class ParserView(APIView):
    """
    解析相关
    """
    # 只能处理content_type 为'application/json' 或者 application/x-www-form-urlencoded'的数据
    parser_classes = [JSONParser, FormParser]
    # content_negotiation_class = ''

    def post(self, request, *args, **kwargs):
        # self.dispatch()
        # 有request.data的时候才调用解析
        print(request.data)
        return Response('999')


# ###############   序列化 ##########################
class PasswordValidator(object):
    """
    对密码进行复杂的验证
    """
    def __init__(self, base):
        self.base = base

    # value为用户发送过来的值，想定义更复杂的验证可以放在这个方法里面
    def __call__(self, value):
        if value != self.base:
            message = '密码必须是 %s.' % self.base
            raise serializers.ValidationError(message)

    def set_context(self, serializer_field):
        """
        This hook is called by the serializer instance,
        prior to the validation call being made.
        """
        # 执行验证之前调用,serializer_fields是当前字段对象
        pass


class UserSerializers(serializers.Serializer):
    """
    序列化函数
    注意：前面的名字要和数据库的字段保持一致
    """
    username = serializers.CharField(error_messages={'required': '用户名不能为空'})
    # validators对密码可以进行复杂的判断,表示密码必须为666，注意666的字符串和数字的问题
    password = serializers.CharField(validators=[PasswordValidator("666"), ])
    email = serializers.CharField()
    ug = serializers.CharField(source="ug.title")
    # user_type_id = serializers.IntegerField()


class SerializersView(APIView):
    """
    序列化
    """
    def get(self, request, *args, **kwargs):
        user_list = models.UserInfo.objects.all()
        # many=True表示需要序列化的是一个列表
        ser = UserSerializers(instance=user_list, many=True)
        return Response(ser.data)

    def post(self, request, *args, **kwargs):
        ser = UserSerializers(data=request.data)
        # 做用户请求的验证
        if ser.is_valid():
            # 如果正确，打印数据
            return Response(ser.validated_data)
        else:
            # 如果错误，打印错误信息
            return Response(ser.errors)


# ######################## 分页 #####################
class MyPagination(PageNumberPagination):
    # 默认一页显示数据条数
    page_size = 1
    # 第几页
    page_query_param = 'page'
    # 定制一页显示的数据条数
    page_size_query_param = 'page_size'


class PagerSerializers(serializers.Serializer):
    """
    序列化函数
    注意：前面的名字要和数据库的字段保持一致
    """
    username = serializers.CharField()
    password = serializers.CharField()
    email = serializers.CharField()
    ug = serializers.CharField(source="ug.title")


class PagerView(APIView):
    def get(self, request, *args, **kwargs):
        user_list = models.UserInfo.objects.all()
        # 根据url参数获取分页数据
        obj = MyPagination()
        page_user_list = obj.paginate_queryset(user_list, request, self)
        # 数据进行序列化
        ser = PagerSerializers(instance=page_user_list, many=True)
        response = obj.get_paginated_response(ser.data)
        return response


# ################### 渲染 ###################
from rest_framework.renderers import JSONRenderer, AdminRenderer, BrowsableAPIRenderer


class RenderView(APIView):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer]

    def get(self, request, *args, **kwargs):
        user_list = models.UserInfo.objects.all()
        ser = UserSerializers(instance=user_list, many=True)
        return Response(ser.data)
