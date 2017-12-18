## DjangoRestFramework创建流程

*DjangoRestFramework其实就是一套API的创建规范的组件，比如遵循的协议、正规的解析、发送格式、用户验证等等，其实没有restframework，我们完全可以根据API创建的规范自定义这些规则，但是比较麻烦，在实际生产中我们可以直接使用这个插件*

#### DjangoRestFramework生命周期

1. 请求进来首先进入wsgi协议
2. 中间件
3. 路由系统
4. 视图函数
   * dispatch
   * 封装request
   * 版本控制
   * 用户认证
   * 权限控制
   * 限制访问次数
   * 执行get/post方法
   * 解析
   * 验证/序列化
   * 分页
   * viewset
   * 路由
   * 返回值
5. 数据库
6. 返回的时候通过中间件
7. 然后再通过wsgi
8. 返回给用户

#### 首先进行如下的环境搭建

```shell
# 创建文件夹
$ mkdir myproject

# 创建并运行虚拟环境
$ cd myproject/
$ virtualenv --no-site-packages venv
$ source venv/bin/activate  # 注意windows会不同

# 在虚拟环境中安装依赖
$ pip install django
$ pip install djangorestframework

# 创建django程序
$ django-admin startproject Lufy

# 创建app
$ cd Lufy/
$ python3 manage.py startapp app01

# 运行测试
$ python3 manage.py runserver 127.0.0.1:8080
```

#### 初始配置

```python
# app配置
INSTALLED_APPS = [
    'django.contrib.admin',
    'app01',
    'rest_framework',
]
```

#### API规则(restful设计)

* API与用户的通信协议，总是使用[HTTPs协议](http://www.ruanyifeng.com/blog/2014/02/ssl_tls.html)。

* 域名
  * https://api.example.com    尽量将API部署在专用域名之下
  * https://example.org/api/    如果是简单的API可以部署在主域名之下

* 版本
  - 应该将API的版本号放在域名下URL，如：https://api.example.com/v1/

* 路径，视网络上任何东西都是资源，所以应该使用名词表示（可复数）
  - https://api.example.com/v1/zoos
  - https://api.example.com/v1/animals
  - https://api.example.com/v1/employees

* method：对于资源的具体
  - GET      ：从服务器取出资源（一项或多项）
  - POST    ：在服务器新建一个资源
  - PUT      ：在服务器更新资源（客户端提供改变后的完整资源）
  - PATCH  ：在服务器更新资源（客户端提供改变的属性）
  - DELETE ：从服务器删除资源

* 过滤，如果记录数量很多，服务不可能将他们都返回给用户，API应该提供参数，过滤返回结果

  * https://api.example.com/v1/zoos?limit=10：指定返回记录的数量
  * https://api.example.com/v1/zoos?offset=10：指定返回记录的开始位置
  * https://api.example.com/v1/zoos?page=2&per_page=100：指定第几页，以及每页的记录数
  * https://api.example.com/v1/zoos?sortby=name&order=asc：指定返回结果按照哪个属性排序，以及排序顺序
  * https://api.example.com/v1/zoos?animal_type_id=1：指定筛选条件

* 状态码

  ```python
  200 OK - [GET]：服务器成功返回用户请求的数据，该操作是幂等的（Idempotent）。
  201 CREATED - [POST/PUT/PATCH]：用户新建或修改数据成功。
  202 Accepted - [*]：表示一个请求已经进入后台排队（异步任务）
  204 NO CONTENT - [DELETE]：用户删除数据成功。
  400 INVALID REQUEST - [POST/PUT/PATCH]：用户发出的请求有错误，服务器没有进行新建或修改数据的操作，该操作是幂等的。
  401 Unauthorized - [*]：表示用户没有权限（令牌、用户名、密码错误）。
  403 Forbidden - [*] 表示用户得到授权（与401错误相对），但是访问是被禁止的。
  404 NOT FOUND - [*]：用户发出的请求针对的是不存在的记录，服务器没有进行操作，该操作是幂等的。
  406 Not Acceptable - [GET]：用户请求的格式不可得（比如用户请求JSON格式，但是只有XML格式）。
  410 Gone -[GET]：用户请求的资源被永久删除，且不会再得到的。
  422 Unprocesable entity - [POST/PUT/PATCH] 当创建一个对象时，发生一个验证错误。
  500 INTERNAL SERVER ERROR - [*]：服务器发生错误，用户将无法判断发出的请求是否成功。

  更多看这里：http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
  ```

  ​

* 错误处理，状态码是4xx时，应返回错误信息，error当做key。

  ```python
  {
      error: "Invalid API key"
  }
  ```

* 返回结果，针对不同操作，服务器向用户返回的结果应该符合以下规范。

  ```python
  GET /collection：返回资源对象的列表（数组）
  GET /collection/resource：返回单个资源对象
  POST /collection：返回新生成的资源对象
  PUT /collection/resource：返回完整的资源对象
  PATCH /collection/resource：返回完整的资源对象
  DELETE /collection/resource：返回一个空文档
  ```

* Hypermedia API，RESTful API最好做到Hypermedia，即返回结果中提供链接，连向其他API方法，使得用户不查文档，也知道下一步应该做什么。

  ```python
  {"link": {
    "rel":   "collection https://www.example.com/zoos",
    "href":  "https://api.example.com/zoos",
    "title": "List of zoos",
    "type":  "application/vnd.yourformat+json"
  }}
  ```

#### 基于Django Rest Framework框架实现

以下是rest framework框架基本流程，重要的功能是在APIView的dispatch中触发。

url.py

```python
from django.conf.urls import url
from django.contrib import admin
from app01 import views
 
urlpatterns = [
    url(r'^admin/', admin.site.urls),
    # 一般URL
    url(r'^user/', views.UserView.as_view()),
]
```

views.py

```python
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.versioning import URLPathVersioning
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from app01 import models
from django.http import JsonResponse
from rest_framework import serializers
from rest_framework.request import Request
 
 
class UserView(APIView):
    """
    普通请求
    """
    def get(self, request, *args, **kwargs):
        return Response('111')
 
    def post(self, request, *args, **kwargs):
        return Response('POST请求，响应内容')
 
    def put(self, request, *args, **kwargs):
        return Response('PUT请求，响应内容')
```

#### 版本配置

基于url的正则方式

*如：/v1/users/*

```python
# 配置  setting.py
# api版本控制
REST_FRAMEWORK = {
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning',
    'DEFAULT_VERSION': 'v1',            # 默认版本
    'ALLOWED_VERSIONS': ['v1', 'v2'],   # 允许的版本
    'VERSION_PARAM': 'version'          # URL中获取值的key
}


# url配置   url.py
from django.conf.urls import url
from django.contrib import admin
from app01 import views

urlpatterns = [
    url(r'^(?P<version>[v1|v2]+)/version/', views.VersionView.as_view(), name='aaa'),
]


# view配置   view.py
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.versioning import URLPathVersioning
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from app01 import models
from django.http import JsonResponse
from rest_framework import serializers
from rest_framework.request import Request


class VersionView(APIView):
    """
    版本控制
    """
    def get(self, request, *args, **kwargs):
        print(self.dispatch)
        print(request.version)
        print(request)
        # 反向生成URL
        reverse_url = request.versioning_scheme.reverse('aaa', request=request)
        print(reverse_url)
        return Response('222')
```

#### 认证和授权

用户url传入的token认证

* 做用户认证首先需要链接数据库，因为客户端需要携带用户名和密码，然后访问登录url
* 获取到发过来的用户名和密码之后在数据库中进行判断，如果用户名和密码正确，则为这个用户生成一个token，发送给客户端并且将这个token存入数据库
* 下次用户携带token访问不允许匿名用户访问的URL，
* 收到用户的token之后进入数据库进行判断，如有有这个token的话就允许进入，如果没有的话拒绝

```python
# model.py
from django.db import models

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

class Token(models.Model):
    user = models.OneToOneField('UserInfo')   # 表示只能在一个终端登录
    token = models.CharField(max_length=64)   # 相当于访问验证码


# url.py
from django.conf.urls import url
from django.contrib import admin
from app01 import views

urlpatterns = [
    # 登录URL
    url(r'^auth/', views.AuthView.as_view(), name='bbb'),
    # 不允许匿名用户登录url
    url(r'^authentication/', views.AuthenticationView.as_view(), name='bbb'),
]

# view.py
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.versioning import URLPathVersioning
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from app01 import models
from django.http import JsonResponse
from rest_framework import serializers
from rest_framework.request import Request


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

    def get(self, request, *args, **kwargs):
        print(request.user.username)
        print(request.user.password)
        print(request.user.email)
        return Response('333')
```

#### 权限管理

基于用户类型进行权限管理

给用户分组，游客能登录用户管理，其他类型既能登录用户管理，又能登录组管理

```python
# model.py
from django.db import models

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

class Token(models.Model):
    user = models.OneToOneField('UserInfo')   # 表示只能在一个终端登录
    token = models.CharField(max_length=64)   # 相当于访问验证码
    
    
# url.py
urlpatterns = [
    # 添加权限管理，对于普通用户让他进行用户管理，对于文艺用户让他即可以用户管理，也可以组管理
    # 用户管理，不允许匿名用户登录url
    url(r'^authentication/', views.AuthenticationView.as_view(), name='bbb'),
    # 组管理，
    url(r'^groups/', views.GroupView.as_view(), name='bbb'),
]


# view.py
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
    
class AuthenticationView(AuthJudgeView, APIView):
    """
    不允许匿名用户
    发送get请求http://127.0.0.1:8000/authentication/?tk=9e49406f211628a30bb9c359f7e9331f
    """
    permission_classes = [CustomPermission, ]

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
```

#### 用户访问频率、次数限制

基于用户IP限制访问频率

```python
# setting.py
REST_FRAMEWORK = {
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning',
    'DEFAULT_VERSION': 'v1',            # 默认版本
    'ALLOWED_VERSIONS': ['v1', 'v2'],   # 允许的版本
    'VERSION_PARAM': 'version',         # URL中获取值的key
    # 配置访问次数
    'DEFAULT_THROTTLE_RATES': {
        'anon': '5/m'  # 限制用户每分钟只能访问5次
    }
}


# url.py
urlpatterns = [
    url(r'^user/', views.UserView.as_view()),
]

# views.py
class CustomRateThrottle(SimpleRateThrottle):
    scope = 'anon'

    def get_cache_key(self, request, view):
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }
    

class UserView(APIView):
    """
    普通请求
    """
    throttle_classes = [CustomRateThrottle, ]

    def get(self, request, *args, **kwargs):
        return Response('111')
```

django控制访问次数缓存配置

*Django想要控制用户访问次数，就必须要记录每个用户每次的访问时间、ip等信息，以便下次访问的时候能够进行对比，以达到控制访问次数的效果，这些数据都是以字典的形式记录在Django的缓存中的*

比如

```python
用户访问记录：
{
    用户A: [1511312683.7824545, 1511312683.7824545, 1511312683.7824545],
    用户B: [1511312683.7824545, 1511312683.7824545, 1511312683.7824545],
}
```

当下次用户访问的时候Django会取出这个用户和这次访问进行对比进行判断

唯一标识

* 匿名用户一般都是使用IP作为唯一标识
* 登录用户一般都是使用用户名、手机号  等不能修改的信息作为唯一标识

#### 解析器

*解析器就是前端给后端Django发送数据的时候，不一定按照很正规的规范发送，不一定合适，比如不同的content_type为application/json的时候，request.post里面是没有值的，值全部在request.body里面，这就要求我们根据不同的content_type进行解析，把request.body里面的数据解析道request.post里面*

* 根据用户发送的请求头对请求体进行处理
* 只有在调用request.data的时候才进行处理并拿到结果

```python
# url.py
urlpatterns = [
    url(r'^parser/', views.ParserView.as_view(), name='bbb'),
]

# view.py
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
```

#### 序列化

*序列化就是将你取到的数据自动转化成json格式的数据发送*

```python
# model.py
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


# url.py
urlpatterns = [
    # 格式化，后面的format表示支持.json格式的
    url(r'^serializers\.(?P<format>\w+)', views.SerializersView.as_view(), name='bbb'),
]

# view.py
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

class UserSerializers(serializers.Serializer):
    """
    序列化函数
    注意：前面的名字要和数据库的字段保持一致
    """
    username = serializers.CharField()
    password = serializers.CharField()
    email = serializers.CharField()
    ug = serializers.CharField(source="ug.title") # source表示源头
    # user_type_id = serializers.IntegerField()


class SerializersView(APIView):
    """
    序列化
    调用ser.data的时候真正执行序列化
    """
    def get(self, request, *args, **kwargs):
        user_list = models.UserInfo.objects.all()
        # many=True表示需要序列化的是一个列表
        ser = UserSerializers(instance=user_list, many=True)
        return Response(ser.data)
```

序列化还有用户请求认证的功能

```python
# model.py
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


# url.py
urlpatterns = [
    # 格式化，后面的format表示支持.json格式的
    url(r'^serializers\.(?P<format>\w+)', views.SerializersView.as_view(), name='bbb'),
]

# view.py
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
```

#### 分页

传统方式分页，根据url得到页码，获取所有数据，传入每页需要多少数据，生成数据和上一页以及下一页

```python
# url.py
urlpatterns = [
    # 格式化，后面的format表示支持.json格式的
    url(r'^pager/', views.PagerView.as_view(), name='bbb'),
]

# views.py
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
```

上面的方式是最传统的分页方式，但是如果数据量太大的话，效率不高，下面基于位置和个数进行分页

```python
# url.py
from django.conf.urls import url, include
from web.views import s9_pagination

urlpatterns = [
    url(r'^test/', s9_pagination.UserViewSet.as_view()),
]

from rest_framework.views import APIView
from rest_framework import serializers
from .. import models

from rest_framework.pagination import PageNumberPagination,LimitOffsetPagination


class StandardResultsSetPagination(LimitOffsetPagination):
    # 默认每页显示的数据条数
    default_limit = 10
    # URL中传入的显示数据条数的参数
    limit_query_param = 'limit'
    # URL中传入的数据位置的参数
    offset_query_param = 'offset'
    # 最大每页显得条数
    max_limit = None

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserInfo
        fields = "__all__"


class UserViewSet(APIView):
    def get(self, request, *args, **kwargs):
        user_list = models.UserInfo.objects.all().order_by('-id')

        # 实例化分页对象，获取数据库中的分页数据
        paginator = StandardResultsSetPagination()
        page_user_list = paginator.paginate_queryset(user_list, self.request, view=self)

        # 序列化对象
        serializer = UserSerializer(page_user_list, many=True)

        # 生成分页和数据
        response = paginator.get_paginated_response(serializer.data)
        return response
```

游标分页

游标分页是效率最高的，因为用前面的方法，获取第一页很快，但是如果数据量更大的话，到后面会越来越慢，因为获取后面的页码的时候数据库还是从第一条开始，效率很低

使用游标的方法会维持一个游标，每次点击下一页的时候，跟新游标，这样，访问数据的时候直接取游标后面的数据就行了，数据量很大的时候可以用这种方式来实现，虽然只能一页一页翻，但是不会卡，速度很快

```python
# url.py
from django.conf.urls import url, include
from web.views import s9_pagination

urlpatterns = [
    url(r'^test/', s9_pagination.UserViewSet.as_view()),
]

# view.py
from rest_framework.views import APIView
from rest_framework import serializers
from .. import models

from rest_framework.pagination import PageNumberPagination, LimitOffsetPagination, CursorPagination


class StandardResultsSetPagination(CursorPagination):
    # URL传入的游标参数
    cursor_query_param = 'cursor'
    # 默认每页显示的数据条数
    page_size = 2
    # URL传入的每页显示条数的参数
    page_size_query_param = 'page_size'
    # 每页显示数据最大条数
    max_page_size = 1000

    # 根据ID从大到小排列
    ordering = "id"



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserInfo
        fields = "__all__"


class UserViewSet(APIView):
    def get(self, request, *args, **kwargs):
        user_list = models.UserInfo.objects.all().order_by('-id')

        # 实例化分页对象，获取数据库中的分页数据
        paginator = StandardResultsSetPagination()
        page_user_list = paginator.paginate_queryset(user_list, self.request, view=self)

        # 序列化对象
        serializer = UserSerializer(page_user_list, many=True)

        # 生成分页和数据
        response = paginator.get_paginated_response(serializer.data)
        return response
```

#### 渲染

我们需要哪一种格式，导入他的类，添加到renderer_classes里面，调用的时候url写响应的后缀就行了，比如.json等等，

```python
# url.py
urlpatterns = [
    # 格式化，后面的format表示支持.json格式的
    url(r'^pager/', views.PagerView.as_view(), name='bbb'),
    # 一定记住，必须要两个url一起用
    url(r'^render\.(?P<format>\w+)', views.RenderView.as_view(), name='bbb'),
]

from rest_framework.renderers import JSONRenderer, AdminRenderer, BrowsableAPIRenderer

class RenderView(APIView):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer]

    def get(self, request, *args, **kwargs):
        user_list = models.UserInfo.objects.all()
        ser = UserSerializers(instance=user_list, many=True)
        return Response(ser.data)
```

#### 问题

什么是rest api？

rest api实际上就是一组对API的约束条件和原则，URL需要有域名，版本，路径，函数，状态吗

### 如何保证API的安全？

我们在使用API提交或者获取数据的时候有可能被别人获取，并且进行获取数据和提交数据，如何进行有效的验证来避免吗？

解决：

参考tonado源码

1. 在维护一个key，这个key两端都有，自定义一个请求头，header={'auth-api':key}发送给主机，然后主机在request的header里面找到key然后对比，如果和自己的key一样的话，验证成功，

   > 注意，在自定义请求头的时候字母和字母之间用-链接，不能用下划线
   >
   > 主机取到的值为   request.META里面取到{"HTTP_AUTH_API": key}

2. 但是，这样的话请求头别人照样可以拿到，我们可以让这个key动态起来，也就是和时间配合，使用md5加密，将加密后的结果以及当时的时间添加到请求头中发送过去，然后主机里面有key，再加上请求头里面发送过来的时间同样进行md5，如果一样的话，就验证成功，

3. 但是如果这样的话我门会生成很多的被攻击的加密值，我门应该在服务端添加时间显示，比如10秒，在10秒以内的可以验证成功，在10秒意外的就不允许

4. 但是还是有问题，如果别人在很快的时间内获取API然后进行操作的话，还是挡不住，因此我门需要在服务端维护一个列表或者字典，如果一个请求访问过的话记录下来，如果下次又有一样的话，就拒绝访问