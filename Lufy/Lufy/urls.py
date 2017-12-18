"""Lufy URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from app01 import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    # 一般URL
    url(r'^user/', views.UserView.as_view()),
    # 版本url
    url(r'^(?P<version>[v1|v2]+)/version/', views.VersionView.as_view(), name='aaa'),
    # 用户登录url
    url(r'^auth/', views.AuthView.as_view(), name='bbb'),
    # 添加权限管理，对于普通用户让他进行用户管理，对于文艺用户让他即可以用户管理，也可以组管理
    # 用户管理，不允许匿名用户登录url
    url(r'^authentication/', views.AuthenticationView.as_view(), name='bbb'),
    # 组管理，
    url(r'^groups/', views.GroupView.as_view(), name='bbb'),
    # 解析器
    url(r'^parser/', views.ParserView.as_view(), name='bbb'),
    # 格式化，后面的format表示支持.json格式的
    url(r'^serializers\.(?P<format>\w+)', views.SerializersView.as_view(), name='bbb'),
    # 分页
    url(r'^pager/', views.PagerView.as_view(), name='bbb'),
    # 渲染
    url(r'^render/', views.RenderView.as_view(), name='bbb'),
    url(r'^render\.(?P<format>\w+)', views.RenderView.as_view(), name='bbb'),
    # url
    # 手动操作url
    # get查询列表
    url(r'^route/$', views.RenderView.as_view()),
    # url(r'^route\.(?P<format>\w+)/$', views.RenderView.as_view()),  # 可以加后缀
    # 获取单个数据，比如更新、删除、查询
    url(r'^route/(?P<pk>\d+)$', views.RenderView.as_view()),
    url(r'^route/(?P<pk>\d+)\.(?P<format>\w+)$', views.RenderView.as_view()),
]
