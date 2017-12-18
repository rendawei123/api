import Vue from 'vue'
import Router from 'vue-router'
import HelloWorld from '@/components/HelloWorld'
import course from '@/components/course'
import index from '@/components/index'
import degree from '@/components/degree'
import science from '@/components/science'
import login from '@/components/login'
import detail from '@/components/detail'

Vue.use(Router)

export default new Router({
  routes: [
    {
      path: '/',
      name: 'HelloWorld',
      component: HelloWorld
    },
    {
      path: '/login',
      name: 'login',
      component: login
    },
    {
      path: '/index',
      name: 'index',
      component: index
    },
    {
      path: '/course',
      name: 'course',
      component: course
    },
    {
      path: '/degree',
      name: 'degree',
      component: degree
    },
    {
      path: '/science',
      name: 'science',
      component: science
    },
    {
      path: '/course/detail/:id',
      name: 'detail',
      component: detail
    }
  ]
})
