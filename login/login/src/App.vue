<template>
  <div id="app">

    <router-link to="/index">首页</router-link>
    <router-link to="/course">课程</router-link>
    <router-link to="/degree">学位</router-link>
    <router-link to="/science">深科技</router-link>
    <router-link to="/">用户</router-link>

    <router-view/>



  </div>
</template>

<script>
export default {
  name: 'app'
}
</script>

<style>
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
