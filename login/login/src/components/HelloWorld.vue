<template>

  <div class="hello">
    <h1>{{msg}}</h1>
    <div v-if="this.$store.state.username">
      {{ this.$store.state.username}}
      <button @click="clickme">注销</button>
    </div>
    <router-link v-else to="/login">登录</router-link>
  </div>

</template>

<script>
export default {
  name: 'HelloWorld',
  data () {
    return {
      msg: 'Welcome to Your Luffy'
    }
  },
  methods:{
    clickme:function () {
      this.$store.commit('clearToken')
    }
  },
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h1, h2 {
  font-weight: normal;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}
</style>
