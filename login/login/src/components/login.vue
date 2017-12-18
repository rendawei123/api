<template>
  <div class="hello">
    <input type="text" v-model="username">
    <input type="password" v-model="password">
    <input type="button" value="登录" v-on:click="login">
    <p>{{msg}}{{token}}</p>
  </div>
</template>

<script>
import methods from "../../../../../../../Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/notebook/static/components/codemirror/src/edit/methods";

export default {
  name: 'HelloWorld',
  data () {
    return {
      msg: '',
      username: '',
      password: '',
      token: ''
    }
  },
  methods: {

    login: function () {
      let self = this;
      let url = 'http://127.0.0.1:8000/login/';
      this.ajax.post(url,{
        name:this.username,
        password:this.password
      },{
        "headers":{"Content-Type": "application/x-www-form-urlencoded"}
      }).then(function(response){
        self.msg = response.data.msg;
        self.token = response.data.token;
        if (response.data.code === 1000){
          self.error = response.data.msg
        }
        else if (response.data.code === 1001){
          self.$store.commit('saveToken', response.data.username, response.data.token);
          console.log(response.data.username);
          self.$router.push('/index')
//          let backUrl = self.$route.query.backurl;
//          if (backUrl){
//            self.$route.push({path: backUrl})
////            self.$route.push('/index')
//          } else {
//            self.$route.push('/index')
//          }
        }
      }).catch(function(error){

      })
    }
  }

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
