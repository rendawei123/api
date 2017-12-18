import Vue from 'vue'
import Vuex from 'vuex'
import Cookie from 'vue-cookies'

Vue.use(Vuex)

export default new Vuex.Store({
  // 组件中通过 this.$store.state.username 调用
  state: {
  username: Cookie.get('user'),
  token: Cookie.get('user'),
  apiList: {
    auth: '',
    courses: '',
  }
  },
  mutations: {
  // 组件中通过 this.$store.commit(saveToken,参数)  调用
  saveToken: function (state, user, token) {
    state.username = user
    Cookie.set("user", user, "1min")
    Cookie.set("token", token, "1min")

  },
  clearToken: function (state) {
    state.username = null
    Cookie.remove('user')
    Cookie.remove('token')

  }
  },

})
