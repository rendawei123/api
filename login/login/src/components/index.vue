<template>
  <div class="hello">
    <div>{{msg}}</div>
    <div  v-for="item in arr">
      {{item.id}}
      <router-link :to="{path:'/course/detail/'+item.id}" key="item.id">
        {{item.name}}
      </router-link>
      课程周期：{{item.period}}周
    </div>


  </div>

</template>

<script>
  export default {
    name: 'index',
    data() {
      return {
        msg: 'index',
        arr: []
      }
    },
    mounted: function () {
      this.show_list()
    },
    methods: {
      show_list() {
        var url = 'http://127.0.0.1:8000/index/';
        var self = this;
        this.ajax.get(url).then(function (response) {
          self.arr = response.data.data;
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
