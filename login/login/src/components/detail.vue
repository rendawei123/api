<template>

  <div class="hello">
    <p>{{msg}}</p>
    <p>课程id：{{ this.$route.params.id }}</p>
    <p>课程名称：{{ course_name }}</p>
    <p>课程标语：{{ course_slogan }}</p>
    <p>课程时长：{{ course_hour }}</p>
    <p>课程id：{{ course_id }}</p>
    <div>
      课程价格：<ul>
      <li v-for="item in price_policy_list">课程价格：{{item.price}}¥ 课程时长：{{item.period}}h</li>
    </ul>
    </div>
  </div>

</template>

<script>
export default {
  name: 'detail',
  data () {
    return {
      msg: '课程详细',
      course_name: '',
      course_slogan: '',
      course_hour: '',
      course_id: '',
      price_policy_list: ''
    }
  },
mounted:function () {
  this.show_detail()
},
  methods:{
  show_detail:function () {
    var url = 'http://127.0.0.1:8000/index/' + this.$route.params.id;
    var self = this;
    this.ajax.get(url).then(function (response) {
      self.detail = response.data.data;
      self.course_name = self.detail.course_name;
      self.course_slogan = self.detail.course_slogan;
      self.course_hour = self.detail.hours;
      self.course_id = self.detail.id;
      self.price_policy_list = self.detail.course_price_policy;
    })
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
