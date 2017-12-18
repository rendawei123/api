from django.utils.deprecation import MiddlewareMixin


class M1(MiddlewareMixin):

    # 方法和参数必须要按照人家的规定的写
    # def process_request(self, request):
    #     print('process_request')  # 注意，request没有返回值

    def process_response(self, request, response):
        response['Access-Control-Allow-Origin'] = '*'
        return response