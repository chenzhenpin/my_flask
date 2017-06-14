#coding=utf-8
from flask_admin import  BaseView, expose
from flask import url_for
from flask_login import current_user
from flask_admin.contrib.sqla import ModelView
from ..models import Post
from myapp.extension import db
import os as op
from myapp.extension import admin
from flask_admin.contrib.fileadmin import FileAdmin




class MyView(BaseView):
    #改函数返回真才能访问该导航
    def is_accessible(self):
        return current_user.is_authenticated  #用户登录返回真。
    # http://127.0.0.1:5000/welcome/my/
    @expose('/')
    def index(self):
        url = url_for('.view')
        return self.render('admin/home.html',url=url)
    #http://127.0.0.1:5000/welcome/my/view
    @expose('/view')
    def view(self):
        return self.render('admin/view.html')

class hello1(BaseView):
    # http://127.0.0.1:5000/welcome/test1/
    @expose('/')
    def index(self):
        return self.render('admin/hello1.html')
class hello2(BaseView):
    # http://127.0.0.1:5000/welcome/test2/
    @expose('/')
    def index(self):
        return self.render('admin/hello2.html')
class hello3(BaseView):
    # http://127.0.0.1:5000/welcome/test3/
    @expose('/')
    def index(self):
        url = url_for('my.view') #MyView.view函数
        return self.render('admin/hello3.html',url=url)





class UserView(BaseView):
    #改函数返回真才能访问该导航
    def is_accessible(self):
        return current_user.is_authenticated  #用户登录返回真。
    # http://127.0.0.1:5000/welcome/my/
    @expose('/')
    def index(self):
        url = url_for('.view')
        return self.render('admin/home.html',url=url)
    #http://127.0.0.1:5000/welcome/my/view
    @expose('/view')
    def view(self):
        return self.render('admin/view.html')

class MyV1(ModelView):
    def is_accessible(self):
        if current_user.is_authenticated :
            return True
        return False
    can_create = False

    column_labels = {
        'id':u'序号',
        'body' : u'文章',
        'timestamp':u'发布时间',
        'author_id':u'作者id'
    }
    column_list = ('id', 'body','timestamp','author_id')
    def __init__(self, session, **kwargs):
        super(MyV1, self).__init__(Post,session, **kwargs)



admin.add_view(MyView(name='新闻',endpoint='my'))
admin.add_view(hello1(name='Hello 1', endpoint='test1', category='信息'))
admin.add_view(hello2(name='Hello 2', endpoint='test2', category='信息'))
admin.add_view(hello3(name='Hello 3', endpoint='test3', category='信息'))
path = op.join(op.dirname(__file__), '../static/img')
print(path)
admin.add_view(FileAdmin(path, '/static/', name='文件',endpoint='file'))
admin.add_view(MyV1(db.session, name=u'管理新闻'))