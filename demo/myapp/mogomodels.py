#coding=utf-8
from myapp.extension import mogodb
from datetime import datetime
from flask import url_for

class Todo(mogodb.Document):
    meta = {
        'collection': 'todo',
        'ordering': ['-create_at'],
        'strict': False,
    }

    task = mogodb.StringField()
    create_at = mogodb.DateTimeField(default=datetime.now)
    is_completed = mogodb.BooleanField(default=False)




class Comment(mogodb.EmbeddedDocument):
    created_at = mogodb.DateTimeField(default=datetime.now, required=True)
    body = mogodb.StringField(verbose_name="Comment", required=True)
    author = mogodb.StringField(verbose_name="Name", max_length=255, required=True)
class Post(mogodb.Document):
    created_at = mogodb.DateTimeField(default=datetime.now, required=True)
    title = mogodb.StringField(max_length=255, required=True)
    slug = mogodb.StringField(max_length=255, required=True)
    body = mogodb.StringField(required=True)
    categories = mogodb.ReferenceField((Todo), required = True)#引用字段，存储一个Todo实例
    comments = mogodb.ListField(mogodb.EmbeddedDocumentField(Comment))# 嵌入字段，可以存储多个Comment实例，Comment模型必须在Post模型的前面声明
    def get_absolute_url(self):
        return url_for('post', kwargs={"slug": self.slug})
    def __unicode__(self):
        return self.title
    meta = {
        'allow_inheritance': True,
        'indexes': ['-created_at', 'slug'],
        'ordering': ['-created_at']
    }
class Context(mogodb.Document):
    created_at = mogodb.DateTimeField(default=datetime.now, required=True)
    context=mogodb.StringField(required=True)




#文档
# #添加>>> post = Post(
# ... title="Hello World!",
# ... slug="hello-world",
# ... body="Welcome to my new shiny Tumble log powered by MongoDB, MongoEngine, and Flask"
# ... )
# >>> post.save()
# >>> comment = Comment(
# ... author="Joe Bloggs",
# ... body="Great post! I'm looking forward to reading your blog!"
# ... )
# >>> post.comments.append(comment)
# >>> post.save()
# >>> comment = Comment(
# ... author="Joe Bloggs",
# ... body="Great post! I'm looking forward to reading your blog!"
# ... )
#查询posts=Post.objects.all()
# for post in posts ：
#     post.body

#查询post=Post.objects(slug="hello-world").first()
# post.body
#更新
#post.update(title='meet you')
#删除post.delete()
#分页skip_nums = 1
# limit = 3
# todos = Todo.objects().order_by(
#     '-create_at'
# ).skip(
#     skip_nums
# ).limit(
#     limit
# )
#使用 paginate() 方法
# def view_todos(page=1):
#     todos = Todo.objects.paginate(page=page, per_page=10)

