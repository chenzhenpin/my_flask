#coding=utf-8
import os
from datetime import timedelta
basedir = os.path.abspath(os.path.dirname(__file__))





class Config:
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'data.sqlite')
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SECRET_KEY='nice to me you'
    FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
    FLASKY_MAIL_SENDER = 'chenzhenpingz@163.com'
    FLASKY_ARTICLE_COMMENT_PER_PAGE=20
    FLASKY_POSTS_PER_PAGE=8 #配置查询文章分页的每页的额记录数
    FLASKY_COMMENTS_PER_PAGE=10 #配置查询评论分页的每页的额记录数
    FLASKY_FOLLOWERS_PER_PAGE=10

    MAX_SEARCH_RESULTS = 50 #Whoosh 返回数据的最多条数
    #celery配置
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    CELERY_TIMEZONE = 'Asia/Shanghai'
    CELERY_ENABLE_UTC = False  # 不是用UTC
    CELERYBEAT_SCHEDULE = {
        'add-every-2-seconds': {
            'task': 'tasks.used_apk_cdn',
            'schedule': timedelta(seconds=2),
            'args': (16, 10),
        },
    }

    #SERVER_NAME='onlysee.6655.la'

    MONGODB_DB='test'
    MONGODB_HOST='127.0.0.1'
    MONGODB_PORT=27017

    DEBUG_TB_PANELS=['flask.ext.mongoengine.panels.MongoDebugPanel']#Flask-DebugToolbar跟踪查询monogodb

    UPLOAD_FOLDER=os.path.join(basedir, r'uploads\img')

    # 比如文件储存地址设置：
    # UPLOADED_FILES_DEST = '/path/to/the/uploads'

    # 如果你的set叫photos，那么这条设置就改成：
    UPLOADED_PHOTOS_DEST = os.path.join(basedir, r'myapp/static')
    UPLOADED_VIDEOS_DEST = os.path.join(basedir, r'myapp/static')
    # 你也可以设置一个默认的配置：
    UPLOADS_DEFAULT_DEST = os.path.join(basedir, r'uploads')
    #启用缓慢查询记录功能的配置
    SQLALCHEMY_RECORD_QUERIES = True
    FLASKY_DB_QUERY_TIMEOUT = 0.5
    FLASKY_SLOW_DB_QUERY_TIME = 0.1
    #配置Flask-SSLify ，Ture不开启
    SSL_DISABLE = True


    #CELERY_TASK_SERIALIZER = 'json'# pickle
    # FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')
    # @staticmethod不需要表示自身对象的self和自身类的cls参数，就跟使用函数一样。
    @staticmethod
    def init_app(app):
        pass
class DevelopmentConfig(Config):
    DEBUG = True
    MAIL_SERVER = 'smtp.163.com'
    MAIL_PORT = 25
    MAIL_USE_TLS = True
    MAIL_USERNAME =  os.environ.get('MAIL_USERNAME') or 'chenzhenpingz@163.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or '74745656q'
    FLASKY_ADMIN='1940497838@qq.com'
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
    #                             'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')
    SQLALCHEMY_DATABASE_URI ='mysql://chenzhen:123456@localhost:3306/flask'


    #输出日志
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        import logging
        handler = logging.FileHandler('flask.log')
        app.logger.addHandler(handler)
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
                                'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')
class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                                'sqlite:///' + os.path.join(basedir, 'data.sqlite')
config = {
'development': DevelopmentConfig,
'testing': TestingConfig,
'production': ProductionConfig,
'default': DevelopmentConfig
}