#coding=utf-8
from flask import Flask,request,session
from myapp.extension import socketio,db,login_manager,pagedown,moment,\
                            bootstrap,babel,admin,toolbar,mogodb,mail,photos,videos,celery,filecache
import flask_whooshalchemyplus
from flask_uploads import configure_uploads
from config import config,Config
from myapp.defs import cn_to_utc,utc_to_cn
from flask_sslify import SSLify
import re




#setup_periodic_tasks()

login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'


def create_app(config_name):
    from .main import main as main_blueprint
    from .auth import auth as auth_blueprint
    from .mongo import mongo as mongo_blueprint
    from .socket_io import socket_io as socket_io_blueprint
    app = Flask(__name__)
    #判断客户端是否是手机
    @app.before_request
    def before_first_request():
        User_Agent = request.headers['User-Agent']
        is_mobile = re.findall('Mobile', User_Agent)
        if is_mobile:
             session['mobile_flags'] = 1
        else:
            session['mobile_flags']=0
    app.config['BABEL_DEFAULT_LOCALE']='zh_CN'
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    babel.init_app(app)
    bootstrap.init_app(app)
    configure_uploads(app, photos)
    configure_uploads(app, videos)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    pagedown.init_app(app)
    login_manager.init_app(app)
    admin.init_app(app)
    socketio.init_app(app)
    filecache.init_app(app)
    #toolbar.init_app(app)
    mogodb.init_app(app)
    celery.conf.update(app.config)
    flask_whooshalchemyplus.init_app(app)

    app.register_blueprint(main_blueprint)
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(socket_io_blueprint)
    app.register_blueprint(mongo_blueprint,url_prefix='/mongo')
    sslify = SSLify(app)

    #自定义过滤器截取字符数
    @app.template_filter('filter')
    def filter(s):
        return s[0:300]

    @app.template_filter('utctime')
    def utctime(s):
        utctime=cn_to_utc(s)
        return utctime

    @app.template_filter('nowtime')
    def nowtime(s):
        nowtime=utc_to_cn(s)
        return nowtime
    # 或者
    # def filter(s):
    #     return s[0:300]
    # app.jinja_env.filters['filter'] = filter

    #添加jiaja2循环扩展支持break,continue
    app.jinja_env.add_extension('jinja2.ext.loopcontrols')
    return app


