#coding=utf-8
from flask import Flask,request,session
from myapp.extension import socketio,db,login_manager,pagedown,moment,\
                            bootstrap,babel,admin,toolbar,mogodb,mail,photos
import flask_whooshalchemyplus
from flask_uploads import configure_uploads
from config import config,Config
from celery import  Celery
from flask_sslify import SSLify
import re
celery = Celery(__name__,backend=Config.CELERY_RESULT_BACKEND,broker=Config.CELERY_BROKER_URL)



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
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    pagedown.init_app(app)
    login_manager.init_app(app)
    admin.init_app(app)
    socketio.init_app(app)
    #toolbar.init_app(app)
    mogodb.init_app(app)
    celery.conf.update(app.config)
    flask_whooshalchemyplus.init_app(app)

    app.register_blueprint(main_blueprint)
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(socket_io_blueprint)
    app.register_blueprint(mongo_blueprint,url_prefix='/mongo')
    sslify = SSLify(app)
    return app


