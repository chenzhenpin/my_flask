#coding=utf-8
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_pagedown import PageDown
from flask_babelex import Babel
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_admin import Admin,AdminIndexView
from flask_debugtoolbar import DebugToolbarExtension
from flask_mongoengine import MongoEngine
from flask_uploads import UploadSet,IMAGES,VIEDO
from flask_mail import Mail


mail=Mail()
mogodb=MongoEngine()
pagedown = PageDown()
bootstrap = Bootstrap()
moment = Moment()
babel=Babel()
moment = Moment()
db=SQLAlchemy()
login_manager=LoginManager()
socketio=SocketIO()
toolbar=DebugToolbarExtension()
photos = UploadSet('photos',IMAGES)
videos=UploadSet('videos',VIEDO)
admin = Admin(
    index_view=AdminIndexView(
    name=u'导航',
    template='admin/welcome.html',
    url='/welcome'  #http://127.0.0.1:5000/welcome
    )
)

