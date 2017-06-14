#coding=utf-8
from flask import Flask,render_template,session,redirect,url_for
from flask.ext.bootstrap import Bootstrap
from flask.ext.moment import Moment
from datetime import datetime,date
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField,DateField
from wtforms.validators import Required
from flask.ext.sqlalchemy import SQLAlchemy
import os
from flask.ext.script import Manager,Shell
from flask.ext.migrate import Migrate, MigrateCommand
from threading import Thread
from flask_mail import Mail
from flask.ext.mail import Message


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'
bootstrap = Bootstrap(app)
moment = Moment(app)
manager=Manager(app)
mail=Mail(app)
#邮箱配置
app.config['MAIL_SERVER'] = 'smtp.163.com'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'chenzhenpingz@163.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or '74745656q'
FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
app.config['FLASKY_ADMIN']='1940497838@qq.com'

#数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True #每次提交都更新数据库
db = SQLAlchemy(app)
#数据库迁移
#python hello.py db init该命令创建迁移仓库
#python hello.py db migrate -m "initial migration"该命令自动创建迁移脚本
#python hello.py db upgrade 更新
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)


#定义数据库模型
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    #db.relationship() 中的 backref 参数向 User 模型中添加一个 role 属性，该属性的值为Role对象。
    users = db.relationship('User', backref='role')
    #返回该模型的信息
    def __repr__(self):
        return '<Role %r>' % self.name
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    #定义外键对应roles表的id字段
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    def __repr__(self):
        return '<User %r>' % self.username
#定义表单
class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
   # date=DateField('日期')
    submit = SubmitField('Submit')

#为shell命令定义回调函数，自动导入模块
def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)
manager.add_command("shell", Shell(make_context=make_shell_context))

#邮箱
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):

    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr

@app.route('/',methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        name=User.query.filter_by(username=form.name.data).first()
        if name is None :
            user=User(username=form.name.data)
            db.session.add(user)
            db.session.commit()
            session['known'] = False
            if app.config['FLASKY_ADMIN']:
                send_email(app.config['FLASKY_ADMIN'], 'New User',
                           'mail/new_user', user=user)
        else:
            session['known']=True
            form.name.data = ''
        session['name'] = form.name.data
        return redirect(url_for('index'))
    return render_template('index.html',
                           current_time=datetime.utcnow(),time=date(1991,9,1), form=form,
                           name = session.get('name'),known = session.get('known', False))
@app.route('/user/<name>')
def user(name):
    return render_template('user.html', name=name)
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
if __name__ == '__main__':
    manager.run()
    #myapp.run(debug=True)