#coding=utf-8
from flask import render_template, redirect, request, url_for, flash,session,Response,current_app,jsonify,send_from_directory,abort
from . import auth
from ..models import User,File
from ..mogomodels import Context
from .forms import RegistrationForm ,LoginForm,ChangePasswordForm,PasswordResetRequestForm,PasswordResetForm,ChangeEmailForm
from .. import db
from ..celery_email import send_email
from flask_login import logout_user, login_required,current_user,login_user
from flask_uploads import  patch_request_class
from ..extension import photos,videos
from ..defs import datedir
import time,datetime
import os
#过滤未确认账户的用户

# @auth.before_app_request
# def before_request():
#     if current_user.is_authenticated:
#         current_user.ping() #更新最后登录时间
#         if not current_user.confirmed \
#             and request.endpoint[:5] != 'auth.':
#             return redirect(url_for('auth.unconfirmed'))



@auth.route('/      ', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            #该函数标记用户已经登陆，第二参数为布尔型，False值关闭浏览器则会话过期
            login_user(user, form.remember_me.data)
            # Flask - Login会把原地址保存在查询字符串的next参数中，这个参数可从request.args字典中读取。
            # 如果查询字符串中没有next参数，则重定向到首页。
            # 比如查看一个需要登陆的路由会跳转到登陆页面，登陆后则会跳转到之前的地址
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        user=User.query.filter_by(username=form.username.data).first()
        user.user_init()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    #current_user为当前用户对象
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

#重新发送确认账户信息
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm ',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.'+current_user.email+'Confirm Your Account')
    return redirect(url_for('main.index'))

#修改密码
@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            flash('Your password has been updated.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template("auth/change_password.html", form=form)
#重设密码发送令牌表给邮箱
@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
        flash('An email with instructions to reset your password has been '
              'sent to you.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

#重置密码
@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)

#发送修改邮箱令牌
@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, 'Confirm your email address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash('An email with instructions to confirm your new email '
                  'address has been sent to you.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template("auth/change_email.html", form=form)
#修改邮箱
@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('Your email address has been updated.')
    else:
        flash('Invalid request.')
    return redirect(url_for('main.index'))




# @auth.route('/edit',methods=['GET', 'POST'])
# def edit():
#     # session['img_token']=random.random(0,9999)
#     form=EditPostForm()
#     if form.validate_on_submit():
#         data=form.context.data
#         context=Context(context=data )
#         if context.save():
#             return 'ok'
#     return render_template("wangeditor/edit.html",form=form)


# @auth.route('/show',methods=['GET', 'POST'])
# def show():
#     # session['img_token'] = random.random(0, 9999)
#     data=Context.objects.first()
#     form = EditPostForm()
#     print(type(data))
#     print(data.context)
#     if form.validate_on_submit():
#         data = form.context.data
#         context = Context(context=data)
#         if context.save():
#             return 'ok'
#     return render_template("wangeditor/edit.html", form=form,data=data)
#
# ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

# #文件名合法性验证
# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS
#对文件上传进行相应
@auth.route("/upimage",methods = ["POST"])
def upimage():

    app = current_app._get_current_object()
    year = time.strftime('%Y', time.localtime(time.time()))
    # 月份
    month = time.strftime('%m', time.localtime(time.time()))
    name = str(time.time())[6:10] + str(time.time())[11:]
    filename = photos.save(request.files['myFileName'],'uploads/images/'+year+'/'+month,name=name+'.')
    patch_request_class(app, 16 * 1024 * 1024)#限制大小
    file_url = photos.url(filename)
    if filename == None:
        result = r"error|未成功获取文件，上传失败"
        res = Response(result)
        res.headers["ContentType"] = "text/html"
        res.headers["Charset"] = "utf-8"
        return res
    else:
        print(file_url)
        res = Response(file_url)
        res.headers["ContentType"] = "text/html"
        res.headers["Charset"] = "utf-8"
        return res



#对文件上传进行相应
@auth.route("/uploadfile",methods = ["POST"])
@login_required
def uploadfile():
    file_url=''
    app = current_app._get_current_object()

    year = time.strftime('%Y', time.localtime(time.time()))
    # 月份
    month = time.strftime('%m', time.localtime(time.time()))
    # 日期
    day = time.strftime('%d', time.localtime(time.time()))
    files=request.files.getlist("uploadfile")
    uid=request.form.get('uid',0)
    for file in files:
        file_name=file.filename
        print(file_name)

        name=str(time.time())[6:10]+str(time.time())[11:]
        if uid=='1':
            #修改save源码 extension,支持中文文件名称
            pathname = photos.save(file, 'uploads/img/'+year+'/'+month+'/'+day, name=name + '.')
            patch_request_class(app, 10 * 1024 * 1024)  # 限制大小10MB
            # file_url = photos.url(pathname)
            file_path = photos.path(pathname)
            file=File(user_id=current_user.id, file_path=file_path, file_url=pathname, file_name=file_name, cls=uid)
            db.session.add(file)

        if uid=='2':
            pathname = videos.save(file, 'uploads/video/'+year + '/' + month + '/' + day, name=name + '.')
            patch_request_class(app, 200 * 1024 * 1024)  # 限制大小80MB
            # file_url = videos.url(pathname)
            file_path = photos.path(pathname)
            file=File(user_id=current_user.id,file_path=file_path,file_url=pathname,file_name=file_name,cls=uid)
            db.session.add(file)
        #filename=filepath.split('/')[1]
        #获取文件绝对路径
        # file_path = photos.path(filename)
        # dir_name,file_name=os.path.split(file_path)
        # url_name=send_from_directory(dir_name,file_name)
        # print(dir_name)
        # print(url_name)

    if pathname == None:
        return jsonify({'status': '0', 'msg': '上传失败'})
    else:
        import urllib
        return jsonify({'status':'1','msg':'上传成功','file_url':pathname})
        # res = Response(file_url)
        # res.headers["ContentType"] = "text/html"
        # res.headers["Charset"] = "utf-8"
        # return res

#跨域名装饰器

# from functools import wraps
# from flask import make_response
#
#
# def allow_cross_domain(fun):
#     @wraps(fun)
#     def wrapper_fun(*args, **kwargs):
#         rst = make_response(fun(*args, **kwargs))
#         rst.headers['Access-Control-Allow-Origin'] = '*'
#         rst.headers['Access-Control-Allow-Methods'] = 'PUT,GET,POST,DELETE'
#         allow_headers = "Referer,Accept,Origin,User-Agent"
#         rst.headers['Access-Control-Allow-Headers'] = allow_headers
#         return rst
#     return wrapper_fun
#
#
#
# @app.route('/hosts/')
# @allow_cross_domain
# def domains():
#     pass