#coding=utf-8
from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField,TextAreaField
from wtforms.validators import Required, Length, Email,Regexp,EqualTo
from wtforms import ValidationError
from ..models import User
class  LoginForm(Form):
    email = StringField('邮箱', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('密码', validators=[Required()])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登录')
class RegistrationForm(Form):
    email = StringField('邮箱', validators=[Required(), Length(1, 64),
    Email()])

    # username = StringField('Username', validators=[Required(), Length(1, 32),])
    username = StringField('账号', validators=[Required(), Length(1, 64),
                                                   Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                    '账号只允许英文字母和数字')])
    password = PasswordField('密码', validators=[
    Required(), EqualTo('password2', message='两次输入的密码不一样')])
    password2 = PasswordField('确认密码', validators=[Required()])
    submit = SubmitField('注册')
    #自定义email字段的验证函数
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已被注册')
    #自定义username字段的验证函数
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('改账号已被注册')

class ChangePasswordForm(Form):
    old_password = PasswordField('Old password', validators=[Required()])
    password = PasswordField('New password', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm new password', validators=[Required()])
    submit = SubmitField('Update Password')

#重设密码发送令牌表给邮箱表单
class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('Reset Password')

#密码重置表单
class PasswordResetForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('New Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Reset Password')
#修改密码表单
class ChangeEmailForm(Form):
    email = StringField('New Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

# class EditPostForm(Form):
#     context=TextAreaField('context')
#     submit = SubmitField('发表')





