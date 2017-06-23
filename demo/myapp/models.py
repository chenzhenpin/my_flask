#coding=utf-8
import hashlib
from flask_login import UserMixin,AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from datetime import datetime
from markdown import markdown
import bleach
from jieba.analyse.analyzer import ChineseAnalyzer
from myapp.extension import db,login_manager


class Role(db.Model,UserMixin):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    #db.relationship() 中的 backref 参数向 User 模型中添加一个 role 属性，该属性的值为Role对象。
    users = db.relationship('User', backref='role')


    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()
    #返回该模型的信息
    def __repr__(self):
        return '<Role %r>' % self.name

#该模型要定义在User模型之前否则执行脚本会出错
class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))#评论的作者
    by_user_id=db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
        'strong']
        target.body_html = bleach.linkify(bleach.clean(
        markdown(value, output_format='html'),
        tags=allowed_tags, strip=True))
    #返回被点评论文章的用户
    @property
    def post_user(self):
        # return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
        #     .filter(Follow.follower_id == self.id)
        return User.query.join(Post, Post.id == User.id).filter(Post.id == self.post_id)

db.event.listen(Comment.body, 'set', Comment.on_changed_body)

class Heart(db.Model):
    __tablename__ = 'hearts'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # 被点赞的用户id
    by_user_id=db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    #返回被点赞的文章用户
    @property
    def post_user(self):
        # return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
        #     .filter(Follow.follower_id == self.id)
        return User.query.join(Post, Post.id == User.id).filter(Post.id == self.post_id)

class User(db.Model,UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)#用户名
    password_hash = db.Column(db.String(128))
    #定义外键对应roles表的id字段
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    #该字段用来确认账户
    confirmed = db.Column(db.Boolean, default=False)
    avatar_hash = db.Column(db.String(32))

    name = db.Column(db.String(64))#用户姓名
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow) #注册时间
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow) #最后访问时间
    img=db.Column(db.LargeBinary(length=100000))
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    #一个模型定义的多个外键都在同另一个模型中，Follow，Comment，Heart都应该定义到User模型的前面否则会有错
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    comments = db.relationship('Comment',
                               foreign_keys=[Comment.author_id],
                               backref=db.backref('author',lazy='joined'),
                               lazy='dynamic',cascade='all, delete-orphan')
    by_comments = db.relationship('Comment',
                                  foreign_keys=[Comment.by_user_id],
                                  backref=db.backref('by_user',lazy='joined'),
                                  lazy='dynamic',cascade='all, delete-orphan')

    hearts    =db.relationship('Heart',
                               foreign_keys=[Heart.user_id],
                               backref=db.backref('user',lazy='joined'),
                               lazy='dynamic',cascade='all, delete-orphan')
    by_hearts= db.relationship('Heart',
                               foreign_keys=[Heart.by_user_id],
                               backref=db.backref('by_user',lazy='joined'),
                               lazy='dynamic',cascade='all, delete-orphan')
    #comments = db.relationship('Whoosh', backref='author', lazy='dynamic')

    def __init__(self,**kwargs):
        super(User,self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
        if self.role is None:
            self.role = Role.query.filter_by(default=True).first()
        self.follow(self)#自己关注自己
    #确认账户
    #生成令牌
    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})
    #确认令牌
    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    #密码加密
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    #生成重置密码令牌方法
    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})
    #重置密码方法
    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True
    #生成发送修改邮箱令牌
    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})
    #校验生成邮箱令牌
    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True
    #验证是否拥有某权限
    def can(self, permissions):
        return self.role is not None and \
               (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
    #更新最后访问时间
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    #生成测试数据
    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError

        from random import seed
        import forgery_py
        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    # 添加关注
    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    # 删除关注
    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)
    #获取关注者的文章
    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
            .filter(Follow.follower_id == self.id)

    # 是否关注某人
    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id).first() is not None

    # 是否被某人关注
    def is_followed_by(self, user):
        return self.followers.filter_by(
            follower_id=user.id).first() is not None
    #自己关注自己
    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    #返回模型信息
    def __repr__(self):
        return '<User %r>' % self.username

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    cls=db.Column(db.Integer,default=1)
    file_urls=db.Column(db.String)
    disabled = db.Column(db.Boolean)
    views=db.Column(db.Integer,default=0)
    hearts=db.relationship('Heart', backref='post', lazy='dynamic')
    timestamp = db.Column(db.DateTime(), index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    # 生成测试数据
    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py
        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
                 timestamp=forgery_py.date.date(True),
                 author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']

        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))
    #获取点赞的用户
    @property
    def hearts_user(self):
        # return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
        #     .filter(Follow.follower_id == self.id)
        return User.query.join(Heart,Heart.user_id==User.id).filter(Heart.post_id==self.id)
    #返回点赞的用户username字符串
    @property
    def hearts_username(self):
        # return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
        #     .filter(Follow.follower_id == self.id)
        users= User.query.join(Heart,Heart.user_id==User.id).filter(Heart.post_id==self.id)
        hearts_listname=[]
        for user in users:
            hearts_listname.append(user.username)
        return hearts_listname
db.event.listen(Post.body, 'set', Post.on_changed_body) #Post.body字段值改变会自动调用Post.on_changed_body函数




class Whoosh(db.Model):
    __searchable__ = ['body']
    __analyzer__ = ChineseAnalyzer()
    id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    def __repr__(self):
        return '<Whoosh %r>' % (self.body)


















class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80
#验证未登录用户的权限
class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
    def is_administrator(self):
        return False
#重新定义未登录的用户
login_manager.anonymous_user = AnonymousUser




#加载用户登陆的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


