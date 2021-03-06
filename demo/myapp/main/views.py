#coding=utf-8
from time import sleep
from flask import render_template, redirect, url_for,request,flash,abort,current_app,make_response,jsonify,session
from flask.ext.sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm,EditProfileAdminForm,PostForm,EditArticleForm,SearchArticleForm
from .. import db
from flask_login import login_required,current_user
from ..models import User,Role,Post,Comment,Whoosh,Permission,Heart,Article,Collect,Follow
from ..celery_email import sub
from ..decorators import admin_required, permission_required
from ..defs import datedir
import os,shutil
from ..extension import photos,filecache
import bleach
from markdown import markdown
#报告缓慢的数据库查询
@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASKY_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
            'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n' %(query.statement, query.parameters, query.duration,query.context))
    return response

# @main.route('/test')
# def test():
#     r=sub.delay()
#     print(r.result)
#     print(r.successful())
#     print(r.backend)
#     i=0
#     while r.successful()==False:
#         i=i+1
#         sleep(4)
#         print(i)
#     return r.status

@main.route('/is_admin')
@login_required
@admin_required
def for_admins_only():
    return "For administrators!"

@main.route('/moderator')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def for_moderators_only():
    return "For comment moderators!"

@main.route('/user/<username>')
def user(username):

    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    user_flag =(request.cookies.get('user_flag', '1'))
    print(user_flag)
    page=request.args.get('page',1,type=int)
    if user_flag=='2':
        pagination=user.articles.filter(Article.disabled!=2).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        articles = pagination.items
        return render_template('user.html', user=user,articles=articles,user_flag=user_flag,pagination=pagination)
    if user_flag=='3':
        pagination=Article.query.join(Collect,Collect.user_id==user.id).filter(Article.id==Collect.article_id).filter(Article.disabled!=2).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        articles = pagination.items
        return render_template('user.html', user=user,articles=articles,user_flag=user_flag,pagination=pagination)
    user_flag ='1'
    pagination=user.posts.paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('user.html', user=user, posts=posts, user_flag=user_flag, pagination=pagination)

@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        current_user.img=form.img.data
        db.session.add(current_user)
        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    form.img.data=current_user.img
    return render_template('edit_profile.html', form=form)

@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)
@main.route('/user_img')
@login_required
def user_img():
    img  = User.query.filter_by(id=current_user.id).first()
    return img.img

@main.route('/img/<username>')
def img(username):
    try:
        img  = User.query.filter_by(username=username).first()
    except:
        pass
    else:img  = User.query.filter_by(username='chen').first()
    return img.img


@main.route('/', methods=['GET', 'POST'])
#@filecache.memoize(timeout=50)
def index():
    form = PostForm()
    # current_app.logger.debug('A value for debugging')
    # current_app.logger.warning('A warning occurred (%d apples)', 42)
    # current_app.logger.error('An error occurred')

    if current_user.can(Permission.WRITE_ARTICLES) and \
    form.validate_on_submit():
        if form.cls.data=='':
            form.cls.data=None
        post = Post(body=form.body.data,author=current_user._get_current_object(),file_urls=form.file_urls.data,cls=form.cls.data)
        db.session.add(post)

        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.followed_posts
    else:
        query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items

    if session.get('mobile_flags',None):
        return render_template('index.html', form=form, posts=posts,
                               show_followed=show_followed, pagination=pagination)
    return render_template('index.html', form=form, posts=posts,
                           show_followed=show_followed, pagination=pagination)
@main.route('/articles', methods=['GET','POST'])
def articles():
    form=SearchArticleForm()
    page = request.args.get('page', 1, type=int)
    print ('1')



    show_article_followed = False
    if current_user.is_authenticated:
        show_article_followed = bool(request.cookies.get('show_article_followed', ''))


    #搜索部分
    if form.validate_on_submit():
        pagination=Article.query.whoosh_search(form.keyword.data.strip())\
            .order_by(Article.timestamp.desc()).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        articles = pagination.items
        return render_template('articles.html', show_followed=show_followed, form=form,
                               articles=articles, pagination=pagination)

    if show_article_followed:
        query = current_user.follwed_articles
    else:
        query = Article.query
    query=query.filter(Article.disabled==0)
    pagination = query.order_by(Article.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    articles = pagination.items

    return render_template('articles.html',show_article_followed=show_article_followed,form=form,
                           articles=articles,pagination=pagination)
@main.route('/article/<int:id>',methods=['GET','POST'])
def article(id):
    page = request.args.get('page', 1, type=int)
    article=Article.query.filter_by(id=id).first()
    article.add_views
    pagination=Comment.query.filter_by(article=article).order_by(Comment.timestamp.desc()).paginate(
        page,per_page=current_app.config['FLASKY_ARTICLE_COMMENT_PER_PAGE'],error_out=False
    )
    comments = pagination.items
    if request.method=='POST' and \
        current_user.can(Permission.WRITE_ARTICLES):
        body=request.form.get('body')
        comment=Comment(body=body,author=current_user._get_current_object(),\
               article_id=article.id)
        db.session.add(comment)
        return redirect(url_for('.article',id=article.id))
    return render_template('article.html',article=article,comments=comments,pagination=pagination)


@main.route('/edit/article', methods=['GET', 'POST'])
@login_required
def edit_article():
    form=EditArticleForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
        form.validate_on_submit():
        # #过滤script标签
        # allowed_tags = ['script']
        # body=bleach.linkify(bleach.clean(markdown(form.body.data, output_format='html'), tags=allowed_tags, strip=False))
        article=Article(body=form.body.data,title=form.title.data.strip(),author=current_user._get_current_object())
        db.session.add(article)
        return redirect(url_for('.articles'))
    return render_template('edit_article.html',form=form)
#编辑文章
@main.route('/update/article/<int:id>', methods=['GET', 'POST'])
@login_required
def update_article(id):
    article = Article.query.get_or_404(id)
    if current_user != article.author :
        abort(403)
    form = EditArticleForm()
    if form.validate_on_submit():
        article.body = form.body.data
        article.title=form.title.data
        db.session.add(article)
        flash('The post has been updated.')
        return redirect(url_for('.article', id=article.id))
    form.title.data=article.title
    form.body.data = article.body
    return render_template('update_article.html', form=form,id=article.id)
@main.route('/delete/article/<int:id>',methods=['GET','POST'])
@login_required
def delete_article(id):
    article=Article.query.get_or_404(id)
    if current_user !=article.author :
        abort(403)
    article.disabled=2
    db.session.add(article)
    return redirect(url_for('.articles'))
@main.route('/disabled/article/<int:id>')
def disabled_article(id):
    article=Article.query.get_or_404(id)
    print (article.disabled+1000)
    if article.author!=current_user :
        abort(404)
    if article.disabled==0:
        article.disabled=1
        db.session.add(article)
        db.session.commit()
    elif article.disabled==1:
        article.disabled=0
        db.session.add(article)
        db.session.commit()
    print (article.disabled+1000)
    return redirect(url_for('.user',username=article.author.username))





#取消关注路由
@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))
#添加关注路由
@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('该用户不存在')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('你已经关注该用户')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('你成功关注了 %s.' % username)
    return redirect(url_for('.user', username=username))
#查看被关注列表
@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('该用户不存在')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('followers.html', user=user, title="Followers of",
    endpoint='.followers', pagination=pagination,
    follows=follows)

@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)
#所有动态
@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp

#只展示关注者的动态
@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp

#所有文章
@main.route('/article/all')
def show_article_all():
    resp = make_response(redirect(url_for('.articles')))
    resp.set_cookie('show_article_followed', '', max_age=30*24*60*60)
    return resp
#关注着文章
@main.route('/article/followed')
@login_required
def show_article_followed():
    resp = make_response(redirect(url_for('.articles')))
    resp.set_cookie('show_article_followed', '1', max_age=30*24*60*60)
    return resp

@main.route('/user_post/<username>')
def user_post(username):
    resp = make_response(redirect(url_for('.user',username=username)))
    resp.set_cookie('user_flag', '1', max_age=30*24*60*60)
    return resp

@main.route('/user_article/<username>')
def user_article(username):
    resp = make_response(redirect(url_for('.user',username=username)))
    resp.set_cookie('user_flag', '2', max_age=30*24*60*60)
    return resp

@main.route('/user_collect/<username>')
def user_collect(username):

    resp = make_response(redirect(url_for('.user', username=username)))
    if current_user._get_current_object().username==username:
        resp.set_cookie('user_flag', '3', max_age=30 * 24 * 60 * 60)
    else:
        resp.set_cookie('user_flag', '1', max_age=30 * 24 * 60 * 60)


    return resp

#评论
@main.route('/post/<int:id>', methods=['GET', 'POST'])
@login_required
def post(id):
    post = Post.query.get_or_404(id)
    # form = CommentForm()
    if request.method=='POST':
        by_user_id = request.form.get('by_user_id', None, type=int)
        body = request.form.get('body', None, type=str)
        by_user=User.query.get_or_404(by_user_id)
        if by_user_id is None or body is None:
            flash('评论失败')
            return 'false'
        comment = Comment(body=body,
                          post=post,
                          author=current_user._get_current_object(),
                          by_user=by_user)
        db.session.add(comment)
        return 'ok'
        # return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) / \
        current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
                                        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
                                            error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post],
    comments=comments, pagination=pagination)


#点赞
@main.route('/heart/<int:id>',methods=['GET','POST'])
@login_required
def heart(id):
    post = Post.query.get_or_404(id)
    post.add_views
    heart=Heart.query.filter_by(user=current_user._get_current_object(),post=post).first()
    if heart:
        db.session.delete(heart)
        return '0'
    else:
        heart_add=Heart(post=post, user=current_user._get_current_object(),by_user_id=post.author_id)
        db.session.add(heart_add)
        return '1'
@main.route('/article_hearts/<int:id>',methods=['POST'])
@login_required
def article_hearts(id):
    article = Article.query.get_or_404(id)
    heart=Heart.query.filter_by(user=current_user._get_current_object(),article=article).first()
    if heart:
        db.session.delete(heart)
        return '0'
    else:
        heart_add=Heart(article=article, user=current_user._get_current_object())
        db.session.add(heart_add)
        return '1'

@main.route('/article_collect/<int:id>',methods=['POST'])
@login_required
def article_collect(id):
    article=Article.query.get_or_404(id)
    collect=Collect.query.filter_by(article=article,user=current_user._get_current_object()).first()
    if collect:
        db.session.delete(collect)
        return '0'
    else:
        collect_add=Collect(user=current_user._get_current_object(),article=article)
        db.session.add(collect_add)
        return '1'


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
    page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
    error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
    pagination=pagination, page=page)

@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
    page=request.args.get('page', 1, type=int)))
@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
    page=request.args.get('page', 1, type=int)))

@main.route('/whoosh',methods=['GET', 'POST'])
def whoosh():
    if request.method== "POST":
        if  request.form.get('search') :
            print(request.form.get('search'))
            query=Whoosh.query.whoosh_search(request.form.get('search')).all()
            if query:
                if isinstance(query, list):
                    result={}
                    k=0
                    import json
                    for i in query:
                        print(i.body)
                        k = k + 1
                        result[k]=i.body
                    return jsonify(result)
                return query
                return 'i.body'
            return 'ok result'
        return 'ok search'
    # return str(w.id)+'/n'+w.body
    return render_template('whoosh/index.html')







