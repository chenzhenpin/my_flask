from flask import Blueprint, request, redirect, render_template, url_for
from flask.views import MethodView
from . import mongo
from myapp.mogomodels import Post
@mongo.route('/list')
def list():
    posts = Post.objects.all()
    return render_template('mongo/list.html', posts=posts)
@mongo.route('/detail/<slug>')
def detail(slug):
    post = Post.objects.get_or_404(slug=slug)
    return render_template('mongo/detail.html', post=post)

