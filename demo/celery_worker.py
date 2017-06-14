#coding=utf-8
from myapp import celery, create_app
import os
#celery worker -A celery_worker.celery --loglevel=info   win下再加--pool=solo参数
app = create_app(os.getenv('FLASK_CONFIG') or 'default')
app.app_context().push()