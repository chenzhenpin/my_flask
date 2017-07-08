#coding=utf-8
from myapp import  create_app
from myapp.extension import celery
import os
import subprocess
#celery worker -A celery_worker.celery --loglevel=info   win下再加--pool=solo参数
app = create_app(os.getenv('FLASK_CONFIG') or 'default')
app.app_context().push()

#celery worker -A celery_worker.celery --loglevel=info --beat  定时任务定时时间在配置文件见

@celery.task(name='tasks.used_apk_cdn')
def used_apk_cdn(a,b):
    msg=subprocess.call(['sudo','python ','hello.py'])
    print(a+b)
    print(msg)