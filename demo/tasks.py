# tasks.py
import time
from celery import Celery

celery = Celery('tasks', broker='redis://localhost:6379/0')

@celery.task
def sendmail():
    print('sending mail to ...' )
    time.sleep(2.0)
    print('mail sent.')