
import uuid

from flask import Flask, request, jsonify
from celery import Celery
#celery worker -A celery_worker.celery --loglevel=info
app = Flask(__name__)
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
app.config['CELERY_TASK_SERIALIZER'] = 'pickle'# pickle

celery = Celery('na', broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)


@celery.task
def send_email():
    return 2+1


@app.route('/')
def reset_password():
    a=send_email.delay()
    return a



if __name__ == '__main__':
    app.run()