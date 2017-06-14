from flask import Blueprint
mongo = Blueprint('mongo', __name__)
from . import views#改句在mongo = Blueprint('mongo', __name__)前面将导致导入出错
