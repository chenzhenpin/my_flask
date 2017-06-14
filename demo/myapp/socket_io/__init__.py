from flask import Blueprint
socket_io = Blueprint('socket_io', __name__)
from . import views