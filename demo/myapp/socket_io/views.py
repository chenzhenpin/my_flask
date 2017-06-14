from flask import render_template,session
from .import socket_io
@socket_io.route('/msg/')
def msg():
    return render_template('socketio/msg.html')