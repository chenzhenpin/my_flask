#coding=utf-8
from flask_socketio import emit,leave_room,join_room

from flask import request,session
from datetime import datetime
from myapp.extension import socketio

#添加命名空间要与前端的命名空间相应
@socketio.on('my event',namespace='/test')
def my_event(message):
    print(message['data'])
    emit('myresponse', {'data': 'your response!'})


@socketio.on('msg',namespace='/test')
def msg(message):
    #获取客户端ip
    ip = request.remote_addr
    now=datetime.now()
    time=now.strftime('%Y-%m-%d %H:%M:%S')
    print(message['data']+ip+request.sid)
    emit('msgresponse', {'data':time+'\r\n'+ip+': '+message['data']})


@socketio.on('join',namespace='/test')
def join(message):
    join_room(message['room'])
    session['room_count']=session.get('room_count',0)+1
    room='room'+str(session['room_count'])
    session[room]=message['room']
    x=1
    while x <=session['room_count']:
        room = 'room' +str(x)
        print(session[room])
        x+=1
    emit('join_response',{'data':'you join '+message['room']})
    emit('room_worker',{'data':'room worker'},room='first_room')
@socketio.on('leave',namespace='/test')
def leave(message):
    leave_room(message['room'])
    emit('join_response',{'data':'you leave '+message['room']})



