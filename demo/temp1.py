from flask import Flask, render_template
from flask_socketio import SocketIO,emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)
@app.route('/')
def index():
    return render_template('index.html')
@socketio.on('my event')
def my_event(message):
    print(message['data'])
    emit('myresponse', {'data': 'I\'m myresponse!'})
@socketio.on('response')
def my_event(message):
    print(message['data'])
@app.route('/test')
def test():
    emit('myresponse', {'data': 'I\'m myresponse!'})
if __name__ == '__main__':
    socketio.run(app)