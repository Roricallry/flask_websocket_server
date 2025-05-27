from flask import Flask, render_template
from flask_socketio import SocketIO, send

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")  # 允许跨域

# 客户端连接时触发
@socketio.on('connect')
def handle_connect():
    print('客户端已连接')
    send('你已连接到服务器')

# 接收客户端消息
@socketio.on('message')
def handle_message(msg):
    print(f'收到消息: {msg}')
    send(f'服务器回复: {msg}', broadcast=True)  # 广播给所有客户端

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)