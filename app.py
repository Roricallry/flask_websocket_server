from flask import Flask, render_template, request, jsonify, render_template_string, flash, session, redirect, url_for
from flask_socketio import SocketIO, send, emit, disconnect
from models import db, Device, Admin
from config import Config
from datetime import datetime, timedelta
from socket_events import register_socket_events
from routes import register_routes
from flask_mail import Mail
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
# 允许所有跨域
app.config.from_object(Config)

from routes import socketio_bp
socketio = SocketIO(app, cors_allowed_origins="*")
app.register_blueprint(socketio_bp)

# 初始化
db.init_app(app)
mail = Mail(app)



limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=app.config["RATELIMIT_STORAGE_URL"]
)

# 初始化 Redis
r = redis.StrictRedis(
    host=app.config['REDIS_HOST'],
    port=app.config['REDIS_PORT'],
    db=app.config['REDIS_DB'],
    decode_responses=True
)

from routes import register_routes  # 延迟导入，避免循环
from socket_events import register_socket_events
register_routes(app,socketio,mail,r, limiter)
register_socket_events(socketio)

def push_flash_message(message, category='success'):
    data = {
        'message': message,
        'category': category
    }
    socketio.emit('flash_message', data)
    print('已推送消息:', data)

# 这里模拟定时任务或链式计算完成时调用
@app.route('/send_message')
def send_message():
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    push_flash_message(f"链式计算完成，时间：{now}", 'success')
    return "消息已推送"


if __name__ == '__main__':
    print("✅ 启动服务器：https://localhost:5000")
    with app.app_context():
        db.create_all()

        # 创建管理员账号（只添加一次）
        if not Admin.query.filter_by(username='admin').first():
            admin = Admin(username='admin')
            admin.set_password('123456')  # 密码加密
            db.session.add(admin)
            db.session.commit()
            print("✅ 管理员账号已创建：admin / 123456")
        else:
            print("ℹ️ 管理员账号已存在")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
