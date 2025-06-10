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

socketio = SocketIO(app, cors_allowed_origins="*")

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
    socketio.run(app, port=5000, ssl_context=('server.crt', 'server.key'), debug=True)
