from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, send, emit, disconnect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Device
from config import Config
import uuid
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://caserver:guet@47.106.143.170:3306/test'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 禁用警告

# 配置 Redis 存储
app.config["RATELIMIT_STORAGE_URL"] = "redis://localhost:6379/0"

# 初始化 Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config["RATELIMIT_STORAGE_URL"],
)
app.config.from_object(Config)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # 允许跨域

# 创建表（需先手动创建数据库）
with app.app_context():
    db.create_all()

# -----------------------------------------------------------------------------------------------
# 设备管理 CRUD API
# -----------------------------------------------------------------------------------------------
@app.route('/device', methods=['POST'])
def create_device():
    """创建设备（无密码）"""
    device_id = str(uuid.uuid4())  # 生成 UUID
    new_device = Device(
        device_id=device_id,
        is_active=False,
        is_privacy_compute=False
    )
    db.session.add(new_device)
    try:
        db.session.commit()
        return jsonify({"device_id": device_id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

@app.route('/send', methods=['GET'])
def send_to_first():
    """向第一个活跃设备发送数据"""
    # 查询第一个活跃设备（按数据库顺序）
    active_device = Device.query.filter_by(is_active=True).first()

    if not active_device:
        return jsonify({"error": "No active devices available"}), 404

    if not active_device.websocket_id:
        return jsonify({"error": "Device not connected via WebSocket"}), 400

    # 构造要发送的数据
    message = {
        "timestamp": datetime.now().isoformat(),
        "device_id": active_device.device_id,
        "content": "Targeted message from server"
    }

    try:
        # 精确发送到指定设备
        socketio.emit("message", message, to=active_device.websocket_id)
        return jsonify({
            "status": f"Message sent to {active_device.device_id}",
            "sent_data": message
        }), 200
    except Exception as e:
        return jsonify({
            "error": f"Failed to send message: {str(e)}",
            "device_id": active_device.device_id
        }), 500

# -----------------------------------------------------------------------------------------------
# WebSocket 事件处理
# -----------------------------------------------------------------------------------------------

# 客户端连接时触发
@socketio.on('connect')
@limiter.limit("5/minute")  # 每分钟最多 5 次连接尝试
def handle_connect():
    """设备连接时验证并更新状态"""
    device_id = request.args.get('device_id')

    # 检查 device_id 是否存在
    if not device_id:
        emit('error', '缺少 device_id 参数')
        disconnect()
        return
    device = db.session.get(Device, device_id)
    if not device:
        print("Device not found")
        disconnect()
        return

    # 更新设备状态
    device.is_active = True
    device.websocket_id = request.sid
    device.last_heartbeat = datetime.now()
    db.session.commit()

    emit('status', {'is_active': True, 'device_id': device_id})

@socketio.on('disconnect')
def handle_disconnect():
    """设备断开时更新状态"""
    device = Device.query.filter_by(websocket_id=request.sid).first()
    if device:
        device.is_active = False
        device.websocket_id = None
        db.session.commit()

@socketio.on('heartbeat')
def handle_heartbeat():
    """处理心跳包"""
    device = Device.query.filter_by(websocket_id=request.sid).first()
    if device:
        device.last_heartbeat = datetime.now()
        db.session.commit()


# 接收客户端消息
@socketio.on('message')
def handle_message(msg):
    print(f'收到消息: {msg}')
    send(f'服务器回复: {msg}', broadcast=True)  # 广播给所有客户端

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)