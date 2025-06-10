from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Device(db.Model):
    __tablename__ = 'device'

    device_id = db.Column(db.String(36), primary_key=True, nullable=False)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    websocket_id = db.Column(db.String(100), unique=True)
    user_email = db.Column(db.String(255))
    is_privacy_compute = db.Column(db.Boolean, default=False, nullable=False)
    last_heartbeat = db.Column(db.DateTime)
    certificate = db.Column(db.Text, nullable=True) # 新增字段用于保存设备证书

class Admin(db.Model):
    __tablename__ = 'admin'

    username = db.Column(db.String(64), primary_key=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)