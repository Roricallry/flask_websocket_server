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
    password_hash = db.Column(db.String(128))
    is_privacy_compute = db.Column(db.Boolean, default=False, nullable=False)
    last_heartbeat = db.Column(db.DateTime)

    def set_password(self, password):
        """加密密码"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)