import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')

    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://caserver:guet@47.106.143.170:3306/db_server')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_SIZE = 10
    SQLALCHEMY_POOL_RECYCLE = 3600

    # 邮件配置（QQ邮箱）
    MAIL_SERVER = 'smtp.qq.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '3127902929@qq.com')         # QQ邮箱
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'ryercmtqgmzodfjc')       # SMTP 授权码
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_SENDER', '3127902929@qq.com')     # 发件人

    # Redis 配置
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))

    RATELIMIT_STORAGE_URL = "redis://localhost:6379/0"
