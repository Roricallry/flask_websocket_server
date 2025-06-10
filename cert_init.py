import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# 证书和密钥路径配置
SERVER_CERT_PATH = "server.crt"
SERVER_PRIVATE_KEY_PATH = "server.key"
CERT_STORE_PATH = "certificates/"

os.makedirs(CERT_STORE_PATH, exist_ok=True)

def load_server_certificate():
    """加载服务端证书和私钥"""
    try:
        with open(SERVER_PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_CERT_PATH, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        public_key = cert.public_key()
        return private_key, cert, public_key
    except Exception as e:
        raise RuntimeError(f"加载服务端证书失败: {str(e)}")

# 加载一次，在模块导入时执行
SERVER_PRIVATE_KEY, SERVER_CERT, SERVER_PUBLIC_KEY = load_server_certificate()