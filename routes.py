from flask import Flask, render_template, request, jsonify, render_template_string, flash, session, redirect, url_for
from flask_socketio import SocketIO, send, emit, disconnect

from flask import request, render_template, redirect, url_for, flash, session
from models import db, Device, Admin
from config import Config
from datetime import datetime, timedelta
from cert_init import SERVER_PRIVATE_KEY, SERVER_CERT, SERVER_PUBLIC_KEY
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask_mail import Message
import random, string
import redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def register_routes(app,socketio,mail,r, limiter):
    @app.route('/')
    def index():
        if 'admin' not in session:
            return redirect(url_for('login'))

        # 如果设置了 FLASH_FLAG，就使用 flash 发送一次
        flash_data = app.config.pop('FLASH_FLAG', None)
        if flash_data:
            flash(flash_data['message'], flash_data['category'])

        devices = Device.query.filter(Device.certificate.isnot(None)).all()

        return render_template('index.html', devices=devices)

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("3 per minute")
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                session['admin'] = username
                flash('登录成功', 'success')
                return redirect(url_for('index'))  # 登录成功跳转主页
            else:
                flash('用户名或密码错误', 'danger')

        return render_template('login.html')

        # 登录api函数
    @app.route('/user_login', methods=['GET', 'POST'])
    @limiter.limit("3 per minute")
    def user_login():
        if request.method == 'POST':
            data = request.get_json()
            email = data.get('email')
            code = data.get('code')
            print(request.form.to_dict())
            print("code:", code)

            if not email or not code:
                return jsonify({'status': 'error', 'message': '邮箱和验证码不能为空'}), 400

            key = f'login_verify_code:{email}'
            real_code = r.get(key)

            if not real_code:
                return jsonify({'status': 'error', 'message': '验证码已过期或未发送'}), 400
            elif code != real_code:
                return jsonify({'status': 'error', 'message': '验证码错误'}), 400
            else:
                device_id = data.get('device_id')
                device = Device.query.filter_by(device_id=device_id).first()
                if not device:
                    return jsonify({'status': 'error', 'message': '设备不存在'}), 400
                elif not device.user_email or device.user_email == email:
                    if not device.user_email:
                        device.user_email = email
                        db.session.commit()
                        print("用户绑定设备")

                    r.delete(key)  # 释放redis中存储的验证码
                    return jsonify({'status': 'success', 'message': '登录成功'}), 200
                elif device.user_email != email:
                    return jsonify({'status': 'error', 'message': '账户已绑定'}), 400

                return jsonify({'status': 'error', 'message': '未知错误，请联系管理员'}), 400

        return jsonify({'status': 'error', 'message': '请用POST传参'}), 500

        # 解绑邮箱api函数
    @app.route('/unbind_email', methods=['GET', 'POST'])
    def unbind_email():
        if request.method == 'POST':
            data = request.get_json()
            email = data.get('email')
            code = data.get('code')
            print("code:", code)

            if not email or not code:
                print('邮箱和验证码不能为空')
                return jsonify({'status': 'error', 'message': '邮箱和验证码不能为空'}), 400

            key = f'authenticate_verify_code:{email}'
            real_code = r.get(key)

            if not real_code:
                print('验证码已过期或未发送')
                return jsonify({'status': 'error', 'message': '验证码已过期或未发送'}), 400
            elif code != real_code:
                print('验证码错误')
                return jsonify({'status': 'error', 'message': '验证码错误'}), 400
            else:
                device_id = data.get('device_id')
                device = Device.query.filter_by(device_id=device_id).first()
                if not device:
                    print('设备不存在')
                    return jsonify({'status': 'error', 'message': '设备不存在'}), 400
                if device.user_email != email:
                    print('这并非你的设备')
                    return jsonify({'status': 'error', 'message': '这并非你的设备'}), 400

                device.user_email = ""
                db.session.commit()
                print("用户解绑设备")

                r.delete(key)  # 释放redis中存储的验证码
                return jsonify({'status': 'success', 'message': '登录成功'}), 200

        return jsonify({'status': 'error', 'message': '请用POST传参'}), 500

        # 发送验证码
    @app.route('/send-code', methods=['POST'])
    def send_code():
        data = request.get_json()
        email = data.get('email')
        action = data.get('action')
        email_info = ""

        if action == 'login':
            email_info = "登录"
        elif action == "authenticate":
            email_info = "修改绑定邮箱"
        else:
            return jsonify({'status': 'error', 'message': '未知行为'}), 400
        if not email:
            return jsonify({'status': 'error', 'message': '邮箱不能为空'}), 400

        redis_key = f'{action}_verify_code:{email}'

        # 防止重复发送
        if r.get(redis_key):
            return jsonify({'status': 'error', 'message': '验证码已发送，请稍后再试'}), 400

        code = ''.join(random.choices(string.digits, k=6))

        try:
            msg = Message(
                subject=f'您的验证码',
                recipients=[email],
                body=f'验证码：{code} 用于设备{email_info}，5分钟内有效，请勿泄露和转发。如非本人操作，请忽略此邮件。'
            )
            mail.send(msg)

            # 存入 Redis，5 分钟过期
            r.setex(redis_key, 300, code)

            return jsonify({'status': 'ok'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'邮件发送失败：{str(e)}'})

    @app.route('/logout')
    def logout():
        session.pop('admin', None)
        flash('您已退出登录', 'info')
        return redirect(url_for('login'))

    @app.route('/request_certificate', methods=['POST'])
    def request_certificate():
        """处理设备证书请求"""
        try:
            # 获取CSR
            csr_pem = request.data
            if not csr_pem:
                return jsonify({"error": "未提供CSR"}), 400

            # 解析CSR
            csr = x509.load_pem_x509_csr(csr_pem)

            # 验证CSR签名
            if not csr.is_signature_valid:
                return jsonify({"error": "无效的CSR签名"}), 400

            # 提取设备UUID (CN字段)
            device_uuid = None
            for attr in csr.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    device_uuid = attr.value
                    break

            if not device_uuid:
                return jsonify({"error": "CSR中未找到设备UUID"}), 400

            device = Device.query.filter_by(device_id=device_uuid).first()
            if not device:
                return jsonify({"error": "该设备不存在"}), 400

            # 创建证书 - 使用服务端证书作为颁发者
            cert = (
                x509.CertificateBuilder()
                .subject_name(csr.subject)  # 使用CSR中的主题
                .issuer_name(SERVER_CERT.subject)  # 使用服务端证书作为颁发者
                .public_key(csr.public_key())  # 使用CSR中的公钥
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1年有效期
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                )
                .sign(SERVER_PRIVATE_KEY, hashes.SHA256()))  # 使用服务端私钥签名

            # 保存证书
            device.certificate = cert.public_bytes(serialization.Encoding.PEM)
            db.session.commit()

            print(f"[向设备{device_uuid}成功签发证书]")
            # 返回证书
            return cert.public_bytes(serialization.Encoding.PEM), 200, {
                'Content-Type': 'application/x-pem-file',
                'Content-Disposition': f'attachment; filename=device_{device_uuid}.crt'
            }

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def load_server_private_key(path="server_private.pem"):
        with open(path, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

    SERVER_PRIVATE_KEY = load_server_private_key()

    def decrypt_final_result(encrypted_b64: str, private_key) -> float:
        encrypted = base64.b64decode(encrypted_b64)
        decrypted_bytes = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return float(decrypted_bytes.decode("utf-8"))

    @app.route('/start_chain_computation', methods=['POST'])
    def start_chain_computation():
        if 'admin' not in session:
            return redirect(url_for('login'))

        # 提取在线且同意参与统计的设备
        devices = Device.query.filter_by(is_active=True, is_privacy_compute=True).order_by(Device.device_id).all()
        print(devices)

        if len(devices) < 3:
            flash("参与链式计算的设备数量不足3个", "danger")
            return redirect(url_for('index'))

        device_ids = [d.device_id for d in devices]
        websocket_ids = [d.websocket_id for d in devices]
        certs = [d.certificate for d in devices]

        app.config['CHAIN_STATE'] = {
            'current_index': 0,  # 当前执行的是第0个设备
            'device_ids': device_ids,
            'websocket_ids': websocket_ids,
            'certs': certs,
            'results': [None] * len(devices),  # 用于存储每个设备返回的结果，先用None占位
            'final_result': None,
        }

        # 启动链式计算，发送证书给第一个设备
        if websocket_ids[0]:
            socketio.emit('chain_step', {
                'prev_result': None,
                'target_cert': certs[1]  # 发给下一个设备的证书
            }, room=websocket_ids[0])
            flash("链式计算已启动", "success")
        else:
            flash("第一个设备不在线", "danger")

        return redirect(url_for('index'))

    @socketio.on('chain_response')
    def handle_chain_response(data):
        print(f"收到链式计算结果：{data}")

        # 如果是最终处理结果（来自第一个设备）
        if 'final_result' in data:
            encrypted_final_result = data.get('final_result')
            try:
                decrypted_value = decrypt_final_result(encrypted_final_result, SERVER_PRIVATE_KEY)
                print(f"✅ 最终链式结果解密成功：{decrypted_value:.2f}")
                # 保存 flash 信息到 app.config，供下一次请求时使用
                app.config['FLASH_FLAG'] = {
                    'message': f"链式计算完成，最终结果为：{decrypted_value:.2f}",
                    'category': 'success'
                }
            except Exception as e:
                print(f"❌ 最终链式结果解密失败: {e}")
                app.config['FLASH_FLAG'] = {
                    'message': f"链式计算结果解密失败：{e}",
                    'category': 'danger'
                }
            return

        chain = app.config.get('CHAIN_STATE')
        if not chain:
            return

        index = chain['current_index']
        result = data.get('result')
        chain['results'][index] = result

        next_index = index + 1
        device_count = len(chain['device_ids'])

        # 如果还有下一个设备，则继续传递
        if next_index < device_count:
            if chain['websocket_ids'][next_index]:
                socketio.emit('chain_step', {
                    'prev_result': result,
                    'target_cert': chain['certs'][(next_index + 1) % device_count]  # 发给下下个设备的证书
                }, room=chain['websocket_ids'][next_index])
                chain['current_index'] = next_index
        else:
            # 最后设备处理完毕，返回最终加密结果给第一个设备
            chain['final_result'] = result
            print(f"最终结果（将发回第一个设备）: {result}")
            if chain['websocket_ids'][0]:
                socketio.emit('chain_complete', {
                    'final_input': result
                }, room=chain['websocket_ids'][0])

            # 提示链式计算完成（原始值解密稍后再处理）
            app.config['FLASH_FLAG'] = {
                'message': f"链式计算完成，最终结果已加密并返回第一设备等待最终处理。",
                'category': 'success'
            }
            app.config.pop('CHAIN_STATE', None)