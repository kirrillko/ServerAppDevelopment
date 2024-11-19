from flask import Flask, request, jsonify, render_template, redirect, url_for
import sys
import sqlite3
import pytz
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
# ОС от Шиленкова (лаба 2):
# сделать счётчик активных токенов на сервере. можно в БД.
# чтобы учесть, что сеансы могут быть на разных устройствах
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['TOKEN_EXPIRATION'] = 3600  # 1 час
app.config['MAX_ACTIVE_TOKENS'] = 5  # Максимум 5 активных токенов

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Создаем таблицу для пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

@app.route('/')
def index():
    timezone = 'Asia/Magadan'
    local_time = datetime.now(pytz.timezone(timezone))
    return f"Главная страница. Текущая локальная дата и время в {timezone}: {local_time}"

@app.route('/info/server', methods=['GET'])
def python_info():
    return jsonify({'Версия Python': sys.version})

@app.route('/info/client', methods=['GET'])
def client_info():
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    return jsonify({'IP': user_ip, 'Browser': user_agent})

@app.route('/info/database', methods=['GET'])
def database_info():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT sqlite_version();')
    version = cursor.fetchone()[0]
    conn.close()
    return jsonify({'SQLite Version': version})

# DTO классы
class UserDTO:
    def __init__(self, user_id, email, created_at):
        self.id = user_id
        self.email = email
        self.created_at = created_at

class TokenDTO:
    def __init__(self, access_token, refresh_token=None):
        self.access_token = access_token
        self.refresh_token = refresh_token

class MessageDTO:
    def __init__(self, message):
        self.message = message

class LoginRequest:
    def __init__(self, email, password):
        self.email = email
        self.password = password

    def to_dict(self):
        return {'email': self.email, 'password': self.password}

class RegisterRequest:
    def __init__(self, email, password):
        self.email = email
        self.password = password

    def to_dict(self):
        return {'email': self.email, 'password': self.password}

# Контроллер аутентификации
class AuthController:

    @staticmethod
    def register(register_request):
        email = register_request.email
        password_hash = generate_password_hash(register_request.password)

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Проверяем, существует ли пользователь
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            return MessageDTO('Пользователь уже существует'), 400

        # Добавляем нового пользователя
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()

        return UserDTO(user_id, email, datetime.now()), 201

    @staticmethod
    def login(login_request):
        email = login_request.email
        password = login_request.password

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Проверяем существование пользователя
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        if not user or not check_password_hash(user[2], password):
            return MessageDTO('Неверный email или пароль'), 400

        user_id = user[0]

        # Проверяем количество активных сеансов
        active_tokens = request.cookies.getlist('active_tokens')
        if len(active_tokens) >= app.config['MAX_ACTIVE_TOKENS']:
            return MessageDTO('Достигнуто максимальное количество активных сеансов'), 403

        # Генерируем токен доступа
        access_token = jwt.encode(
            {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(seconds=app.config['TOKEN_EXPIRATION'])},
            app.config['SECRET_KEY'], algorithm='HS256')

        return TokenDTO(access_token), 200

    @staticmethod
    def get_user_info(user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return UserDTO(user[0], user[1], user[3]), 200
        else:
            return MessageDTO('Пользователь не найден'), 404

    @staticmethod
    def change_password(user_id, old_password, new_password):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Проверяем старый пароль
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user or not check_password_hash(user[2], old_password):
            return MessageDTO('Неверный старый пароль'), 400

        # Обновляем пароль
        new_password_hash = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, user_id))
        conn.commit()
        conn.close()

        return MessageDTO('Пароль успешно изменен'), 200

# Маршруты
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        register_request = RegisterRequest(data['email'], data['password'])
        result, status = AuthController.register(register_request)
        if status == 201:
            return redirect(url_for('/'))
        else:
            return render_template('register.html', title='Register', message=result.message)
    return render_template('register.html', title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        login_request = LoginRequest(data['email'], data['password'])
        result, status = AuthController.login(login_request)
        if status == 200:
            response = redirect(url_for('profile'))
            response.set_cookie('access_token', result.access_token)
            return response
        else:
            return render_template('login.html', title='Login', message=result.message)
    return render_template('login.html', title='Login')

@app.route('/profile', methods=['GET'])
def profile():
    token = request.cookies.get('access_token')
    if token:
        user_id = decode_token(token)
        result, status = AuthController.get_user_info(user_id)
        if status == 200:
            return render_template('profile.html', title='Profile', user=result)
    return redirect(url_for('/'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    token = request.cookies.get('access_token')
    if token:
        # Удаляем токен из куки
        response = redirect(url_for('login'))
        response.delete_cookie('access_token')
        return response
    return redirect(url_for('login'))


# Декодирование токена
def decode_token(token):
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return decoded['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Токен истек'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Недействительный токен'}), 401

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
