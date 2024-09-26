from flask import Flask, request, jsonify
import sys
import sqlite3
import pytz
from datetime import datetime

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS test (test TEXT)')
    cursor.execute('INSERT INTO test (test) VALUES (?)', ('test',))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    timezone = 'Asia/Yekaterinburg'
    local_time = datetime.now(pytz.timezone(timezone))
    return f"Главная страница моих лабораторных работ по курсу 'Разработка серверных приложений'.<br>Студент Кирилл Данилов группы 1111б.<br>Текущая локальная дата и время в {timezone}: {local_time}"

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

if __name__ == '__main__':
    init_db()
    app.run(debug=True)