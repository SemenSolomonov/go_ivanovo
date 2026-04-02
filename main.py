import os, sys
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
import sqlite3
from cryptography.fernet import Fernet
import base64
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
bcrypt = Bcrypt(app)


# ======================
# КОНФИГУРАЦИЯ ШИФРОВАНИЯ
# ======================

def init_encryption():
    """Инициализация шифрования Fernet"""
    # Генерируем ключ из секретного ключа приложения
    secret_key = app.secret_key.encode()

    # Используем PBKDF2 для получения ключа фиксированной длины
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = b'ivanovo_monuments_salt'  # Можно вынести в конфиг
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key))
    return Fernet(key)


# Инициализируем шифратор
encryptor = init_encryption()


def encrypt_field(data):
    """Шифрует поле базы данных"""
    if not data:
        return None
    encrypted = encryptor.encrypt(data.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_field(encrypted_data):
    """Дешифрует поле базы данных"""
    if not encrypted_data:
        return None
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = encryptor.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception:
        return encrypted_data  # Если не удалось дешифровать, возвращаем как есть


# ======================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ======================

def get_db_connection():
    """Создает подключение к базе данных"""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def login_required(f):
    """Декоратор для проверки авторизации"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# ======================
# ИНИЦИАЛИЗАЦИЯ БД
# ======================

def init_db():
    """Инициализация базы данных с зашифрованными полями"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Создаем таблицу пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email_encrypted TEXT NOT NULL,  -- Зашифрованное поле
            password TEXT NOT NULL,
            full_name_encrypted TEXT,        -- Зашифрованное поле
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')

    # Создаем таблицу посещенных памятников
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS visited_monuments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            monument_id INTEGER NOT NULL,
            visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            UNIQUE(user_id, monument_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Создаем индексы для производительности
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_visits ON visited_monuments(user_id)')

    conn.commit()
    conn.close()

    print("✅ База данных инициализирована")


def migrate_existing_data():
    """Мигрирует существующие данные с шифрованием"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Проверяем структуру таблицы
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'email' in columns and 'email_encrypted' not in columns:
            print("🔧 Миграция данных с шифрованием...")

            # Создаем новую таблицу с зашифрованными полями
            cursor.execute('''
                CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email_encrypted TEXT NOT NULL,
                    password TEXT NOT NULL,
                    full_name_encrypted TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')

            # Копируем данные со шифрованием
            cursor.execute('SELECT * FROM users')
            users = cursor.fetchall()

            for user in users:
                user_id, username, email, password, full_name, created_at = user[:6]

                # Шифруем данные
                encrypted_email = encrypt_field(email) if email else ''
                encrypted_full_name = encrypt_field(full_name) if full_name else None

                cursor.execute('''
                    INSERT INTO users_new 
                    (id, username, email_encrypted, password, full_name_encrypted, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, username, encrypted_email, password, encrypted_full_name, created_at))

            # Заменяем таблицу
            cursor.execute('DROP TABLE users')
            cursor.execute('ALTER TABLE users_new RENAME TO users')

            print(f"✅ Мигрировано {len(users)} пользователей")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Ошибка миграции: {e}")


# ======================
# МАРШРУТЫ ПРИЛОЖЕНИЯ
# ======================

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')


# Страницы памятников
@app.route('/page1')
def page1():
    return render_template('page1.html')


@app.route('/page2')
def page2():
    return render_template('page2.html')


@app.route('/page3')
def page3():
    return render_template('page3.html')


@app.route('/page4')
def page4():
    return render_template('page4.html')


@app.route('/info')
def info():
    return render_template('info.html')


# ======================
# АУТЕНТИФИКАЦИЯ
# ======================

# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form.get('full_name', '').strip()

        # Валидация
        errors = []
        if not username or len(username) < 3:
            errors.append('Имя пользователя должно быть не менее 3 символов')
        if not email or '@' not in email:
            errors.append('Введите корректный email')
        if not password or len(password) < 6:
            errors.append('Пароль должен быть не менее 6 символов')
        if password != confirm_password:
            errors.append('Пароли не совпадают')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')

        # Проверка существования пользователя
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email_encrypted = ?',
                       (username, encrypt_field(email)))

        if cursor.fetchone():
            flash('Пользователь с таким именем или email уже существует!', 'error')
            conn.close()
            return render_template('register.html')

        # Хеширование пароля
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Шифрование данных
        encrypted_email = encrypt_field(email)
        encrypted_full_name = encrypt_field(full_name) if full_name else None

        # Сохранение в базу данных
        try:
            cursor.execute('''
                INSERT INTO users (username, email_encrypted, password, full_name_encrypted)
                VALUES (?, ?, ?, ?)
            ''', (username, encrypted_email, hashed_password, encrypted_full_name))

            conn.commit()
            user_id = cursor.lastrowid

            # Автоматический вход после регистрации
            session['user_id'] = user_id
            session['username'] = username

            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?',
                           (datetime.now().isoformat(), user_id))
            conn.commit()

            flash('Регистрация успешна! Добро пожаловать!', 'success')
            return redirect(url_for('profile'))

        except Exception as e:
            flash(f'Ошибка при регистрации: {str(e)}', 'error')
            return render_template('register.html')
        finally:
            conn.close()

    return render_template('register.html')


# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            flash('Заполните все поля', 'error')
            return render_template('login.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Ищем пользователя по username
        cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            # Обновляем время последнего входа
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?',
                           (datetime.now().isoformat(), user['id']))
            conn.commit()

            # Сохраняем в сессию
            session['user_id'] = user['id']
            session['username'] = user['username']

            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверное имя пользователя или пароль!', 'error')

        conn.close()

    return render_template('login.html')


# Профиль пользователя
@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Получаем данные пользователя
    cursor.execute('''
        SELECT id, username, email_encrypted, full_name_encrypted, created_at, last_login 
        FROM users WHERE id = ?
    ''', (session['user_id'],))

    user_row = cursor.fetchone()

    if not user_row:
        session.clear()
        flash('Пользователь не найден', 'error')
        return redirect(url_for('login'))

    # Дешифруем данные
    user = {
        'id': user_row['id'],
        'username': user_row['username'],
        'email': decrypt_field(user_row['email_encrypted']),
        'full_name': decrypt_field(user_row['full_name_encrypted']),
        'created_at': user_row['created_at'],
        'last_login': user_row['last_login']
    }

    # Получаем посещенные памятники
    cursor.execute('''
        SELECT monument_id, visited_at, notes 
        FROM visited_monuments 
        WHERE user_id = ? 
        ORDER BY visited_at DESC
    ''', (session['user_id'],))

    visited_monuments = []
    monuments_data = {
        1: {'name': 'Дом-птица', 'address': 'пр. Ленина, 53'},
        2: {'name': 'Дом-подкова', 'address': 'ул. Громобоя, 13'},
        3: {'name': 'Дом-корабль', 'address': 'проспект Ленина, 49'},
        4: {'name': 'Дом-пуля', 'address': 'проспект Ленина, 37'},
        5: {'name': 'Ёжик в тумане', 'address': 'парк имени В.Я. Степанова'},
        6: {'name': 'Пальцы', 'address': 'проспект Ленина, около дома 47'},
        7: {'name': 'Аллея любви', 'address': ''},
        8: {'name': 'Верность', 'address': ''},
        9: {'name': 'Молекула', 'address': ''},
        10: {'name': 'Волк с телёнком', 'address': ''},
        11: {'name': 'Акула пера', 'address': ''},
        12: {'name': 'Прялка', 'address': ''},
        13: {'name': 'Такса', 'address': ''},
        14: {'name': 'Первый стоматолог', 'address': ''},
        15: {'name': 'Ивановский областной художественный музей', 'address': ''},
        16: {'name': 'Музей ивановского ситца', 'address': ''},
        17: {'name': 'Музей промышленности и искусства', 'address': ''},
        18: {'name': 'Музей советского автопрома', 'address': ''},
        19: {'name': 'Музейно-выставочный центр', 'address': ''},
        20: {'name': 'Музей первого Совета', 'address': ''},
        21: {'name': 'Дом-музей семьи Бубновых', 'address': ''},
        22: {'name': 'Музей сыра', 'address': ''},
        23: {'name': 'Щудровская палатка', 'address': ''},
    }

    for row in cursor.fetchall():
        monument_id = row['monument_id']
        if monument_id in monuments_data:
            visited_monuments.append({
                'id': monument_id,
                'name': monuments_data[monument_id]['name'],
                'address': monuments_data[monument_id]['address'],
                'visited_at': row['visited_at'],
                'notes': row['notes']
            })

    # Статистика
    total_monuments = 23
    visited_count = len(visited_monuments)
    progress_percent = round((visited_count / total_monuments) * 100) if total_monuments > 0 else 0

    conn.close()

    return render_template('profile.html',
                           user=user,
                           visited_monuments=visited_monuments,
                           visited_count=visited_count,
                           total_monuments=total_monuments,
                           progress_percent=progress_percent)


# Выход
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Вы вышли из системы!', 'info')
    return redirect(url_for('index'))


# ======================
# API ДЛЯ ПРОФИЛЯ
# ======================

@app.route('/api/visit-monument', methods=['POST'])
@login_required
def api_visit_monument():
    """API для отметки посещения памятника"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Нет данных'}), 400

        monument_id = data.get('monument_id')
        notes = data.get('notes', '')

        if not monument_id or not isinstance(monument_id, int):
            return jsonify({'error': 'Неверный ID памятника'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Проверяем, не посещали ли уже
        cursor.execute('''
            SELECT id FROM visited_monuments 
            WHERE user_id = ? AND monument_id = ?
        ''', (session['user_id'], monument_id))

        if cursor.fetchone():
            return jsonify({'error': 'Памятник уже посещен'}), 409

        # Добавляем посещение
        cursor.execute('''
            INSERT INTO visited_monuments (user_id, monument_id, notes)
            VALUES (?, ?, ?)
        ''', (session['user_id'], monument_id, notes))

        conn.commit()
        visit_id = cursor.lastrowid

        conn.close()

        return jsonify({
            'success': True,
            'message': 'Памятник отмечен как посещенный',
            'visit_id': visit_id
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/unvisit-monument/<int:monument_id>', methods=['DELETE'])
@login_required
def api_unvisit_monument(monument_id):
    """API для удаления отметки о посещении"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            DELETE FROM visited_monuments 
            WHERE user_id = ? AND monument_id = ?
        ''', (session['user_id'], monument_id))

        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted_count > 0:
            return jsonify({
                'success': True,
                'message': 'Отметка о посещении удалена'
            })
        else:
            return jsonify({'error': 'Отметка не найдена'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/user/stats')
@login_required
def api_user_stats():
    """API для получения статистики пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM visited_monuments WHERE user_id = ?',
                   (session['user_id'],))
    visited_count = cursor.fetchone()[0]

    total_monuments = 14
    progress_percent = round((visited_count / total_monuments) * 100, 1) if total_monuments > 0 else 0

    conn.close()

    return jsonify({
        'total_visited': visited_count,
        'total_monuments': total_monuments,
        'progress_percent': progress_percent
    })


@app.route('/api/user/visits')
@login_required
def api_user_visits():
    """API для получения списка посещений"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT monument_id, visited_at, notes 
        FROM visited_monuments 
        WHERE user_id = ? 
        ORDER BY visited_at DESC
    ''', (session['user_id'],))

    visits = []
    for row in cursor.fetchall():
        visits.append({
            'monument_id': row['monument_id'],
            'visited_at': row['visited_at'],
            'notes': row['notes']
        })

    conn.close()

    return jsonify({
        'visits': visits,
        'count': len(visits)
    })


# ======================
# АДМИН-ФУНКЦИИ
# ======================

@app.route('/admin/migrate')
def admin_migrate():
    """Страница для миграции данных (только для разработки)"""
    # В продакшене эта страница должна быть защищена
    migrate_existing_data()
    flash('Миграция данных завершена', 'info')
    return redirect(url_for('index'))


# ======================
# ОБРАБОТЧИКИ ОШИБОК
# ======================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# ======================
# ЗАПУСК ПРИЛОЖЕНИЯ
# ======================

if __name__ == '__main__':
    # Инициализация базы данных
    init_db()

    # Миграция существующих данных (если нужно)
    migrate_existing_data()

    # Запуск приложения
    print("🚀 Приложение запущено!")
    print("👉 Главная страница: http://localhost:5000")
    print("👉 Профиль: http://localhost:5000/profile")
    print("👉 Регистрация: http://localhost:5000/register")

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )