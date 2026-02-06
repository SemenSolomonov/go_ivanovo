from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from datetime import datetime

auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['POST'])
def register():
    data = request.json or request.form

    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password:
        return jsonify({'error': 'Логин и пароль обязательны'}), 400

    # Проверка существования
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Пользователь уже существует'}), 400

    # Создание пользователя
    user = User(
        username=username,
        email=email or f"{username}@example.com"
    )
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()

        # Автоматический вход
        login_user(user)

        return jsonify({
            'message': 'Регистрация успешна',
            'user': user.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@auth.route('/login', methods=['POST'])
def login():
    data = request.json or request.form

    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user)
        session['user_id'] = user.id
        session['username'] = user.username

        return jsonify({
            'message': 'Вход выполнен',
            'user': user.to_dict()
        })

    return jsonify({'error': 'Неверный логин или пароль'}), 401


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return jsonify({'message': 'Выход выполнен'})


@auth.route('/profile/update', methods=['PUT'])
@login_required
def update_profile():
    data = request.json

    if 'email' in data:
        current_user.email = data['email']
    if 'full_name' in data:
        current_user.full_name = data['full_name']

    try:
        db.session.commit()
        return jsonify({
            'message': 'Профиль обновлен',
            'user': current_user.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500