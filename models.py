from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from config import encryptor
import base64

db = SQLAlchemy()



def encrypt_field(value):
    """Шифрует поле базы данных"""
    if value is None:
        return None
    encrypted = encryptor.encrypt(value.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_field(encrypted_value):
    """Дешифрует поле базы данных"""
    if encrypted_value is None:
        return None
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_value.encode())
        decrypted = encryptor.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception:
        return encrypted_value  # Если не зашифровано


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

    # Зашифрованные поля
    _email = db.Column('email', db.Text, nullable=False)
    _password_hash = db.Column('password_hash', db.Text, nullable=False)
    _full_name = db.Column('full_name', db.Text)

    # Открытые поля
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    @property
    def email(self):
        return decrypt_field(self._email)

    @email.setter
    def email(self, value):
        self._email = encrypt_field(value)

    @property
    def password_hash(self):
        return decrypt_field(self._password_hash)

    @password_hash.setter
    def password_hash(self, value):
        self._password_hash = encrypt_field(value)

    @property
    def full_name(self):
        return decrypt_field(self._full_name)

    @full_name.setter
    def full_name(self, value):
        self._full_name = encrypt_field(value)

    def set_password(self, password):
        """Хеширует и шифрует пароль"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Проверяет пароль"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Возвращает данные пользователя"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class VisitedMonument(db.Model):
    __tablename__ = 'visited_monuments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    monument_id = db.Column(db.Integer, nullable=False)
    visited_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

    # Связь
    user = db.relationship('User', backref='visited_monuments')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'monument_id', name='unique_visit'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'monument_id': self.monument_id,
            'visited_at': self.visited_at.isoformat() if self.visited_at else None,
            'notes': self.notes
        }


# Модель для миграции старых данных
class DataMigration:
    @staticmethod
    def migrate_user(user):
        """Мигрирует пользователя, шифруя его данные"""
        if not user._email.startswith('gAAAAA'):
            # Если email не зашифрован, шифруем его
            user._email = encrypt_field(user.email)
            user._password_hash = encrypt_field(user.password_hash)
            if user._full_name:
                user._full_name = encrypt_field(user.full_name)
        return user