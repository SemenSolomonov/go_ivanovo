import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or Fernet.generate_key().decode()
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = False  # True для HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Шифрование
    DB_ENCRYPTION_KEY = os.environ.get('DB_ENCRYPTION_KEY') or Fernet.generate_key().decode()


# Инициализация шифрования
def init_encryption():
    key = Config.DB_ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode()

    # Проверяем ключ
    if len(key) != 44 or not key.startswith(b'gAAAAA'):
        # Генерируем новый валидный ключ
        key = Fernet.generate_key()
        print(f"⚠️  Создан новый ключ шифрования. Добавьте в .env:")
        print(f"DB_ENCRYPTION_KEY={key.decode()}")

    return Fernet(key)


# Создаем шифратор
encryptor = init_encryption()