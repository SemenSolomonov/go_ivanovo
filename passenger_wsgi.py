import sys
import os

# Путь до интерпретатора в виртуальном окружении на сервере
INTERP = "/var/www/u3416573/data/www/goivanovo.ru/venv/bin/python"

# Если скрипт запущен не из нашего окружения, перезапускаем его принудительно
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

# Добавляем корневую папку в пути Python
sys.path.append(os.getcwd())

# Импортируем app из твоего main.py и переименовываем в application
from main import app as application