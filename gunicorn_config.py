# gunicorn_config.py

# Адрес и порт, на котором будет работать Gunicorn
bind = "0.0.0.0:8000"

# Количество рабочих процессов.
# Рекомендация: (2 * количество_ядер_CPU) + 1
workers = 3

# Пользователь и группа, от которых будет запущен Gunicorn
# user = "your_user"  # Замените на вашего пользователя на сервере
# group = "your_group" # Замените на вашу группу

# Путь к лог-файлам
accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"

# Уровень логирования
loglevel = "info"

# Рабочая директория
# chdir = "/path/to/your/project" # Укажите путь к проекту на сервере

# Путь к WSGI-приложению
# Пример: tax_service.wsgi:application
# Gunicorn сам найдет его, если запустить из корня проекта
