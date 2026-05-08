# PasswordGuard

PasswordGuard — локальний Flask-вебпрототип для курсової роботи з кібербезпеки, присвячений захисту паролів, безпечному зберіганню облікових записів і порівнянню сучасних алгоритмів хешування.

## Можливості проєкту

- реєстрація користувачів із вибором `bcrypt`, `scrypt` або `Argon2id`;
- вхід через перевірку парольного хешу без збереження відкритого пароля;
- зберігання даних у `SQLite`;
- сторінка користувачів із фрагментом хешу замість повного відкриття значення;
- benchmark алгоритмів `bcrypt`, `scrypt` та `Argon2id`;
- збереження результатів benchmark у `results.csv`;
- dark security-style інтерфейс для локальної демонстрації.

## Захист, реалізований у прототипі

- `Argon2id` використовується як алгоритм за замовчуванням;
- підтримується додатковий `PEPPER_SECRET`, який не зберігається в базі даних;
- застосовано серверну валідацію логіна і пароля;
- сторінки `/users` та `/benchmark` доступні лише після входу;
- форми захищені CSRF-токенами;
- для `/login` діє обмеження спроб входу;
- для відповідей додаються базові security headers;
- події реєстрації, входу та запуску benchmark логуються у `app.log`.

## Структура

```text
app.py
database.py
password_hashing.py
benchmark.py
requirements.txt
README.md
results.csv
templates/
static/
```

## Підтримувані алгоритми

- `bcrypt`
- `scrypt`
- `Argon2id`

Відкритий пароль у базі даних не зберігається.

## Бажані змінні середовища

- `SECRET_KEY` — секрет для Flask session;
- `PEPPER_SECRET` — додатковий секрет, який додається до пароля перед хешуванням.

Приклад для PowerShell:

```powershell
$env:SECRET_KEY = "your-long-random-secret"
$env:PEPPER_SECRET = "your-pepper-secret"
```

## Локальний запуск

```powershell
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Після запуску застосунок доступний за адресою:

[http://127.0.0.1:5000](http://127.0.0.1:5000)

## Окремий запуск benchmark

```powershell
python benchmark.py
```

## Примітки

- `users.db` створюється автоматично під час роботи застосунку;
- `results.csv` створюється або оновлюється після запуску benchmark;
- `app.log` містить базові події безпеки для демонстрації;
- для локального HTTP `Secure` cookie не примушується, щоб не ламати запуск у Flask.
