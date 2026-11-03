# PhoenixJustCode | Phoenix

Этот репозиторий содержит код для **визиточного сайта**.

## О проекте

Визиточный сайт **Phoenix** – это простая и стильная веб-страница, представляющая личную информацию, контакты и ссылки на социальные сети.

![изображение](https://github.com/user-attachments/assets/4f5ea45d-7a44-44ee-99c2-5e0ebd7f60c4)




## Функционал

- 🖥️ Адаптивный дизайн  
- 🔗 Ссылки на соцсети и контакты  
- 🚀 Быстрая загрузка


## Локальный запуск

```bash
docker run -d --rm --name phoenix-db -e POSTGRES_PASSWORD=dev -p 5432:5432 postgres:16-alpine
DATABASE_URL='postgres://postgres:dev@127.0.0.1:5432/postgres?sslmode=disable' go run .
```

Сайт откроется на http://127.0.0.1:8000. Все переменные окружения перечислены в `ExampleEnv`.

## Тесты

```bash
export TEST_DATABASE_URL='postgres://postgres:dev@127.0.0.1:5432/postgres?sslmode=disable'
go test -race ./...                         # unit и интеграционные тесты, покрытие >= 90%
go test -tags load -v ./loadtest            # нагрузочный тест на локальном сервере
LOAD_URL=https://phoenixjustcode.ru LOAD_CONCURRENCY=5 LOAD_DURATION=10s \
  go test -tags load -v ./loadtest          # осторожно: нагрузка на прод
```

## Как устроен прод

- nginx (TLS) → `127.0.0.1:8000` → systemd `phoenix.service`, пользователь `phoenix`, лимит памяти 256 МБ.
- Релизы: `/opt/phoenix/releases/<sha>`, активный — симлинк `/opt/phoenix/current`, хранятся 5 последних.
- Секреты: `/etc/phoenix/env` (600) и GitHub Secrets.
- Ключ деплоя (пользователь `deploy`) умеет только две команды через `phoenix-ssh-gate`:
  загрузить бинарник и запустить `phoenix-deploy`; shell и проброс портов запрещены.
- Первый релиз откатывается на `releases/legacy` (старый бинарник из `/var/www/phoenix`).
  Новая версия переводит пароль админа на bcrypt при входе, поэтому после ручного возврата
  на legacy пароль нужно задать заново старым бинарником (`./phoenix -create-admin`).
- Миграции в `internal/database/migrations` только добавляющие (тест не пропустит DROP и т.п.).
  Деструктивные изменения схемы выполняются вручную после бэкапа.
- Бэкапы: ежедневно в 02:30 (Алматы) в `/root/backups`, с проверкой восстановления на временной базе;
  перед каждым деплоем — `/var/backups/phoenix/predeploy-*.dump`.
- Мониторинг и Telegram-алерты: `phoenix-monitor` (каждые 2 минуты), отчёт по понедельникам в 10:00.

## Runbook

**Задеплоить.** Пуш в `main`. CI (линтеры, тесты, покрытие, нагрузка) → сборка на GitHub → загрузка
→ бэкап БД → переключение → проверка `/healthz`, `/readyz` и https://phoenixjustcode.ru.
Если проверка не прошла, деплой сам откатывается и workflow падает с уведомлением в Telegram.

**Проверить версию.**
```bash
curl -s https://phoenixjustcode.ru/healthz    # {"status":"ok","version":"<sha коммита>"}
```

**Откатить вручную** на любой из сохранённых релизов:
```bash
ssh phoenix
ls -lt /opt/phoenix/releases/
ln -sfn /opt/phoenix/releases/<sha> /opt/phoenix/current.tmp && mv -Tf /opt/phoenix/current.tmp /opt/phoenix/current
systemctl restart phoenix && curl -s https://phoenixjustcode.ru/healthz
```
Или `git revert <коммит>` и пуш в `main`: пройдёт обычный деплой.

**Логи.**
```bash
journalctl -u phoenix -f                      # приложение
journalctl -u phoenix --since "1 hour ago"
tail -f /var/log/nginx/access.log /var/log/nginx/error.log
journalctl -u pg-backup                       # ежедневный бэкап и проверка восстановления
```

**Восстановить базу.**
```bash
ssh phoenix
ls -lt /root/backups/phoenix_data-*.dump /var/backups/phoenix/predeploy-*.dump
systemctl stop phoenix
runuser -u postgres -- pg_restore --clean --if-exists --no-owner --role=phoenix_app \
  -d phoenix_data < /root/backups/phoenix_data-<дата>.dump
systemctl start phoenix && curl -s https://phoenixjustcode.ru/readyz
```

**Создать или сменить пароль админа** (пароль читается из stdin, в историю не попадает):
```bash
ssh phoenix
set -a; . /etc/phoenix/env; set +a
read -rs PW && echo "$PW" | /opt/phoenix/current/phoenix create-admin admin
```

**Сервис не поднимается** (5 падений за 5 минут → systemd перестаёт перезапускать, приходит алерт):
```bash
journalctl -u phoenix -n 50 --no-pager
systemctl reset-failed phoenix && systemctl start phoenix
```
