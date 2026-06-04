# MicroPKI

MicroPKI — учебная CLI-утилита для создания Root CA, Intermediate CA и выпуска конечных X.509-сертификатов по шаблонам `server`, `client`, `code_signing`.

## Требования

- Python 3.8+
- `cryptography>=41.0.0`
- `pytest>=7.0.0` для тестов
- OpenSSL CLI — только для дополнительных interoperability/TLS-проверок. Если OpenSSL не установлен, соответствующий pytest-тест пропускается.

## Установка

```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows PowerShell/CMD

python -m pip install -r requirements.txt
python -m pip install -e .
```

После установки команда `micropki` доступна из активированного окружения. Без установки можно использовать `python -m micropki`.

## Sprint 1: создание Root CA

```bash
mkdir -p secrets logs
printf "root-passphrase\n" > secrets/root.pass

micropki ca init \
  --subject "/CN=Demo Root CA,O=MicroPKI" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./secrets/root.pass \
  --out-dir ./pki \
  --validity-days 7300 \
  --log-file ./logs/ca-init.log
```

ECC-вариант Root CA:

```bash
micropki ca init \
  --subject "CN=ECC Root CA,O=MicroPKI" \
  --key-type ecc \
  --key-size 384 \
  --passphrase-file ./secrets/root.pass \
  --out-dir ./pki-ecc
```

Если выходные файлы уже существуют, `ca init` запросит подтверждение перезаписи. Для перезаписи без вопроса используйте `--force`.

## Sprint 2: выпуск Intermediate CA

```bash
printf "intermediate-passphrase\n" > secrets/intermediate.pass

micropki ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file ./secrets/root.pass \
  --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./secrets/intermediate.pass \
  --out-dir ./pki \
  --validity-days 1825 \
  --pathlen 0
```

Команда создаёт:

```text
pki/private/intermediate.key.pem
pki/certs/intermediate.cert.pem
pki/csrs/intermediate.csr.pem
```

Ключ Intermediate CA хранится зашифрованным PKCS#8 PEM. В `policy.txt` добавляется секция Intermediate CA с subject, serial, validity, key algorithm/size, path length и issuer.

## Sprint 2: выпуск server certificate

```bash
micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --template server \
  --subject "CN=example.com,O=MicroPKI" \
  --san dns:example.com \
  --san dns:www.example.com \
  --san ip:192.168.1.10 \
  --out-dir ./pki/certs \
  --validity-days 365
```

Для `server` обязателен хотя бы один `dns:` или `ip:` SAN. Конечный приватный ключ сохраняется рядом с сертификатом в открытом PEM-виде с правами `0o600`; утилита пишет предупреждение в лог.

## Sprint 2: выпуск client certificate

```bash
micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --template client \
  --subject "CN=Alice Smith,EMAIL=alice@example.com" \
  --san email:alice@example.com \
  --out-dir ./pki/certs
```

Для `client` допустимы `email:` и `dns:` SAN.

## Sprint 2: выпуск code signing certificate

```bash
micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --template code_signing \
  --subject "CN=MicroPKI Code Signer" \
  --out-dir ./pki/certs
```

Для `code_signing` SAN не обязателен. Если SAN указан, допускаются только `dns:` и `uri:`.

## Sprint 2: подпись внешнего CSR

Опционально `issue-cert` принимает `--csr`. CSR проверяется по подписи. Если CSR запрашивает `CA=TRUE`, выпуск конечного сертификата отклоняется.

```bash
micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --template server \
  --subject "CN=csr.example.com" \
  --san dns:csr.example.com \
  --csr ./external/server.csr.pem \
  --out-dir ./pki/certs
```

## Проверка Root CA

```bash
micropki ca verify --cert ./pki/certs/ca.cert.pem
```

Ожидаемый результат:

```text
/path/to/pki/certs/ca.cert.pem: OK
```

## Проверка цепочки leaf → intermediate → root

```bash
micropki ca verify-chain \
  --root-cert ./pki/certs/ca.cert.pem \
  --intermediate-cert ./pki/certs/intermediate.cert.pem \
  --cert ./pki/certs/example.com.cert.pem \
  --purpose server
```

Команда проверяет подписи, сроки действия, Basic Constraints и базовое соответствие Key Usage / Extended Key Usage.

## Дополнительная проверка через OpenSSL

Инспекция расширений:

```bash
openssl x509 -in ./pki/certs/intermediate.cert.pem -text -noout
openssl x509 -in ./pki/certs/example.com.cert.pem -text -noout
```

Проверка цепочки через OpenSSL:

```bash
openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/intermediate.cert.pem
openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./pki/certs/example.com.cert.pem
```

Также есть скрипт:

```bash
python scripts/openssl_verify_chain.py \
  --root-cert ./pki/certs/ca.cert.pem \
  --intermediate-cert ./pki/certs/intermediate.cert.pem \
  --cert ./pki/certs/example.com.cert.pem
```

Примечание: в Sprint 1 AKI у Root CA намеренно помечен critical по требованию проверки. Некоторые версии OpenSSL могут отклонять такой Root CA как `unhandled critical extension`; поэтому основная проверка реализована встроенной командой `micropki ca verify-chain`.

## TLS round-trip test

Для демонстрации server certificate в TLS можно использовать OpenSSL-скрипт:

```bash
python scripts/tls_roundtrip.py \
  --root-cert ./pki/certs/ca.cert.pem \
  --chain-cert ./pki/certs/intermediate.cert.pem \
  --server-cert ./pki/certs/example.com.cert.pem \
  --server-key ./pki/certs/example.com.key.pem
```

Скрипт запускает `openssl s_server` и подключается к нему через `openssl s_client`, доверяя Root CA.

## Тестирование

```bash
make test
```

На Windows `make` может отсутствовать в Git Bash. В этом случае используйте:

```bash
python run_tests.py
```

или напрямую:

```bash
python -m pytest -q
```

Для CMD также доступен:

```bat
run_tests.bat
```

## Структура проекта

```text
micropki/
  __init__.py
  __main__.py
  ca.py
  certificates.py
  chain.py
  cli.py
  crypto_utils.py
  csr.py
  logger.py
  templates.py
  database.py
  repository.py
  serial.py
  crl.py
  revocation.py
scripts/
  openssl_verify_chain.py
  tls_roundtrip.py
tests/
  test_micropki.py
  test_openssl_compat.py
  test_sprint2.py
pyproject.toml
requirements.txt
Makefile
run_tests.py
run_tests.bat
run_tests.sh
README.md
COMPLIANCE_REPORT.md
```

## Sprint 3: база сертификатов SQLite

Инициализация базы сертификатов:

```bash
micropki db init --db-path ./pki/micropki.db
```

Команда идемпотентна: повторный запуск не ломает существующую схему. База содержит таблицу `certificates`, уникальный индекс по `serial_hex`, индекс по `status` и служебную таблицу `schema_migrations` для простой подготовки к будущим миграциям.

Начиная со Sprint 3, команды `ca init`, `ca issue-intermediate` и `ca issue-cert` поддерживают `--db-path`. По умолчанию используется `./pki/micropki.db`. Новые сертификаты автоматически заносятся в базу после выпуска.

Пример полного начала работы:

```bash
mkdir -p secrets
printf "root-passphrase\n" > secrets/root.pass
printf "intermediate-passphrase\n" > secrets/intermediate.pass

micropki db init --db-path ./pki/micropki.db

micropki ca init \
  --subject "CN=Demo Root CA,O=MicroPKI" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./secrets/root.pass \
  --out-dir ./pki \
  --db-path ./pki/micropki.db \
  --force

micropki ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file ./secrets/root.pass \
  --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./secrets/intermediate.pass \
  --out-dir ./pki \
  --db-path ./pki/micropki.db

micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --template server \
  --subject "CN=example.com,O=MicroPKI" \
  --san dns:example.com \
  --san ip:127.0.0.1 \
  --out-dir ./pki/certs \
  --db-path ./pki/micropki.db
```

## Sprint 3: просмотр сертификатов из базы

Список сертификатов:

```bash
micropki ca list-certs --db-path ./pki/micropki.db --format table
micropki ca list-certs --db-path ./pki/micropki.db --status valid --format json
micropki ca list-certs --db-path ./pki/micropki.db --format csv
```

Вывод PEM по серийному номеру:

```bash
micropki ca show-cert 2A7F --db-path ./pki/micropki.db > cert.pem
```

## Sprint 3: HTTP repository server

Запуск сервера репозитория:

```bash
micropki repo serve \
  --host 127.0.0.1 \
  --port 8080 \
  --db-path ./pki/micropki.db \
  --cert-dir ./pki/certs \
  --log-file ./logs/repo.log
```

Проверка порта сервера:

```bash
micropki repo status --host 127.0.0.1 --port 8080
```

Примеры API-запросов:

```bash
curl http://127.0.0.1:8080/certificate/2A7F --output cert.pem
curl http://127.0.0.1:8080/ca/root --output root.pem
curl http://127.0.0.1:8080/ca/intermediate --output intermediate.pem
curl -i http://127.0.0.1:8080/crl
```

Эндпоинты:

```text
GET /certificate/<serial>   # PEM сертификата из SQLite, 400 для не-hex serial, 404 если не найден
GET /ca/root                # pki/certs/ca.cert.pem
GET /ca/intermediate        # pki/certs/intermediate.cert.pem
GET /crl                    # текущий Intermediate CRL, 404 если CRL ещё не создан
GET /crl?ca=root            # Root CRL
GET /crl/intermediate.crl   # альтернативный путь к CRL
```

Все ответы HTTP включают `Access-Control-Allow-Origin: *`. Каждый запрос логируется в формате с префиксом `[HTTP]`, методом, путём, IP клиента и статусом ответа.

## Sprint 3: дополнительные проверки

Проверка генератора serial:

```bash
python scripts/serial_stress.py --db-path ./pki/micropki.db --count 100
```

Полный интеграционный workflow Sprint 3:

```bash
python scripts/integration_sprint3.py
```

Тесты:

```bash
python run_tests.py
```

На текущей версии тестовый набор покрывает SQLite-схему, уникальность serial, автоматическую вставку сертификатов, CLI `list-certs`/`show-cert`, HTTP API `/certificate/<serial>`, `/ca/root`, `/ca/intermediate`, `/crl`, CORS и негативную проверку невалидного serial.


## Sprint 4: отзыв сертификатов и CRL

Sprint 4 добавляет полный цикл отзыва сертификатов: запись статуса в SQLite, генерацию X.509 CRL v2, хранение CRL в `pki/crl/` и HTTP-раздачу CRL через репозиторий.

Структура `pki/` теперь включает каталог CRL:

```text
pki/
  private/
  certs/
  csrs/
  crl/
    root.crl.pem
    intermediate.crl.pem
  micropki.db
  policy.txt
```

Поддерживаемые причины отзыва:

```text
unspecified, keyCompromise, cACompromise, affiliationChanged,
superseded, cessationOfOperation, certificateHold, removeFromCRL,
privilegeWithdrawn, aACompromise
```

Отзыв сертификата по serial:

```bash
micropki ca revoke 2A7F \
  --reason keyCompromise \
  --db-path ./pki/micropki.db \
  --force
```

Без `--force` команда запросит интерактивное подтверждение. Если сертификат уже отозван, команда пишет предупреждение и завершается успешно без изменения записи. Если serial не найден, команда возвращает ненулевой код.

Генерация Intermediate CRL:

```bash
micropki ca gen-crl \
  --ca intermediate \
  --ca-pass-file ./secrets/intermediate.pass \
  --out-dir ./pki \
  --db-path ./pki/micropki.db \
  --next-update 7
```

Генерация Root CRL:

```bash
micropki ca gen-crl \
  --ca root \
  --ca-pass-file ./secrets/root.pass \
  --out-dir ./pki \
  --db-path ./pki/micropki.db
```

Можно явно указать пути к CA certificate/key и выходному CRL-файлу:

```bash
micropki ca gen-crl \
  --ca intermediate \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --out-file ./backup/intermediate.crl.pem \
  --db-path ./pki/micropki.db
```

Быстрая проверка статуса в базе:

```bash
micropki ca check-revoked 2A7F --db-path ./pki/micropki.db
```

## Sprint 4: CRL через HTTP repository

Запуск сервера с каталогом CRL:

```bash
micropki repo serve \
  --host 127.0.0.1 \
  --port 8080 \
  --db-path ./pki/micropki.db \
  --cert-dir ./pki/certs \
  --crl-dir ./pki/crl
```

Получение CRL:

```bash
curl -H "Accept: application/pkix-crl" http://127.0.0.1:8080/crl --output intermediate.crl.pem
curl http://127.0.0.1:8080/crl?ca=root --output root.crl.pem
curl http://127.0.0.1:8080/crl/intermediate.crl --output intermediate.crl.pem
```

Ответ CRL возвращается с `Content-Type: application/pkix-crl`, `Access-Control-Allow-Origin: *`, `Last-Modified`, `Cache-Control` и `ETag`. Если CRL-файл ещё не создан, сервер возвращает `404 Not Found`.

## Sprint 4: проверка CRL

Инспекция CRL:

```bash
openssl crl -in ./pki/crl/intermediate.crl.pem -inform PEM -text -noout
```

Проверка подписи CRL Intermediate CA:

```bash
openssl crl \
  -in ./pki/crl/intermediate.crl.pem \
  -inform PEM \
  -CAfile ./pki/certs/intermediate.cert.pem \
  -noout
```

Ожидаемый результат OpenSSL: `verify OK`.

Полный жизненный цикл в тестах покрывает выпуск leaf-сертификата, отзыв с причиной `keyCompromise`, обновление полей `status`, `revocation_reason`, `revocation_date`, генерацию CRL, наличие serial в CRL, увеличение CRL Number, HTTP-раздачу CRL и негативные сценарии для отсутствующего/уже отозванного сертификата.

## Sprint 5: выпуск OCSP responder certificate

OCSP responder certificate — специальный конечный сертификат для подписи OCSP-ответов. Он выпускается от Intermediate CA, содержит `BasicConstraints: CA=FALSE`, `KeyUsage: digitalSignature` и `ExtendedKeyUsage: OCSPSigning`.

```bash
micropki ca issue-ocsp-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --subject "CN=OCSP Responder,O=MicroPKI" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:ocsp.example.com \
  --out-dir ./pki/certs \
  --validity-days 365
```

Команда создаёт:

```text
pki/certs/ocsp.cert.pem
pki/certs/ocsp.key.pem
pki/ocsp/
```

Приватный ключ OCSP responder хранится незашифрованным PEM с правами `0o600`, потому что responder должен загружать его автоматически при старте. Утилита выводит предупреждение об этом в лог.

## Sprint 5: запуск OCSP responder

```bash
micropki ocsp serve \
  --host 127.0.0.1 \
  --port 8081 \
  --db-path ./pki/micropki.db \
  --responder-cert ./pki/certs/ocsp.cert.pem \
  --responder-key ./pki/certs/ocsp.key.pem \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --cache-ttl 120 \
  --log-file ./logs/ocsp.log
```

Responder принимает DER-кодированные OCSP-запросы через HTTP POST на `/ocsp` или `/` с заголовком:

```text
Content-Type: application/ocsp-request
```

Ответ возвращается с:

```text
Content-Type: application/ocsp-response
```

Responder определяет статус по SQLite-базе:

```text
valid   -> good
revoked -> revoked
missing / wrong issuer -> unknown
```

Каждый OCSP-запрос логируется в структурированном JSON-подобном формате: client IP, serial, статус ответа, совпадение issuer и время обработки в миллисекундах.

## Sprint 5: проверка через OpenSSL ocsp

Good status:

```bash
openssl ocsp \
  -issuer ./pki/certs/intermediate.cert.pem \
  -cert ./pki/certs/example.com.cert.pem \
  -url http://127.0.0.1:8081/ocsp \
  -VAfile ./pki/certs/ocsp.cert.pem \
  -CAfile ./pki/certs/intermediate.cert.pem \
  -partial_chain \
  -no_nonce
```

Ожидаемый результат:

```text
Response verify OK
./pki/certs/example.com.cert.pem: good
```

Revoked status:

```bash
micropki ca revoke <SERIAL> --reason keyCompromise --force --db-path ./pki/micropki.db

openssl ocsp \
  -issuer ./pki/certs/intermediate.cert.pem \
  -cert ./pki/certs/example.com.cert.pem \
  -url http://127.0.0.1:8081/ocsp \
  -VAfile ./pki/certs/ocsp.cert.pem \
  -CAfile ./pki/certs/intermediate.cert.pem \
  -partial_chain \
  -no_nonce
```

## Sprint 5: OCSP nonce и replay protection

OCSP nonce — расширение запроса с OID `1.3.6.1.5.5.7.48.1.2`. Клиент добавляет случайное значение в запрос, а responder обязан вернуть точно такое же значение в ответе. Это помогает обнаруживать повторно отправленные старые OCSP-ответы.

В MicroPKI responder работает так:

```text
request has nonce    -> response echoes the same nonce
request has no nonce -> response has no nonce extension
```

OpenSSL-запрос с nonce:

```bash
openssl ocsp \
  -issuer ./pki/certs/intermediate.cert.pem \
  -cert ./pki/certs/example.com.cert.pem \
  -url http://127.0.0.1:8081/ocsp \
  -VAfile ./pki/certs/ocsp.cert.pem \
  -CAfile ./pki/certs/intermediate.cert.pem \
  -partial_chain \
  -nonce
```

## Sprint 5: структура проекта

```text
micropki/
  ocsp.py
  ocsp_responder.py
```

`ocsp.py` содержит разбор OCSP request, построение signed OCSP response, nonce handling, status determination и проверку OCSP signer certificate.  
`ocsp_responder.py` содержит HTTP-server для `micropki ocsp serve`.

## Sprint 6: client CSR generation

Generate an end-entity private key and PKCS#10 CSR:

```bash
micropki client gen-csr \
  --subject "CN=app.example.com,O=MicroPKI" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:app.example.com \
  --san dns:api.example.com \
  --out-key ./app.key.pem \
  --out-csr ./app.csr.pem
```

The generated private key is unencrypted PEM and is written with `0o600` permissions where the operating system supports POSIX file modes. The command logs a warning because this key is not passphrase-protected.

## Sprint 6: CSR-based certificate issuance

`ca issue-cert` now accepts an external CSR:

```bash
micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --template server \
  --csr ./app.csr.pem \
  --out-dir ./pki/certs \
  --db-path ./pki/micropki.db
```

When `--csr` is used, the certificate subject and SANs are taken from the CSR. The CSR signature is verified. A CSR that requests `CA=TRUE` is rejected for end-entity issuance.

## Sprint 6: repository certificate request endpoint

The repository server can issue certificates through `POST /request-cert` when CA credentials are supplied at startup:

```bash
micropki repo serve \
  --host 127.0.0.1 \
  --port 8080 \
  --db-path ./pki/micropki.db \
  --cert-dir ./pki/certs \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/intermediate.pass \
  --api-key changeme
```

The demo API key is intentionally simple and is not production authentication. For a coursework/demo system it proves the flow; a real CA would require strong authentication, authorisation, approval workflow, rate limiting and audit controls.

Manual request example:

```bash
cat ./app.csr.pem | curl -X POST \
  -H "Content-Type: application/x-pem-file" \
  -H "X-API-Key: changeme" \
  --data-binary @- \
  "http://localhost:8080/request-cert?template=server" \
  --output ./app.cert.pem
```

Client wrapper:

```bash
micropki client request-cert \
  --csr ./app.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --api-key changeme \
  --out-cert ./app.cert.pem
```

## Sprint 6: certificate chain validation

Validate a leaf certificate against an intermediate and trusted root:

```bash
micropki client validate \
  --cert ./app.cert.pem \
  --untrusted ./pki/certs/intermediate.cert.pem \
  --trusted ./pki/certs/ca.cert.pem \
  --purpose server \
  --mode chain
```

Full validation with revocation checking:

```bash
micropki client validate \
  --cert ./app.cert.pem \
  --untrusted ./pki/certs/intermediate.cert.pem \
  --trusted ./pki/certs/ca.cert.pem \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ocsp \
  --ocsp-url http://127.0.0.1:8081/ocsp \
  --crl http://127.0.0.1:8080/crl?ca=intermediate \
  --purpose server \
  --mode full
```

The validator builds the shortest chain from leaf to trusted root, then checks signatures, validity periods, Basic Constraints, path length constraints, CA Key Usage and optional EKU purpose.

`--validation-time` can be used to test expired or not-yet-valid certificates:

```bash
micropki client validate \
  --cert ./app.cert.pem \
  --untrusted ./pki/certs/intermediate.cert.pem \
  --trusted ./pki/certs/ca.cert.pem \
  --validation-time 2035-01-01T00:00:00Z
```

## Sprint 6: revocation status checking

Standalone revocation status check:

```bash
micropki client check-status \
  --cert ./app.cert.pem \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ocsp-url http://127.0.0.1:8081/ocsp \
  --crl ./pki/crl/intermediate.crl.pem
```

Preference logic:

```text
1. Try OCSP first if --ocsp-url is supplied or an OCSP AIA URI exists in the certificate.
2. If OCSP returns good or revoked with a valid response, use that status.
3. If OCSP is unreachable, malformed, invalid, or unknown, fall back to CRL.
4. If CRL is valid and contains the certificate serial, status is revoked.
5. If CRL is valid and does not contain the serial, status is good.
6. If neither OCSP nor CRL can provide a definitive answer, status is unknown.
```

The client can parse OCSP responder URIs from Authority Information Access and CRL URLs from CRL Distribution Points when those extensions are present. Manual `--ocsp-url` and `--crl` flags override discovery.

## Sprint 6: structure

```text
micropki/
  validation.py
  revocation_check.py
  client.py
```

`validation.py` contains custom simplified RFC 5280 path building and validation. `revocation_check.py` contains CRL and OCSP client checks with fallback. `client.py` contains CSR generation, certificate request, validation and status-check helper functions.
