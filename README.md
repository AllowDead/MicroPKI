Инструкция по сборке и установке
Клонируйте репозиторий.
Создайте и активируйте виртуальное окружение:
python -m venv venvsource venv/bin/activate  # Linux/Macvenv\Scripts\activate     # Windows
Установите зависимости:
pip install -r requirements.txt
Установите пакет в режиме разработки (для доступа к команде micropki):
pip install -e .
Пример:
MSYS_NO_PATHCONV=1 micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 --passphrase-file ./secrets/ca.pass --out-dir ./pki --validity-days 7300 --log-file ./logs/ca-init.log
Тестирование:
openssl x509 -in ./pki/certs/ca.cert.pem -text -noout
openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/ca.cert.pem
pytest tests/ -v