# networks-Internet-protocols-course-tasks
### traceroute
Реализация traceroute с возможностью отправки пакетов по ICMP, TCP и UDP.

Запуск:

python3 traceroute.py [OPTIONS] IP_ADDRESS {tcp | udp | icmp}

Опции [OPTIONS]:

* -t — таймаут ожидания ответа (по умолчанию 2сек)
* -p — порт (для tcp или udp)
* -n — максимальное количество запросов
* -v — вывод номера автономной системы для каждого ip-адреса

Пример запуска:

traceroute -p 53 1.1.1.1 tcp

В ответ утилита выдает информацию о маршруте в формате:
NUM IP [TIME,ms]

Где NUM - порядковый номер, с 1.

Если задана опция -v, вывод содержит колонку [AS] с номером автономной системы.

Если истёк таймаут, вместо IP выводится "*".

### dns resolver
Реализация DNS-резолвера, который итеративно опрашивает серверы, 
ответственные за зоны, начиная с корневой, и возвращает результат клиенту.

### http task
Программа находит топ-100 самых активных авторов выбранной организации и 
записывает результат в csv формате. 

При подсчёте игнорируются merge-коммиты (начинаются с «Merge pull request 
#»). 

Активность автора считается как количество его коммитов в репозиториях этой 
организации. 

Автора идентифицируется по адресу электронной почты.

В папке таска лежит результат для Twitter-a.

Запуск:

python3 org_csv.py {org_name} {your_github_api_token}

