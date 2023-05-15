#!/usr/bin/env python3

from Authentication import Ui_Authentication
from Create_new_account import Ui_Create_new_account
from Forgot_password import Ui_Forgot_password
from Macchanger import Ui_Macchanger
from NetScanner import Ui_NetworkScanner
from Toolbar import Ui_Toolbar
from IP_Info import Ui_IP_info
from Profile import Ui_MainWindow_profile
from Check_users import Ui_MainWindow_users
from Check_logs import Ui_MainWindow_logs
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QMessageBox
import sys, re, scapy.all as scapy, subprocess, requests, folium, sqlite3, os
import hashlib
from datetime import datetime, date


class SQL_database():       # Класс базы данных, который отвечает за авторизацию и ведение логов
    def __init__(self):
        self.user = ''      # Объект, благодаря которому ведется учет текущего пользователя
        self.sign_in = ''   # Объект, отвечающий за то, входит ли пользователь в аккаунт или выходит, необходим для ведения логов
        self.flag = True

    def set_sign_in(self, flag1):       
        if flag1:
            self.sign_in = 'entrance'
        else:
            self.sign_in = 'exit'
    
    def get_sign_in(self):
        return self.sign_in
    
    def set_user(self, user):       
        self.user = user

    def get_user(self):
        return self.user
        
    def AddUser(self, login, password, secret_question, secret_answer):     # Функция добавления нового пользователя в базу данных
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute("SELECT id FROM users WHERE login= ?;", (login,))
            ans = cursor.fetchall()
        if len(ans) != 0:
            return False
        else:
            current_date = '.'.join(str(date(int(datetime.now().year), int(datetime.now().month), int(datetime.now().day))).split('-'))
            new_password = hashlib.md5(password.encode('utf-8')).hexdigest()
            new_secret_answer = hashlib.md5(secret_answer.encode('utf-8')).hexdigest()
            with sqlite3.connect('users.db') as db:
                cursor = db.cursor()
                cursor.execute("""INSERT INTO users(login, password, secret_question, secret_answer, reg_date)
                                VALUES(?, ?, ?, ?, ?);""",
                    (login, new_password, secret_question, new_secret_answer, current_date))
                return True
    
    def Auth(self, login, password):        # Функция авторизации пользователя
        try:
            with sqlite3.connect('users.db') as db:
                cursor = db.cursor()
                cursor.execute("SELECT password FROM users WHERE login=?;", (login,))
                ans_password = cursor.fetchall()[0][0]
                new_password = hashlib.md5(password.encode('utf-8')).hexdigest()
            if new_password == ans_password:
                return True
            else:
                return 'incorrect password'
        except Exception:
            return 'incorrect login'
    
    def Forgot_password_login_check(self, login):       # Когда пользователь забывает пароль, первым делом необходимо указать логин, эта функция его проверяет
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            try:
                check = cursor.execute("SELECT secret_question FROM users WHERE login=?;", (login,)).fetchone()[0]
                return True
            except Exception:
                return False

    def Get_question(self, login):      # После того, как логин был верно указан, пользователю возвращается секретный вопрос, на который необходимо ответить
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            question = cursor.execute("SELECT secret_question FROM users WHERE login=?;", (login,)).fetchone()[0]
            return question
        
    def Send_answer(self, login, answer):       # Сюда присылается секретный вопрос, он хешируется и сравнивается в сохраненным в бд хешем
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            input_answer = hashlib.md5(answer.encode('utf-8')).hexdigest()
            cursor.execute("SELECT secret_answer FROM users WHERE login=?;", (login,))
            secret_answer = cursor.fetchall()[0][0]
            if secret_answer == input_answer:
                return True
            else:
                return False
    
    def Get_reg_date(self, login):      # функция, которая возвращает дату регистрации по логину пользователя
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            date = cursor.execute("SELECT reg_date FROM users WHERE login=?;", (login,)).fetchone()[0]
            return date

    def New_password(self, login, new_password):        # Функция, которая перезаписывает хеш пароля в бд
        new_password_hash = hashlib.md5(new_password.encode('utf-8')).hexdigest()
        print(new_password_hash)
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password=? WHERE login=?;", (new_password_hash, login))
            cursor.execute('select * from users;')
            a = cursor.fetchall()
            print(a)

    def add_log(self):      # Функция, которая добавляет новый лог при авторизации или при выходе
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            current_date = datetime.now().strftime("%Y %m %d %H %M %S").split()
            date = '.'.join(current_date[:3])
            time = '.'.join(current_date[3:])
            datetime_for_log = date + '-' + time
            login_id = cursor.execute("""SELECT id FROM users WHERE login = ?""", (database.user,)).fetchall()[0][0]
            cursor.execute("""INSERT INTO logs(datetime, sign_in, fk_users_login_id) VALUES(?, ?, ?)""",
            (datetime_for_log, database.get_sign_in(), login_id))
            db.commit()
        sign_in = 1
        
    def Get_users_list(self, info, filter_info):        # Возвращает список пользователей, основанный на примененных фильтрах
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            if len(info) != 0:
                if filter_info == 'login':
                    result = cursor.execute("SELECT id, login, reg_date FROM users WHERE login=?;", (info,)).fetchall()
                else:
                    result = cursor.execute("SELECT id, login, reg_date FROM users WHERE reg_date=?", (info,)).fetchall()
            else:
                result = cursor.execute("SELECT id, login, reg_date FROM users;").fetchall()
            return result
    
    def Get_logs_list(self, begin_date, end_date, login):       # Возвращает лог, отфильтрованный по примененным фильтрам
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            if not begin_date and not end_date and not login:
                log_result = cursor.execute("""SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in
                                                FROM
                                                    users
                                                JOIN logs
                                                    ON users.id = logs.fk_users_login_id""").fetchall()
            elif begin_date and not end_date and not login:
                log_result = cursor.execute(""" SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in 
                                                FROM 
                                                    users
                                                JOIN logs 
                                                    ON users.id = logs.fk_users_login_id WHERE
                                                    logs.datetime > ?""", (begin_date,)).fetchall()
            elif begin_date and end_date and not login:
                log_result = cursor.execute(""" SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in
                                                FROM
                                                    users
                                                JOIN logs
                                                    ON users.id = logs.fk_users_login_id WHERE logs.datetime
                                                    BETWEEN ? AND ?""", (begin_date, end_date)).fetchall()
            elif begin_date and end_date and login:
                log_result = cursor.execute("""SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in
                                                FROM
                                                    users
                                                JOIN logs
                                                    ON users.id = logs.fk_users_login_id WHERE logs.datetime
                                                    BETWEEN ? AND ? AND users.login = ?""",
                                                    (begin_date, end_date, login)).fetchall()
            elif begin_date and not end_date and login:
                log_result = cursor.execute("""SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in
                                                FROM
                                                    users
                                                JOIN logs
                                                    ON users.id = logs.fk_users_login_id WHERE
                                                    logs.datetime > ? AND users.login = ?""",
                                                    (begin_date, login)).fetchall()
            elif not begin_date and end_date and login:
                log_result = cursor.execute("""SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in
                                                FROM
                                                    users
                                                JOIN logs
                                                    ON users.id = logs.fk_users_login_id WHERE
                                                    logs.datetime < ? AND users.login = ?""",
                                                    (end_date, login)).fetchall()
            elif not begin_date and not end_date and login:
                log_result = cursor.execute("""SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in
                                                FROM
                                                    users
                                                JOIN logs
                                                    ON users.id = logs.fk_users_login_id WHERE
                                                    users.login = ?""", (login,)).fetchall()
            elif not begin_date and end_date and not login:
                log_result = cursor.execute("""SELECT
                                                    logs.datetime,
                                                    users.login,
                                                    logs.sign_in
                                                FROM
                                                    users
                                                JOIN logs
                                                    ON users.id = logs.fk_users_login_id WHERE
                                                    logs.datetime < ?""", (end_date,)).fetchall()
            return log_result
            


class Users_win(QMainWindow, Ui_MainWindow_users):      # Окно, которое может открыть только admin для просмотра списка зарегистрированных пользователей
    def __init__(self):
        super(Users_win, self).__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.search_users)
        self.pushButton_2.clicked.connect(self.Return_Profile)
        self.pushButton_3.clicked.connect(self.Write_to_file)
    
    def Write_to_file(self):
        users_list = database.Get_users_list(self.lineEdit.text(), self.comboBox.currentText())
        current_date = datetime.now().strftime("%Y %m %d %H %M %S").split()
        date = '.'.join(current_date[:3])
        time = '.'.join(current_date[3:])
        datetime_for_write = date + '-' + time
        with open(f'{datetime_for_write}_users_list.txt', 'w') as output_file:
            for user in users_list:
                result = ' '.join([str(i) for i in user])
                output_file.write(result + '\n')

    def search_users(self, date):
        users_list = database.Get_users_list(self.lineEdit.text(), self.comboBox.currentText())
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(['id', 'login', 'reg_date'])
        self.tableWidget.setRowCount(len(users_list))
        for x, row in enumerate(users_list):
            for y, elem in enumerate(row):
                self.tableWidget.setItem(x, y, QTableWidgetItem(str(elem)))

    def Return_Profile(self):
        Users_window.hide()
        profile_window.show()

    def closeEvent(self, event):
        profile_window.show()

class Logs_win(QMainWindow, Ui_MainWindow_logs):        # Окно, которое может открыть только admin для просмотра логов
    def __init__(self):
        super(Logs_win, self).__init__()
        self.setupUi(self)
        self.pushButton_2.clicked.connect(self.Return_Profile)
        self.pushButton.clicked.connect(self.Search_logs)
        self.pushButton_3.clicked.connect(self.Write_to_file)

    def Write_to_file(self):
        logs_list = database.Get_logs_list(self.lineEdit.text(), self.lineEdit_2.text(), self.lineEdit_3.text())
        current_date = datetime.now().strftime("%Y %m %d %H %M %S").split()
        date = '.'.join(current_date[:3])
        time = '.'.join(current_date[3:])
        datetime_for_write = date + '-' + time
        with open(f'{datetime_for_write}_logs_list.txt', 'w') as output_file:
            for log in logs_list:
                result = ' '.join([str(i) for i in log])
                output_file.write(result + '\n')

    def Return_Profile(self):
        Logs_window.hide()
        profile_window.show()

    def Search_logs(self):
        log_result = database.Get_logs_list(self.lineEdit.text(), self.lineEdit_2.text(), self.lineEdit_3.text())
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(['datetime', 'login', 'sign_in'])
        self.tableWidget.setRowCount(len(log_result))
        for x, row in enumerate(log_result):
            for y, elem in enumerate(row):
                self.tableWidget.setItem(x, y, QTableWidgetItem(str(elem)))
    
    def closeEvent(self, event):
        profile_window.show()
    

class Profile(QMainWindow, Ui_MainWindow_profile):       # Окно, в котором пользователь может увидеть свой логин, дату регистрации аккаунта и сменить пароль
    def __init__(self):
        super(Profile, self).__init__()
        self.setupUi(self)
        self.user = ''
        self.pushButton.clicked.connect(self.Change_password)
        self.pushButton_2.clicked.connect(self.Check_users)
        self.pushButton_3.clicked.connect(self.Check_logs)
        self.pushButton_4.clicked.connect(self.Return_toolbar)
    
    def Return_toolbar(self):
        profile_window.hide()
        self.pushButton_2.hide()
        self.pushButton_3.hide()
        toolbar.show()
    
    def Check_logs(self):
        Logs_window.show()
        profile_window.hide()

    def update_profile(self):
        self.user = database.get_user()
        if auth.flag:
            if self.user == 'admin':
                self.pushButton_2.show()
                self.pushButton_3.show()
            self.label.setText(f'Your login/username: {self.user}\nRegistration date: {database.Get_reg_date(self.user)}')
                
    def Check_users(self):
        profile_window.hide()
        Users_window.show()

    def  Change_password(self):
        forgot.show()
        forgot.label.setText(self.user)

    def closeEvent(self, event):
        self.pushButton_2.hide()
        self.pushButton_3.hide()
        toolbar.show()


class NetworkScanner(QMainWindow, Ui_NetworkScanner):       # Окно, открывающее сетевой сканер
    def __init__(self):
        super(NetworkScanner, self).__init__()
        self.setupUi(self)
        self.pushButton_3.clicked.connect(self.Return_toolbar)
        self.pushButton_2.clicked.connect(self.StartScanning)

    def StartScanning(self):
        self.listWidget.clear()
        if len(self.lineEdit.text()) != 0:
            self.listWidget.addItem('IP\t\tMAC Address\n-------------------------------------------------------------') 
            arp_request = scapy.ARP(pdst=self.lineEdit.text())      # создается arp пакет с диапазоном ip
            broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')        # создается ethernet пакет с широковещательным запросом
            arp_request_broadcast = broadcast / arp_request         # пакеты скреиваются
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]       # отправка пакетов и получение нужным нам хостов

            clients_list = []
            for element in answered_list:
                client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
                clients_list.append(client_dict)
            for client in clients_list:
                    self.listWidget.addItem(f'{client["ip"]}\t\t{client["mac"]}')
            self.listWidget.addItem('\n')
        else:
            self.listWidget.addItem('[-] Input IP-range')
    
    def Return_toolbar(self):
        toolbar.show()
        networkScanner_window.hide()

    def closeEvent(self, event):
        toolbar.show()


def GetInterfaces():        # Функция, которыя используется в macchanger для получения списка интерфейсов
        ifconfig_result = str(subprocess.check_output(['ifconfig', '-s']))
        interfaces_list = [i.split()[0] for i in str(ifconfig_result).split('\\n') \
                                if i.split()[0] != "b'Iface" and i.split()[0] != "'"]
        return interfaces_list

def get_current_mac(interface):        # Возвращает текущий mac адрес данного интерфейса
    ifconfig_result = subprocess.check_output(['ifconfig', interface]).decode('utf-8')
    mac_address_search_result = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', ifconfig_result)
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        changer_window.listWidget.addItem('[-] Could not read MAC address.')


class Macchanger(QMainWindow, Ui_Macchanger):       # окно, в котором пользователь может сменить mac адрес того или иного интерфейса
    def __init__(self):
        super(Macchanger, self).__init__()
        self.setupUi(self)
        self.listWidget.addItem('Your interfaces:')
        self.listWidget.addItems(GetInterfaces())
        self.listWidget.addItem('##################')
        self.pushButton.clicked.connect(self.Change_mac)
        self.pushButton_3.clicked.connect(self.Current_mac)
        self.pushButton_2.clicked.connect(self.Return_toolbar)
    
    def Return_toolbar(self):
        self.listWidget.clear()
        self.listWidget.addItem('Your interfaces:')
        self.listWidget.addItems(GetInterfaces())
        self.listWidget.addItem('##################')
        toolbar.show()
        changer_window.hide()

    def Current_mac(self):
        if len(self.lineEdit_2.text()) != 0 and self.lineEdit_2.text() in GetInterfaces():
            if get_current_mac(self.lineEdit_2.text()) != None:
                self.listWidget.addItem(f"""[+] Current MAC for {self.lineEdit_2.text()} 
                is {get_current_mac(self.lineEdit_2.text())}""")
            else:
                self.listWidget.addItem("[-] This interface doesn't have MAC Address")
        elif len(self.lineEdit_2.text()) == 0 or self.lineEdit_2.text() not in GetInterfaces():
            self.listWidget.addItem('[-] Input valid interface')

    def Change_mac(self):
        if len(self.lineEdit.text()) != 0 and len(self.lineEdit_2.text()) != 0 and self.lineEdit_2.text() in GetInterfaces():
            self.listWidget.addItem(f'[+] Changing MAC address for {self.lineEdit_2.text()}')
            subprocess.call(['ifconfig', self.lineEdit_2.text(), 'down'])
            subprocess.call(['ifconfig', self.lineEdit_2.text(), 'hw', 'ether', self.lineEdit.text()])
            subprocess.call(['ifconfig', self.lineEdit_2.text(), 'up'])
            if get_current_mac(self.lineEdit_2.text()) == self.lineEdit.text():
                self.listWidget.addItem(f'[+] MAC address successfully changed to {self.lineEdit.text()}')
            else:
                self.listWidget.addItem('[-] MAC address did not get changed')
        else:
            self.listWidget.addItem('[-] Input valid interface or new MAC Address in field')

    def closeEvent(self, event):
        toolbar.show()


class NoValidIP(Exception):
        pass


class IP_info(QMainWindow, Ui_IP_info):         # окно, в котором отображается информация об ip адресе, введенном пользователем
    def __init__(self):
        super(IP_info, self).__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.GetMap)
        self.pushButton_2.clicked.connect(self.GetInfo)
        self.pushButton_3.clicked.connect(self.Return_toolbar)

    def GetMap(self):
        if not self.label_19 or not self.label_20:
            self.status.showMessage('No lat or long')
            self.status.setStyleSheet('background:red')
        elif not self.lineEdit.text():
            self.status.showMessage('Input IP for create map')
            self.status.setStyleSheet('background:red')
        else:    
            map = folium.Map(location=[self.label_19.text(), self.label_20.text()])
            map.save(f'{self.label_12.text()}_{self.label_17.text()}')
            self.status.showMessage(f'Succesful save map {self.label_12.text()}_{self.label_17.text()}')
            self.status.setStyleSheet('background:green')

    def Return_toolbar(self):
        ip_info_window.hide()
        self.label_12.clear()
        self.label_13.clear()
        self.label_14.clear()
        self.label_15.clear()
        self.label_16.clear()
        self.label_17.clear()
        self.label_18.clear()
        self.label_19.clear()
        self.label_20.clear()
        self.lineEdit.clear()
        self.status.clearMessage()
        self.status.setStyleSheet('background:None')
        toolbar.show()

    def GetInfo(self):
        self.status.setStyleSheet('background:None')
        self.status.clearMessage()
        try:
            flag = True
            check_ip = [int(i) for i  in self.lineEdit.text().split('.') if i.isdigit()]
            if len(check_ip) == 4:
                for num in check_ip:
                    if num not in range(0, 255):
                        flag = False
            else:
                flag = False
            if not self.lineEdit.text():
                flag = True
            if not flag:
                raise NoValidIP
            else:
                request = requests.get(url=f'http://ip-api.com/json/{self.lineEdit.text()}').json()     # делается запрос на сайт с конкретным ip
                IpIfnfo = {                             # создается словарь, в который помещаются значения, которые мы получаем из запроса выше
                        'IP': request.get('query'),
                        'Int prov': request.get('isp'),
                        'Org': request.get('org'),
                        'Country': request.get('country'),
                        'Region Name': request.get('regionName'),
                        'City': request.get('city'),
                        'ZIP': request.get('zip'),
                        'Lat': request.get('lat'),
                        'Lon': request.get('lon')
                    }
                self.label_12.setText(IpIfnfo['IP'])
                self.label_13.setText(IpIfnfo['Int prov'])
                self.label_14.setText(IpIfnfo['Org'])
                self.label_15.setText(IpIfnfo['Country'])
                self.label_16.setText(IpIfnfo['Region Name'])
                self.label_17.setText(IpIfnfo['City'])
                self.label_18.setText(IpIfnfo['ZIP'])
                self.label_19.setText(str(IpIfnfo['Lat']))
                self.label_20.setText(str(IpIfnfo['Lon']))
        except NoValidIP:
            self.status.showMessage('Please, input valid IP address')
            self.status.setStyleSheet('background:red')
        except requests.exceptions.ConnectionError:
            self.status.showMessage('Please, check your connection!')
            self.status.setStyleSheet('background:red')

    def closeEvent(self, event):
        toolbar.show()


class Toolbar(QMainWindow, Ui_Toolbar):         # окно, в котором отображаются все инструменты приложения
    def __init__(self):
        super(Toolbar, self).__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.ChangerWindow)
        self.pushButton_3.clicked.connect(self.ScannerWindow)
        self.pushButton_2.clicked.connect(self.IpInfoWindow)
        self.pushButton_5.clicked.connect(self.Exit)
        self.pushButton_4.clicked.connect(self.Profile)
    
    def Profile(self):
        toolbar.hide()
        profile_window.update_profile()
        profile_window.show()

    def Exit(self):
        reply = QMessageBox.question\
                (self, 'Warning!',
                "You want to leave your account?",
                QMessageBox.Yes,
                QMessageBox.No)
        if reply == QMessageBox.Yes:
            toolbar.hide()
            database.set_sign_in(flag1=False)
            database.add_log()
            auth.show()
    
    def ScannerWindow(self):
        toolbar.hide()
        networkScanner_window.show()
    
    def ChangerWindow(self):
        toolbar.hide()
        changer_window.show()

    def IpInfoWindow(self):
        toolbar.hide()
        ip_info_window.show()

    def closeEvent(self, event):
        if (profile_window.hide() or profile_window.close()) and (networkScanner_window.hide() or networkScanner_window.close()) and \
                    (changer_window.hide() or changer_window.close()) and (ip_info_window.hide() or ip_info_window.close()):
                    reply = QMessageBox.question\
                                        (self, 'Warning!',
                                        "You want to leave your account?",
                                        QMessageBox.Yes,
                                        QMessageBox.No)
                    if reply == QMessageBox.Yes:
                        event.accept()
                        auth.show()
                        database.set_sign_in(flag1=False)
                        database.add_log()
                    else:
                        event.ignore()
    

class Forgot_password(QMainWindow, Ui_Forgot_password):         # окно, отвечающее за смену забытого пароля
    def __init__(self):
        super(Forgot_password, self).__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.Enter)
        self.pushButton_2.clicked.connect(self.SendAnswer)
        self.replace_password.clicked.connect(self.Replace_password)
        self.return_toolbar.clicked.connect(self.ReturnAuth)

    def ReturnAuth(self):
        auth.show()
        forgot.hide()

    def Replace_password(self):
        if len(self.new_password.text()) != 0 and len(self.new_password_repeat.text()) != 0:
            if self.new_password.text() == self.new_password_repeat.text():
                database.New_password(self.lineEdit_2.text(), self.new_password.text())
                self.status.showMessage('Success!')
                self.status.setStyleSheet('background:green')        
            else:
                self.status.showMessage('Passwords do no mach')
                self.status.setStyleSheet('background:red')
        else:
            self.status.showMessage('Fields must not be empty')
            self.status.setStyleSheet('background:red')

    def SendAnswer(self):
        if database.Send_answer(self.lineEdit_2.text(), self.lineEdit.text()):
            self.new_label_1.show()
            self.new_label_2.show()
            self.new_password.show()
            self.new_password_repeat.show()
            self.replace_password.show()
            self.status.showMessage('Success answered the question!')
            self.status.setStyleSheet('background:green')
        else:
            self.status.showMessage('Incorrect answer.')
            self.status.setStyleSheet('background:red')

    def Enter(self):
        if database.Forgot_password_login_check(self.lineEdit_2.text()):
            self.lineEdit.show()
            self.pushButton_2.show()
            self.label_2.setText(f'{self.label_2.text()} {database.Get_question(self.lineEdit_2.text())}')
            self.label_2.show()
            self.status.showMessage('Answer the question.')
            self.status.setStyleSheet('background:green')
            self.lineEdit_2.setReadOnly(True)
        else:
            self.status.showMessage('A user does not exist.')
            self.status.setStyleSheet('background:red')

    def closeEvent(self, event):
        auth.show()


class Create_new_account(QMainWindow, Ui_Create_new_account):       # окно для регистрации нового пользователя
    def __init__(self):
        super(Create_new_account, self).__init__()
        self.setupUi(self)
        self.pushButton_3.clicked.connect(self.Create)
    
    def Create(self):
        if len(self.lineEdit.text()) != 0 and len(self.lineEdit_2.text()) != 0 and \
                    len(self.lineEdit_3.text()) != 0 and len(self.lineEdit_4.text()) != 0:
            if self.lineEdit_2.text() == self.lineEdit_3.text():
                if database.AddUser(self.lineEdit.text(), self.lineEdit_2.text(), self.lineEdit_4.text(), self.lineEdit_5.text()):
                    self.status.showMessage('Success!')
                    self.status.setStyleSheet('background:green')
                else:
                    self.status.showMessage('A user with such a login already exists')
                    self.status.setStyleSheet('background:red')
            else:
                self.status.showMessage('Passwords do no match')
                self.status.setStyleSheet('background:red')
        else:
            self.status.showMessage('Fields must not be empty')
            self.status.setStyleSheet('background:red')
        self.lineEdit.setText('')
        self.lineEdit_2.setText('')
        self.lineEdit_3.setText('')
        self.lineEdit_4.setText('')
        self.lineEdit_5.setText('')

    def closeEvent(self, event):
        auth.show()


class Authentication(QMainWindow, Ui_Authentication):       # самое первое окно, в котором происходит авторизация пользователей
    def __init__(self):
        super(Authentication, self).__init__()
        self.setupUi(self)
        self.pushButton_2.clicked.connect(self.SignIn)
        self.pushButton_3.clicked.connect(self.CreateNewAccount)
        self.pushButton.clicked.connect(self.ForgotPassword)
        self.flag = False

    def ForgotPassword(self):
        forgot.status.clearMessage()
        forgot.status.setStyleSheet('background:None')
        forgot.lineEdit.hide()
        forgot.label_2.hide()
        forgot.pushButton_2.hide()
        forgot.lineEdit_2.setText('')
        forgot.lineEdit.setText('')
        forgot.lineEdit_2.setReadOnly(False)
        forgot.new_label_1.hide()
        forgot.new_label_2.hide()
        forgot.new_password.clear()
        forgot.new_password.hide()
        forgot.new_password_repeat.clear()
        forgot.new_password_repeat.hide()
        forgot.replace_password.hide()
        forgot.show()

    def SignIn(self):
        if database.Auth(self.lineEdit.text(), self.lineEdit_2.text()) == True:
            database.set_user(self.lineEdit.text())
            database.set_sign_in(flag1=True)
            database.add_log()
            self.lineEdit.clear()
            self.lineEdit_2.clear()
            self.flag = True
            toolbar.show()
            auth.hide()
        elif database.Auth(self.lineEdit.text(), self.lineEdit_2.text()) == 'incorrect login':
            self.status.showMessage('Incorrect Username')
            self.status.setStyleSheet('background:red')
        elif database.Auth(self.lineEdit.text(), self.lineEdit_2.text()) == 'incorrect password':
            self.status.showMessage('Incorrect Password')
            self.status.setStyleSheet('background:red')
        
    def CreateNewAccount(self):
        create.lineEdit.setText('')
        create.lineEdit_2.setText('')
        create.lineEdit_3.setText('')
        create.lineEdit_4.setText('')
        create.lineEdit_5.setText('')
        create.status.setStyleSheet('background:None')
        create.status.clearMessage()
        create.show()
    
    def closeEvent(self, event):
        auth.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    database = SQL_database()
    auth = Authentication()
    auth.show()
    profile_window = Profile()
    ip_info_window = IP_info()
    create = Create_new_account()
    forgot = Forgot_password()
    toolbar = Toolbar()
    Users_window = Users_win()
    Logs_window = Logs_win()
    changer_window = Macchanger()
    networkScanner_window = NetworkScanner()
    sys.exit(app.exec())
