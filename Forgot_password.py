# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Forgot_password.ui'
#
# Created by: PyQt5 UI code generator 5.15.7
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QStatusBar


class Ui_Forgot_password(object):
    def setupUi(self, Forgot_password):
        Forgot_password.setObjectName("Forgot_password")
        Forgot_password.resize(800, 387)
        self.centralwidget = QtWidgets.QWidget(Forgot_password)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(40, 50, 351, 28))
        self.label.setObjectName("label")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(330, 120, 261, 42))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit.hide()
        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(330, 50, 261, 42))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(40, 120, 251, 28))
        self.label_2.setObjectName("label_2")
        self.label_2.hide()
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(620, 50, 127, 44))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(620, 120, 141, 44))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_2.hide()
        Forgot_password.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Forgot_password)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 42))
        self.menubar.setObjectName("menubar")
        Forgot_password.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Forgot_password)
        self.statusbar.setObjectName("statusbar")
        Forgot_password.setStatusBar(self.statusbar)

        self.status = QStatusBar(self.centralwidget)
        self.status.setGeometry(QtCore.QRect(20, 250, 100, 20))
        Forgot_password.setStatusBar(self.status)

        self.new_password = QtWidgets.QLineEdit(self.centralwidget)
        self.new_password.setGeometry(QtCore.QRect(330, 200, 261, 42))
        self.new_password.hide()

        self.new_password_repeat = QtWidgets.QLineEdit(self.centralwidget)
        self.new_password_repeat.setGeometry(QtCore.QRect(330, 270, 261, 42))
        self.new_password_repeat.hide()

        self.replace_password = QtWidgets.QPushButton(self.centralwidget)
        self.replace_password.setText('Change password')
        self.replace_password.setGeometry(QtCore.QRect(620, 235, 127, 44))
        self.replace_password.hide()

        self.new_label_1 = QtWidgets.QLabel(self.centralwidget)
        self.new_label_1.setGeometry(QtCore.QRect(40, 200, 251, 28))
        self.new_label_1.setText('New password')
        self.new_label_1.hide()
        
        self.new_label_2 = QtWidgets.QLabel(self.centralwidget)
        self.new_label_2.setGeometry(QtCore.QRect(40, 270, 251, 28))
        self.new_label_2.setText('Repeat new password')
        self.new_label_2.hide()

        self.return_toolbar = QtWidgets.QPushButton(self.centralwidget)
        self.return_toolbar.setText('Return to Authentication')
        self.return_toolbar.setGeometry(QtCore.QRect(100, 10, 140, 44))
        

        self.retranslateUi(Forgot_password)
        QtCore.QMetaObject.connectSlotsByName(Forgot_password)

    def retranslateUi(self, Forgot_password):
        _translate = QtCore.QCoreApplication.translate
        Forgot_password.setWindowTitle(_translate("Forgot_password", "Forgot_password"))
        self.label.setText(_translate("Forgot_password", "Enter your username/login"))
        self.label_2.setText(_translate("Forgot_password", "Your question: "))
        self.pushButton.setText(_translate("Forgot_password", "Enter"))
        self.pushButton_2.setText(_translate("Forgot_password", "Send answer"))



if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Forgot_password = QtWidgets.QMainWindow()
    ui = Ui_Forgot_password()
    ui.setupUi(Forgot_password)
    Forgot_password.show()
    sys.exit(app.exec_())