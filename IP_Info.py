# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'IP_Info.ui'
#
# Created by: PyQt5 UI code generator 5.15.7
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QStatusBar


class Ui_IP_info(object):
    def setupUi(self, IP_info):
        IP_info.setObjectName("IP_info")
        IP_info.resize(800, 500)
        self.centralwidget = QtWidgets.QWidget(IP_info)
        self.centralwidget.setObjectName("centralwidget")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(110, 50, 221, 38))
        self.lineEdit.setObjectName("lineEdit")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 10, 361, 24))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(10, 50, 101, 24))
        self.label_2.setObjectName("label_2")
        self.verticalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(10, 100, 131, 266))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_11 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_11.setObjectName("label_11")
        self.verticalLayout.addWidget(self.label_11)
        self.label_10 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_10.setObjectName("label_10")
        self.verticalLayout.addWidget(self.label_10)
        self.label_5 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_5.setObjectName("label_5")
        self.verticalLayout.addWidget(self.label_5)
        self.label_4 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_4.setObjectName("label_4")
        self.verticalLayout.addWidget(self.label_4)
        self.label_9 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_9.setObjectName("label_9")
        self.verticalLayout.addWidget(self.label_9)
        self.label_8 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_8.setObjectName("label_8")
        self.verticalLayout.addWidget(self.label_8)
        self.label_7 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_7.setObjectName("label_7")
        self.verticalLayout.addWidget(self.label_7)
        self.label_6 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_6.setObjectName("label_6")
        self.verticalLayout.addWidget(self.label_6)
        self.label_3 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_3.setObjectName("label_3")
        self.verticalLayout.addWidget(self.label_3)
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(140, 100, 200, 266))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_12 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_12.setText("")
        self.label_12.setObjectName("label_12")
        self.verticalLayout_2.addWidget(self.label_12)
        self.label_13 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_13.setText("")
        self.label_13.setObjectName("label_13")
        self.verticalLayout_2.addWidget(self.label_13)
        self.label_14 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_14.setText("")
        self.label_14.setObjectName("label_14")
        self.verticalLayout_2.addWidget(self.label_14)
        self.label_15 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_15.setText("")
        self.label_15.setObjectName("label_15")
        self.verticalLayout_2.addWidget(self.label_15)
        self.label_16 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_16.setText("")
        self.label_16.setObjectName("label_16")
        self.verticalLayout_2.addWidget(self.label_16)
        self.label_17 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_17.setText("")
        self.label_17.setObjectName("label_17")
        self.verticalLayout_2.addWidget(self.label_17)
        self.label_18 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_18.setText("")
        self.label_18.setObjectName("label_18")
        self.verticalLayout_2.addWidget(self.label_18)
        self.label_19 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_19.setText("")
        self.label_19.setObjectName("label_19")
        self.verticalLayout_2.addWidget(self.label_19)
        self.label_20 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_20.setText("")
        self.label_20.setObjectName("label_20")
        self.verticalLayout_2.addWidget(self.label_20)
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(10, 380, 181, 40))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(340, 50, 110, 40))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(510, 50, 141, 40))
        self.pushButton_3.setObjectName("pushButton_3")
        IP_info.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(IP_info)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 36))
        self.menubar.setObjectName("menubar")
        IP_info.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(IP_info)
        self.statusbar.setObjectName("statusbar")
        IP_info.setStatusBar(self.statusbar)

        self.status = QStatusBar(self.centralwidget)
        IP_info.setStatusBar(self.status)

        self.retranslateUi(IP_info)
        QtCore.QMetaObject.connectSlotsByName(IP_info)

    def retranslateUi(self, IP_info):
        _translate = QtCore.QCoreApplication.translate
        IP_info.setWindowTitle(_translate("IP_info", "MainWindow"))
        self.label.setText(_translate("IP_info", "Input IP for get information about them.\nIf you not fill the IP-field, you get info about your IP Address."))
        self.label_2.setText(_translate("IP_info", "IP Address"))
        self.label_11.setText(_translate("IP_info", "IP:"))
        self.label_10.setText(_translate("IP_info", "Int prov:"))
        self.label_5.setText(_translate("IP_info", "Org:"))
        self.label_4.setText(_translate("IP_info", "Country:"))
        self.label_9.setText(_translate("IP_info", "Region Name:"))
        self.label_8.setText(_translate("IP_info", "City:"))
        self.label_7.setText(_translate("IP_info", "ZIP:"))
        self.label_6.setText(_translate("IP_info", "Lat:"))
        self.label_3.setText(_translate("IP_info", "Long:"))
        self.pushButton.setText(_translate("IP_info", "Get location on map"))
        self.pushButton_2.setText(_translate("IP_info", "Get Info"))
        self.pushButton_3.setText(_translate("IP_info", "Return Toolbar"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    IP_info = QtWidgets.QMainWindow()
    ui = Ui_IP_info()
    ui.setupUi(IP_info)
    IP_info.show()
    sys.exit(app.exec_())
