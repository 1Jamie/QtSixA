# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './gui/ui/qtsixa_managew.ui'
#
# Created by: PyQt4 UI code generator 4.11.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_ManageW(object):
    def setupUi(self, ManageW):
        ManageW.setObjectName(_fromUtf8("ManageW"))
        ManageW.resize(627, 292)
        self.horizontalLayout = QtGui.QHBoxLayout(ManageW)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.tabWidget = QtGui.QTabWidget(ManageW)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.dev = QtGui.QWidget()
        self.dev.setObjectName(_fromUtf8("dev"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.dev)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.listDev = QtGui.QTableWidget(self.dev)
        self.listDev.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.listDev.setDragDropOverwriteMode(False)
        self.listDev.setAlternatingRowColors(True)
        self.listDev.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)
        self.listDev.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.listDev.setObjectName(_fromUtf8("listDev"))
        self.listDev.setColumnCount(4)
        self.listDev.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.listDev.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.listDev.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.listDev.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        self.listDev.setHorizontalHeaderItem(3, item)
        self.listDev.horizontalHeader().setStretchLastSection(True)
        self.verticalLayout_2.addWidget(self.listDev)
        self.tabWidget.addTab(self.dev, _fromUtf8(""))
        self.input_prof = QtGui.QWidget()
        self.input_prof.setObjectName(_fromUtf8("input_prof"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.input_prof)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.listProf = QtGui.QListWidget(self.input_prof)
        self.listProf.setObjectName(_fromUtf8("listProf"))
        self.verticalLayout_3.addWidget(self.listProf)
        self.tabWidget.addTab(self.input_prof, _fromUtf8(""))
        self.horizontalLayout.addWidget(self.tabWidget)
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.label = QtGui.QLabel(ManageW)
        self.label.setText(_fromUtf8(""))
        self.label.setObjectName(_fromUtf8("label"))
        self.verticalLayout.addWidget(self.label)
        self.label_2 = QtGui.QLabel(ManageW)
        self.label_2.setText(_fromUtf8(""))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.verticalLayout.addWidget(self.label_2)
        self.b_add = QtGui.QPushButton(ManageW)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/plus.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.b_add.setIcon(icon)
        self.b_add.setObjectName(_fromUtf8("b_add"))
        self.verticalLayout.addWidget(self.b_add)
        self.b_remove = QtGui.QPushButton(ManageW)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/minus.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.b_remove.setIcon(icon1)
        self.b_remove.setObjectName(_fromUtf8("b_remove"))
        self.verticalLayout.addWidget(self.b_remove)
        self.b_edit = QtGui.QPushButton(ManageW)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/edit.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.b_edit.setIcon(icon2)
        self.b_edit.setObjectName(_fromUtf8("b_edit"))
        self.verticalLayout.addWidget(self.b_edit)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.b_close = QtGui.QPushButton(ManageW)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/close.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.b_close.setIcon(icon3)
        self.b_close.setObjectName(_fromUtf8("b_close"))
        self.verticalLayout.addWidget(self.b_close)
        self.horizontalLayout.addLayout(self.verticalLayout)

        self.retranslateUi(ManageW)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QObject.connect(self.b_close, QtCore.SIGNAL(_fromUtf8("clicked()")), ManageW.accept)
        QtCore.QMetaObject.connectSlotsByName(ManageW)

    def retranslateUi(self, ManageW):
        ManageW.setWindowTitle(_translate("ManageW", "QtSixA - Manage", None))
        item = self.listDev.horizontalHeaderItem(0)
        item.setText(_translate("ManageW", "Device ID", None))
        item = self.listDev.horizontalHeaderItem(1)
        item.setText(_translate("ManageW", "LED", None))
        item = self.listDev.horizontalHeaderItem(2)
        item.setText(_translate("ManageW", "Joystick", None))
        item = self.listDev.horizontalHeaderItem(3)
        item.setText(_translate("ManageW", "Input (Mouse/Keys)", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.dev), _translate("ManageW", "Devices", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.input_prof), _translate("ManageW", "Input Profiles", None))
        self.b_add.setText(_translate("ManageW", "&Add", None))
        self.b_remove.setText(_translate("ManageW", "&Remove", None))
        self.b_edit.setText(_translate("ManageW", "&Edit", None))
        self.b_close.setText(_translate("ManageW", "&Close", None))

import qtsixa_rc
