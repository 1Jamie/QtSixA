# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './gui/ui/qtsixa_sixpairw.ui'
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

class Ui_SixpairW(object):
    def setupUi(self, SixpairW):
        SixpairW.setObjectName(_fromUtf8("SixpairW"))
        SixpairW.resize(409, 300)
        self.p_1 = QtGui.QWizardPage()
        self.p_1.setObjectName(_fromUtf8("p_1"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.p_1)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.label_1 = QtGui.QLabel(self.p_1)
        self.label_1.setObjectName(_fromUtf8("label_1"))
        self.verticalLayout_3.addWidget(self.label_1)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_3.addItem(spacerItem)
        self.groupBox = QtGui.QGroupBox(self.p_1)
        self.groupBox.setAlignment(QtCore.Qt.AlignCenter)
        self.groupBox.setObjectName(_fromUtf8("groupBox"))
        self.gridLayout = QtGui.QGridLayout(self.groupBox)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.r_sixaxis = QtGui.QRadioButton(self.groupBox)
        self.r_sixaxis.setChecked(True)
        self.r_sixaxis.setObjectName(_fromUtf8("r_sixaxis"))
        self.gridLayout.addWidget(self.r_sixaxis, 0, 0, 1, 1)
        self.r_keypad = QtGui.QRadioButton(self.groupBox)
        self.r_keypad.setObjectName(_fromUtf8("r_keypad"))
        self.gridLayout.addWidget(self.r_keypad, 1, 0, 1, 1)
        self.verticalLayout_3.addWidget(self.groupBox)
        SixpairW.addPage(self.p_1)
        self.p_2 = QtGui.QWizardPage()
        self.p_2.setObjectName(_fromUtf8("p_2"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.p_2)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.label_2 = QtGui.QLabel(self.p_2)
        self.label_2.setText(_fromUtf8(""))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.verticalLayout_2.addWidget(self.label_2)
        self.textEdit = QtGui.QTextEdit(self.p_2)
        self.textEdit.setReadOnly(True)
        self.textEdit.setObjectName(_fromUtf8("textEdit"))
        self.verticalLayout_2.addWidget(self.textEdit)
        SixpairW.addPage(self.p_2)

        self.retranslateUi(SixpairW)
        QtCore.QMetaObject.connectSlotsByName(SixpairW)

    def retranslateUi(self, SixpairW):
        SixpairW.setWindowTitle(_translate("SixpairW", "QtSixA - Sixpair", None))
        self.label_1.setText(_translate("SixpairW", "<font size=4 ><b>Getting ready for Sixpair setup...</b></font><br><br>Before continue please make sure that your bluetooth<br>stick/device/pen is connected to the PC and that the Sixaxis/Keypad<br>is connected to the PC\'s USB<br>", None))
        self.groupBox.setTitle(_translate("SixpairW", "Device Type", None))
        self.r_sixaxis.setText(_translate("SixpairW", "Sixaxis/DualShock3", None))
        self.r_keypad.setText(_translate("SixpairW", "Keypad", None))

