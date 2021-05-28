#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QString byteVectorToQString(QVector<uint8_t> vec) {
    QByteArray byteArray;

    for(const auto &i: vec)
        byteArray.push_back(i);
    auto text = QString::fromLocal8Bit(byteArray);

    return text;
}

QVector<uint8_t> QStringToByteVector(QString text) {
    QByteArray byteArray = text.toLocal8Bit();
    QVector<uint8_t> textBytes;

    for(const auto &i : byteArray)
        textBytes.push_back(i);

    return textBytes;
}

void MainWindow::on_encryptButton_clicked() {
    QVector<uint8_t> plainBytes = QStringToByteVector(ui->plainTextEdit->toPlainText().trimmed());
    QVector<uint8_t> key = QStringToByteVector(ui->lineKeyEdit->text().trimmed());
    QString cipherBytes;
    QVector<uint8_t> box(cryptor.blockSize);

    int n = 0;
    for(const auto &i: plainBytes) {
        box[n++] = i;

        if(n == 16) {
            box = cryptor.encrypt(box, key);
            for(const auto &j : box)
                cipherBytes += QString::number(j) + " ";

            n = 0;
        }
    }

    while(n != 0) {
        box[n++] = 0x00;

        if(n == 16) {
            box = cryptor.encrypt(box, key);
            for(const auto &j : box)
                cipherBytes += QString::number(j) + " ";
            n = 0;
        }
    }

    ui->plainTextEdit_2->clear();
    ui->plainTextEdit_2->appendPlainText(cipherBytes);
}

void MainWindow::on_decryptButton_clicked() {
    QString cipherBytes = ui->plainTextEdit_2->toPlainText();
    QVector<unsigned char> key = QStringToByteVector(ui->lineKeyEdit->text());
    QVector<unsigned char> plainBytes;
    QVector<uint8_t> box(cryptor.blockSize);

    int n = 0;
    QString s;
    for(const auto &i : cipherBytes) {
        if(i == " ") {
            if(s != "") box[n++] = s.toInt();
            s = "";
        }
        else s = s + i;

        if(n == 16) {
            box = cryptor.decrypt(box, key);
            for(auto j:box) plainBytes.push_back(j);
            n = 0;
        }
    }

    ui->plainTextEdit->clear();
    ui->plainTextEdit->appendPlainText(byteVectorToQString(plainBytes));
}

void MainWindow::on_comboBox_activated(const QString &arg) {
    if (arg == "aes128") {
        cryptor.setMode(aes::mode::aes128);
    }
    else if (arg == "aes192")
        cryptor.setMode(aes::mode::aes192);
    else
        cryptor.setMode(aes::mode::aes256);
}

