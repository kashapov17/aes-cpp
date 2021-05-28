#include "mainwindow.h"
#include "ui_mainwindow.h"

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

QString biteToQstring(QVector<unsigned char> bite)
{
    QByteArray bites;
    QString text;

    for(auto i:bite) bites.push_back(i);
    text = QString::fromLocal8Bit(bites);

    return text;
}

QVector<unsigned char> qstringToBite(QString text)
{
    QByteArray bites = text.toLocal8Bit();
    QVector<unsigned char> bite;

    for(auto i:bites) bite.push_back(i);

    return bite;
}

void MainWindow::on_encryptButton_clicked()
{
    QVector<unsigned char> bitesText = qstringToBite(ui->plainTextEdit->toPlainText().trimmed());
    QVector<unsigned char> key = qstringToBite(ui->lineKeyEdit->text().trimmed());
    QString bitesCode;
    array<unsigned char, 16> box;

    int n = 0;
    for(auto i:bitesText)
    {
        box[n++] = i;

        if(n == 16)
        {
            box = cryptor.encrypt(box, key);
            for(auto j:box)
            {
                bitesCode += QString::number(j, 16) + " ";
            }
            n = 0;
        }
    }

    while(n != 0)
    {
        box[n++] = 0x00;

        if(n == 16)
        {
            box = cryptor.encrypt(box, key);
            for(auto j:box)
            {
                bitesCode += QString::number(j) + " ";
            }
            n = 0;
        }
    }

    ui->plainTextEdit_2->clear();
    ui->plainTextEdit_2->appendPlainText(bitesCode);
}

void MainWindow::on_decryptButton_clicked()
{
    QString bitesCode = ui->plainTextEdit_2->toPlainText();
    QVector<unsigned char> key = qstringToBite(ui->lineKeyEdit->text());
    QVector<unsigned char> bitesText;
    array<unsigned char, 16> box;

    int n = 0;
    QString s;
    for(auto i:bitesCode)
    {
        if(i == " ")
        {
            if(s != "") box[n++] = s.toInt();
            s = "";
        }
        else s = s + i;

        if(n == 16)
        {
            box = cryptor.decrypt(box, key);
            for(auto j:box) bitesText.push_back(j);
            n = 0;
        }
    }

    ui->plainTextEdit->clear();
    ui->plainTextEdit->appendPlainText(biteToQstring(bitesText));
}
