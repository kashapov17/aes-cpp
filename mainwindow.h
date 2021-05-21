#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QVector>

#include "aes_128.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_encryptButton_clicked();

    void on_decryptButton_clicked();

private:
    Ui::MainWindow *ui;
    AES_128 aes;
};
#endif // MAINWINDOW_H
