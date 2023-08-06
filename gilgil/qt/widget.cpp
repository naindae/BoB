#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->pbCoffee->setEnabled(false);
    ui->pbTea->setEnabled(false);
    ui->pbMilk->setEnabled(false);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::showButton()
{
    if(200<=money)
    {
        ui->pbTea->setEnabled(true);
        ui->pbCoffee->setEnabled(true);
        ui->pbMilk->setEnabled(true);
    }
    else if(150<=money and money<200)
    {
        ui->pbTea->setEnabled(true);
        ui->pbCoffee->setEnabled(true);
        ui->pbMilk->setEnabled(false);
    }
    else if (100<=money)
    {
        ui->pbCoffee->setEnabled(true);
    }
    else
    {
        ui->pbCoffee->setEnabled(false);
        ui->pbTea->setEnabled(false);
        ui->pbMilk->setEnabled(false);
    }
}

void Widget::changeMoney(int diff)
{
    money += diff;
    showButton();
    ui->lcdNumber->display(money);
}


void Widget::on_pb10_clicked()
{
    changeMoney(10);
}


void Widget::on_pb50_clicked()
{
    changeMoney(50);
}



void Widget::on_pb100_clicked()
{
    changeMoney(100);
}


void Widget::on_pb500_clicked()
{
    changeMoney(500);
}


void Widget::on_pbCoffee_clicked()
{
    changeMoney(-100);
}


void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
}


void Widget::on_pbMilk_clicked()
{
    changeMoney(-200);
}


void Widget::on_pbReset_clicked()
{
    int ex500 = 0;
    int ex100 = 0;
    int ex50 = 0;
    int ex10 = 0;

    ex500 = money / 500;
    money = money % 500;
    ex100 = money / 100;
    money = money % 100;
    ex50 = money / 50;
    money = money % 50;
    ex10 = money / 10;
    money = money%10;
    QString message = QString("500: %1\n100: %2\n50: %3\n10: %4").arg(ex500).arg(ex100).arg(ex50).arg(ex10);
    ui->lcdNumber->display(money);
    QMessageBox mb;
    mb.information(nullptr,"Exchange",message);

}

