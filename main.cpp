/**
 * \file main.cpp
 * This file serve as a test app for GOAuth2
 */

#include "goauth2.h"
#include <QApplication>
#include <QFrame>
#include <QBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QFile credFile(":/credentials.json");
    credFile.open(QIODevice::ReadOnly | QIODevice::Text);
    GOAuth2 gCal(QJsonDocument::fromJson(credFile.readAll()));
    credFile.close();
    gCal.setScope("https://www.googleapis.com/auth/calendar.readonly");
//    gCal.setUser("user@gmail.com");
//    GOAuth2 gCal("<clientID>", "<client_secret>");

    QFrame wmain;
    QVBoxLayout *mainLayout = new QVBoxLayout;
    wmain.setLayout(mainLayout);
    QHBoxLayout *box = new QHBoxLayout;

    QPushButton *bttn = new QPushButton("Auth");
    wmain.connect(bttn, &QPushButton::clicked, &gCal,
                  &GOAuth2::grant);
    box->addWidget(bttn);
    bttn = new QPushButton("Renew");
    wmain.connect(bttn, &QPushButton::clicked,
                  &gCal, &GOAuth2::refreshAccessToken);
    box->addWidget(bttn);
    mainLayout->addLayout(box);

    box = new QHBoxLayout;
    QLineEdit *urlEdit = new QLineEdit;
    box->addWidget(urlEdit);
    bttn = new QPushButton("Get");
    box->addWidget(bttn);
    mainLayout->addLayout(box);

    QTextEdit *textEdit = new QTextEdit;
    mainLayout->addWidget(textEdit);
    wmain.connect(bttn, &QPushButton::clicked, [&](){
    gCal.autoRequest(&GOAuth2::get, urlEdit->text(),
                     [&](QNetworkReply *reply){
        if (reply->error() != QNetworkReply::NoError) {
            qDebug() << reply->errorString();
        }
        textEdit->setText(reply->readAll()); }
    );});

    wmain.connect(&gCal, &GOAuth2::statusChanged,
                  [&](GOAuth2::Status status){
        switch (status) {
        case QAbstractOAuth::Status::Granted:
            qDebug() << "Granted!";
            textEdit->setText("Authentication succeeded!\n Expire at "
                                        + gCal.expirationAt().toString());
            break;
        case QAbstractOAuth::Status::RefreshingToken:
            qDebug() << "Refreshing Token!";
            break;
        case QAbstractOAuth::Status::NotAuthenticated:
            qDebug() << "Not Authenticated!";
            break;
        case QAbstractOAuth::Status::TemporaryCredentialsReceived:
            qDebug() << "Temporary Credentials Received!";
            break;

    }});
    wmain.show();

    return a.exec();
}
