#ifndef AUTOOAUTH2_H
#define AUTOOAUTH2_H

#include <QOAuth2AuthorizationCodeFlow>
#include <QtNetworkAuth>
#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(lcAutoOAuth)

/**
 * \brief The AutoOAuth2 class
 *
 * \details This class combines the QOAuth2AuthorizationCodeFlow with an
 * QOAuthHttpServerReplyHandler, and provides semi-auto renewal interfaces.
 * The HTTP reply handler uses random port unless specifically set.
 *
 * \note connection between httpserverreplyhandler (thus its http server) and
 * QOAuth2AuthorizationCodeFlow happens when building authorization URL, and is
 * not disconnected. This means that the server cannot be shared between instances
 * of QOAuth2AuthorizationCodeFlow, otherwise they will mistake tokens for others.
 * So it makes sense to attach an HTTPServer to each individual instance.
 */
class AutoOAuth2 : public QOAuth2AuthorizationCodeFlow
{
    Q_OBJECT
public:
    explicit AutoOAuth2(const QString &clientIdentifier, const QUrl authorizationUrl,
               const QUrl accessTokenUrl, quint16 port = 0,
               QNetworkAccessManager *manager = nullptr, QObject *parent = nullptr);

    void setCallbackText(const QString &text);
    /**
     * \brief loadRefreshToken: This method will set refresh token and ask for new
     * access token.
     */
    void loadRefreshToken(const QString &token);

    template<typename T>
    /**
     * \brief autoRequest: request from server, with automatic access token refresh if
     * it's expired
     * \param request: the kind of request to make, possibilities are deleteResource,
     *  get, head, post, put
     * \param url: the url as the first arguement of request
     * \param response: a function response to the QNetworkReply of the request. No need
     * to free the QNetworkReply in response function.
     * \param parameter: parameter of the request, most likely is a QVariableMap
     */
    void autoRequest(QNetworkReply* (QAbstractOAuth2::* request) (const QUrl &, const T &),
                     const QUrl &url, const std::function<void (QNetworkReply *)> &response,
                     const T &parameter = T()){
        if (expirationAt() < QDateTime::currentDateTime()) {
            qCDebug(lcAutoOAuth) << "Auto refresh access token";
            QObject *waiter = new QObject;
            connect(this, &AutoOAuth2::expirationAtChanged, waiter,
                    [=](const QDateTime &expTime){
                waiter->deleteLater(); // And thus this connection is single shot
                if (expTime < QDateTime::currentDateTime())
                    qCWarning(lcAutoOAuth) << "Refresh Token Failed! "
                                              "Current token expire at" << expTime;
                QNetworkReply *reply = (this->*request)(url, parameter);
                connect(reply, &QNetworkReply::finished, [=](){
                    reply->deleteLater();
                    response(reply);
                });
            });
            refreshAccessToken();
        }
        else {
            QNetworkReply *reply = (this->*request)(url, parameter);
            connect(reply, &QNetworkReply::finished, [=](){
                reply->deleteLater();
                response(reply);
            });
        }
    }

public slots:
    virtual void grant() override;

private:
    QOAuthHttpServerReplyHandler m_replyHandler;
    quint16 m_port;
};

#endif // AUTOOAUTH2_H
