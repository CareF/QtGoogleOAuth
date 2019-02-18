#include "autooauth2.h"

Q_LOGGING_CATEGORY(lcAutoOAuth, "autooauth2")

AutoOAuth2::AutoOAuth2(const QString &clientIdentifier, const QUrl authorizationUrl,
                       const QUrl accessTokenUrl, quint16 port, QNetworkAccessManager *manager,
                       QObject *parent):
    QOAuth2AuthorizationCodeFlow(clientIdentifier, authorizationUrl, accessTokenUrl, manager, parent),
    m_replyHandler(port, this), m_port(port)
{
    setReplyHandler(&m_replyHandler);
    connect(this, &AutoOAuth2::granted, &m_replyHandler,
            &QOAuthHttpServerReplyHandler::close);
    setCallbackText(tr("Authorization finished. Feel free to close this page."));
#ifdef QT_DEBUG
    QLoggingCategory::setFilterRules("autoauth2=true");
    connect(&m_replyHandler, &QOAuthHttpServerReplyHandler::replyDataReceived,
            [=](const QByteArray &data){
        qCDebug(lcAutoOAuth) << "Reply Handler Data Received" << data;
    });
#endif
}

void AutoOAuth2::setCallbackText(const QString &text) {
    if (text == "")
        m_replyHandler.setCallbackText(
                    "<script language=\"javascript\">"
                    "self.location=\"about:blank\";"
                    "</script>");
    else
        m_replyHandler.setCallbackText(text);
}

void AutoOAuth2::loadRefreshToken(const QString &token) {
    setRefreshToken(token);
    refreshAccessToken();
}

void AutoOAuth2::grant() {
    if (!m_replyHandler.isListening())
        m_replyHandler.listen(QHostAddress::Any, m_port);
    QOAuth2AuthorizationCodeFlow::grant();
}
