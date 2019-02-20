#include "goauth2.h"
#include<QtGui>
#ifdef __USEPKCE
#include <QRandomGenerator>
#include <QCryptographicHash>
#endif

Q_LOGGING_CATEGORY(lcGOAuth, "autooauth2.google")

const QUrl AuthUrl("https://accounts.google.com/o/oauth2/auth");
const QUrl TokenUrl("https://www.googleapis.com/oauth2/v4/token");
GOAuth2::GOAuth2(const QString &clientIdentifier, const QString &clientSecret,
                 quint16 port, QNetworkAccessManager *manager, QObject *parent):
    AutoOAuth2(clientIdentifier, AuthUrl, TokenUrl, port, manager, parent)
{
    setClientIdentifierSharedKey(clientSecret);
    setModifyParametersFunction([this](QAbstractOAuth::Stage stage,
                                QVariantMap *parameters){
        this->modifyParametersFunction(stage, parameters);
    });
    connect(this, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            &QDesktopServices::openUrl);
#ifdef QT_DEBUG
    QLoggingCategory::setFilterRules("autooauth2.google=true");
#endif
}

GOAuth2::GOAuth2(const QJsonDocument &credentialJson, quint16 port,
                 QNetworkAccessManager *manager, QObject *parent):
    GOAuth2(QString(), QString(), port, manager, parent)
{
    if (credentialJson.isNull()) {
        qCWarning(lcGOAuth) << "Fail to parse json file. ";
        return;
    }
    loadJson(credentialJson);
}

void GOAuth2::loadJson(const QJsonDocument &credentialJson) {
    loadJson(credentialJson.object());
}

void GOAuth2::loadJson(const QJsonObject &credentialJson) {
    QJsonValue config(credentialJson.value("installed"));
    if (config == QJsonValue::Undefined) {
        qCWarning(lcGOAuth) << "Invalid Json file: it has to be installed type. ";
        return;
    }
    if (!config.toObject().value("redirect_uris").toArray().contains("http://localhost")) {
        qCWarning(lcGOAuth) << "The API doesn't include loop back redirect uri. ";
        return;
    }
    setClientIdentifier(config.toObject().value("client_id").toString());
//    setAuthorizationUrl(config.toObject().value("auth_uri").toString());
//    setAccessTokenUrl(config.toObject().value("token_uri").toString());
    setClientIdentifierSharedKey(config.toObject().value("client_secret").toString());
}


const QString RevokeURI("https://accounts.google.com/o/oauth2/revoke?token=%1");
QNetworkReply *GOAuth2::revoke() {
    // https://developers.google.com/identity/protocols/OAuth2InstalledApp#tokenrevoke
    return get(QUrl(RevokeURI.arg(refreshToken())));
}

void GOAuth2::modifyParametersFunction(QAbstractOAuth::Stage stage, QVariantMap *parameters) {
    // https://developers.google.com/identity/protocols/OAuth2InstalledApp
    switch (stage) {
    case QAbstractOAuth::Stage::RefreshingAccessToken:
        parameters->insert("client_id", this->clientIdentifier());
        parameters->insert("client_secret", this->clientIdentifierSharedKey());
#ifdef QT_DEBUG
        qCDebug(lcGOAuth) << "Refreshing Access Token";
#endif
        break;
    case QAbstractOAuth::Stage::RequestingAccessToken:
#ifdef __USEPKCE
        parameters->insert("code_verifier", pkceVerifier);
#endif
#ifdef QT_DEBUG
        qCDebug(lcGOAuth, "Request Access Token");
#endif
        break;
    case QAbstractOAuth::Stage::RequestingAuthorization:
        if (!userInfo.isEmpty()) {
            parameters->insert("login_hint", userInfo);
        }
#ifdef __USEPKCE
        updatePKCE();
        parameters->insert("code_challenge_method", "S256");
        parameters->insert("code_challenge", QCryptographicHash::hash(
                               pkceVerifier, QCryptographicHash::Sha256).toBase64(
                               QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals));
#endif
#ifdef QT_DEBUG
        qCDebug(lcGOAuth) << "Request Authorization";
#endif
        break;
    case QAbstractOAuth::Stage::RequestingTemporaryCredentials:
#ifdef QT_DEBUG
        qCDebug(lcGOAuth) << "Request Temporary Credentials";
#endif
        break;
    }
}

#ifdef __USEPKCE
const char PKCEchars[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '-', '.', '_', '~' };
//#define PKCELENGTH 43
#define PKCELENGTH 128
void GOAuth2::updatePKCE() {
    pkceVerifier.clear();
    pkceVerifier.reserve(PKCELENGTH);
    while(pkceVerifier.length()<PKCELENGTH) {
        pkceVerifier.append(PKCEchars[QRandomGenerator::global()->bounded(
                    static_cast<quint32>(sizeof(PKCEchars)/sizeof(char)))]);
    }
}
#endif
