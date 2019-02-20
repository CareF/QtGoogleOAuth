#ifndef GOAUTH2_H
#define GOAUTH2_H

#include "autooauth2.h"
Q_DECLARE_LOGGING_CATEGORY(lcGOAuth)
#define __USEPKCE

/**
 * \brief A wrapper of QOAuth2AuthorizationCodeFlow for Google API
 *
 * \details This class provides OAuth2 Authorization Code Flow for Google.
 * By inherit AutoOAuth2, this class provides an HTTP reply handler with
 * random port (unless specifically set), and refreashes access token
 * automatically.
 *
 * The OAuth2 parameters follow
 * \l {https://developers.google.com/identity/protocols/OAuth2InstalledApp}
 * {Google's Document}. Relavent server URLs are hard coded.
 * Loopback IP must be permitted by the Google API.
 * `id_token` is not implemented because of lack of information in the document.
 *
 * "Proof Key for Code Exchange (PKCE)" is implemented in this class if
 * __USEPKCE is defined. The `code_verifier` is genereated by QRandomGenerator.
 * Apart from interfaces inherited from QOAuth2AuthorizationCodeFlow,
 * The class also provides revoke access method.
 */
class GOAuth2 : public AutoOAuth2
{
    Q_OBJECT
public:
    /**
     * \brief GOreplyAuth2
     * \param clientIdentifier: `client_id` entry in initial request,
     * access token request and refresh token request.
     * \param clientSecret: `client_cecret` entry.
     * \param port: The port listened by replyhandler. Default 0 means
     * generated automatically.
     * \param manager: if nullptr, QOAuth2AuthorizationCodeFlow will
     * create its own.
     */
    explicit GOAuth2(const QString &clientIdentifier = QString(),
                     const QString &clientSecret = QString(),
                     quint16 port = 0, QNetworkAccessManager *manager = nullptr,
                     QObject *parent = nullptr);

    GOAuth2(QNetworkAccessManager *manager, QObject *parent = nullptr):
        GOAuth2(QString(), QString(), 0, manager, parent){}

    /**
     * \brief GOAuth2 load from json object. Json file should come from
     * \l {https://console.developers.google.com/}{Google API console}
     * \param credentialJson
     */
    GOAuth2(const QJsonDocument &credentialJson, quint16 port = 0,
            QNetworkAccessManager *manager = nullptr,
            QObject *parent = nullptr);

    void loadJson(const QJsonDocument &credentialJson);
    void loadJson(const QJsonObject &credentialJson);

    QNetworkReply *revoke();

    const QString &user() const {return userInfo;}
    void setUser(const QString & info) {userInfo = info;}

private:
    QString userInfo;
    void modifyParametersFunction(QAbstractOAuth::Stage stage,
                                  QVariantMap *parameters);
#ifdef __USEPKCE
    QByteArray pkceVerifier;
    void updatePKCE();
#endif
};

#endif // GOAUTH2_H
