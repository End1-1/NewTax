#ifndef PRINTTAX_H
#define PRINTTAX_H

#include <QObject>
#include <QTcpSocket>
#include <QJsonDocument>

#define pt_err_socket_read -5
#define pt_err_nodata_data -4
#define pt_err_nodata_login -3
#define pt_err_weak_3des_key -2
#define pt_err_cannot_connect_to_host -1
#define pt_err_ok 0

class PrintTax : public QObject
{
    Q_OBJECT
    QString fIP;
    int fPort;
    QString fPassword;
    QByteArray fPassSHA256;
    QByteArray fSessionPass;
    QTcpSocket fTcpSocket;
    static QMap<int, QString> fErrors;
    int connectToHost(QString &err);
    void jsonLogin(QByteArray &out);
    void makeRequestHeader(quint8 *dst, quint8 request, quint16 dataLen);
    int getResponse(QByteArray &out, QString &err);
    void cryptData(const QByteArray &k, QByteArray &inData, QByteArray &outData);
    void decryptData(const QByteArray &k, QByteArray &inData, QByteArray &outData);
public:
    explicit PrintTax(const QString &ip, int port, const QString &password, QObject *parent = nullptr);
    int printJSON(QByteArray &jsonData, QString &err);
    QJsonDocument fJSONDoc;
signals:
    void done(int code, const QString &message);
public slots:
};

#endif // PRINTTAX_H
