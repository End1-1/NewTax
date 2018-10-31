#ifndef PRINTTAXN_H
#define PRINTTAXN_H

#include <QObject>
#include <QTcpSocket>
#include <QJsonDocument>

#define pt_err_crn_empty -7
#define pt_err_no_tax_in_db -6
#define pt_err_socket_read -5
#define pt_err_nodata_data -4
#define pt_err_nodata_login -3
#define pt_err_weak_3des_key -2
#define pt_err_cannot_connect_to_host -1
#define pt_err_ok 0


#define opcode_login 2
#define opcode_PrintTaxN 4
#define opcode_taxback 6

class PrintTaxN : public QObject
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
    QMap<QString, QVariant> fJsonHeader;
    QList<QMap<QString, QVariant> > fJsonGoods;
public:
    PrintTaxN();
    explicit PrintTaxN(const QString &ip, int port, const QString &password, QObject *parent = nullptr);
    void setParams(const QString &ip, int port, const QString &password);
    void initErrors();
    int printJSON(QByteArray &jsonData, QString &err, quint8 opcode);
    void addGoods(const QString &dep, const QString &adgt, const QString &code, const QString &name, double price, double qty);
    int makeJsonAndPrint(double card, double prepaid, QString &outInJson, QString &outOutJson, QString &err);
    int printAdvanceJson(double advanceCash, double advanceCard, QString &outInJson, QString &outOutJson, QString &err);
    int printTaxback(int number, const QString &crn, QString &outInJson, QString &outOutJson, QString &err);
    QJsonDocument fJSONDoc;
    QString fPartnerTin;
    static void parseResponse(const QString &in, QString &firm, QString &hvhh, QString &fiscal, QString &number, QString &sn, QString &address, QString &devnum, QString &time);
signals:
    void done(int code, const QString &message);
public slots:
};

#endif // PRINTTAXN_H
