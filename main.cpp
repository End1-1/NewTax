#include <QCoreApplication>
#include "printtaxn.h"
#include <QJsonDocument>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    PrintTaxN pt("10.10.5.15", 1981, "GK9JR7TN", "true", nullptr);
    QString err;
    QByteArray data = QString("{\"seq\":1,\"paidAmount\":2.00, \"paidAmountCard\":0.00, \"useExtPOS\":true, \"mode\":2,\"items\":[{\"dep\":1,\"qty\":1,\"price\":2.00,\"productCode\":\"90920\",\"productName\":\"Սուրճ Ջազզվե դառը\",\"adgCode\":\"56.21\", \"unit\":\"հատ\"}]}").toUtf8();
    int result = pt.printJSON(data, err, opcode_PrintTaxN);
    if (result == 200) {
        QJsonDocument jsonDoc = QJsonDocument::fromJson(data);
        qDebug() << jsonDoc;
    } else {
        qDebug() << QString::fromUtf8(data);
    }
    return a.exec();
}
