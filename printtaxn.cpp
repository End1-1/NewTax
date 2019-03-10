#include "printtaxn.h"
#include "openssl/des.h"
#include <QDataStream>
#include <QCryptographicHash>
#include <QByteArray>
#include <QTcpSocket>
#include <QHostAddress>
#include <QJsonObject>
#include <QDateTime>
#include <QRegExp>
#ifdef WIN32
    #include <winsock2.h>
#endif

quint8 firstdata[] = {213, 128, 212, 180, 213, 132, 0, 5, 2, 0, 0, 0};
QMap<int, QString> PrintTaxN::fErrors;

#define float_str(value, f) QString::number(value, 'f', f).remove(QRegExp("\\.0+$")).remove(QRegExp("\\.$"))

int PrintTaxN::connectToHost(QString &err)
{
    fTcpSocket.connectToHost(QHostAddress(fIP), fPort);
    if (!fTcpSocket.waitForConnected(5000)) {
        err = fTcpSocket.errorString();
        return pt_err_cannot_connect_to_host;
    }
    return pt_err_ok;
}

void PrintTaxN::jsonLogin(QByteArray &out)
{
    fPassSHA256 = QCryptographicHash::hash(fPassword.toLatin1(), QCryptographicHash::Sha256).mid(0, 24);
    QByteArray authStr = QString("{\"password\":\"%1\",\"cashier\":3,\"pin\":\"3\"}").arg(fPassword).toUtf8();
    cryptData(fPassSHA256, authStr, out);
}

void PrintTaxN::makeRequestHeader(quint8 *dst, quint8 request, quint16 dataLen)
{
    memcpy(dst, &firstdata[0], 12);
    dst[8] = request;
    char chLen[2];
    memcpy(&chLen[0], &dataLen, sizeof(qint16));
    dst[10] = chLen[1];
    dst[11] = chLen[0];
}

int PrintTaxN::getResponse(QByteArray &out, QString &err)
{
    out.clear();
    quint8 fd[11];
    quint64 bytesTotal;
    if (fTcpSocket.waitForReadyRead(1300000)) {
        bytesTotal = fTcpSocket.bytesAvailable();
        fTcpSocket.read(reinterpret_cast<char*>(&fd[0]), 11);
        bytesTotal -= 11;
        qint16 dataLen;
        memcpy(&dataLen, &fd[7], 2);
        dataLen = ntohs(dataLen);
        out.clear();
        while (bytesTotal > 0) {
            char buff[1024];
            qint64 bytesRead = fTcpSocket.read(&buff[0], 1024);
            if (bytesRead == 0) {
                err = tr("Socket read error");
                return pt_err_socket_read;
            }
            bytesTotal -= bytesRead;
            out.append(&buff[0], bytesRead);
        }
    } else {
        fTcpSocket.close();
        err = tr("Data read timeout");
        return pt_err_nodata_login;
    }
    quint16 result;
    memcpy(&result, &fd[5], sizeof(quint16));
    result = ntohs(result);
    return result;
}

void PrintTaxN::cryptData(const QByteArray &k, QByteArray &inData, QByteArray &outData)
{
    outData.clear();
    quint8 jsonFillCount = 8 - (inData.length() % 8);
    for (int i = 0; i < jsonFillCount; i++) {
        inData.append((char)jsonFillCount);
    }

    int key_len = 24;
    unsigned char key[24];
    unsigned char block_key[9];
    DES_key_schedule ks,ks2,ks3;

    memcpy(key, k.data(), key_len);
    memset(key + key_len, 0x00, 24 - key_len);

    memset(block_key, 0, sizeof(block_key));
    memcpy(block_key, key + 0, 8);
    DES_set_key_unchecked((const_DES_cblock*)block_key, &ks);
    memcpy(block_key, key + 8, 8);
    DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2);
    memcpy(block_key, key + 16, 8);
    DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);

    qint16 srcLen = inData.length();
    char out[srcLen];
    memset(&out, 0, srcLen);
    for (int i = 0; i < srcLen; i += 8) {
        DES_ecb3_encrypt((const_DES_cblock*)&inData.data()[i], (DES_cblock*)&out[i], &ks, &ks2, &ks3, DES_ENCRYPT);
    }
    outData.append(&out[0], srcLen);


}

void PrintTaxN::decryptData(const QByteArray &k, QByteArray &inData, QByteArray &outData)
{
    outData.clear();

    int key_len = 24;
    unsigned char key[24];
    unsigned char block_key[9];
    DES_key_schedule ks,ks2,ks3;

    memcpy(key, k.data(), key_len);
    memset(key + key_len, 0x00, 24 - key_len);

    memset(block_key, 0, sizeof(block_key));
    memcpy(block_key, key + 0, 8);
    DES_set_key_unchecked((const_DES_cblock*)block_key, &ks);
    memcpy(block_key, key + 8, 8);
    DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2);
    memcpy(block_key, key + 16, 8);
    DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);

    char out[inData.length()];
    memset(&out, 0, inData.length());
    for (int i = 0; i < inData.length(); i += 8) {
        DES_ecb3_encrypt((const_DES_cblock*)&inData.data()[i], (DES_cblock*)&out[i], &ks, &ks2, &ks3, DES_DECRYPT);
    }
    outData.append(out, inData.length());
}

void PrintTaxN::parseResponse(const QString &in, QString &firm, QString &hvhh, QString &fiscal,
                              QString &number, QString &sn, QString &address, QString &devnum, QString &time)
{
    int pos = in.indexOf("\"rseq\":") + 7;
    int pos2 = in.indexOf(",", pos );
    number = in.mid(pos, pos2 - pos);
    pos = in.indexOf("\"fiscal\":") + 9;
    pos2 = in.indexOf(",", pos + 1);
    fiscal = in.mid(pos, pos2 - pos);
    fiscal.replace("\"", "");
    pos = in.indexOf("\"tin\":") + 6;
    pos2 = in.indexOf(",", pos + 1);
    hvhh = in.mid(pos, pos2 - pos);
    hvhh.replace("\"", "");
    pos = in.indexOf("\"taxpayer\":") + 12;
    pos2 = in.indexOf("\"", pos + 1);
    firm = in.mid(pos, pos2 - pos);
    pos = in.indexOf("\"sn\":\"") + 6;
    pos2 = in.indexOf("\"", pos + 1);
    sn = in.mid(pos, pos2 - pos);
    pos = in.indexOf("\"address\":\"") + 11;
    pos2 = in.indexOf("\"", pos + 1);
    address = in.mid(pos, pos2 - pos);
    pos = in.indexOf("\"crn\":") + 7;
    pos2 = in.indexOf("\"", pos + 1);
    devnum = in.mid(pos, pos2 - pos);
    pos = in.indexOf("\"time\":") + 7;
    pos2 = in.indexOf(",", pos + 1);
    time = in.mid(pos, pos2 - pos);
    time = QDateTime::fromMSecsSinceEpoch(time.toDouble()).toString("dd.MM.yyyy HH:mm:ss");
}

PrintTaxN::PrintTaxN()
{
    if (fErrors.count() == 0) {
        initErrors();
    }
    fJsonHeader["paidAmount"] = 0.0;
    fJsonHeader["paidAmountCard"] = 0.0;
    fJsonHeader["prePaymentAmount"] = 0.0;
    fJsonHeader["userExtPOS"] = "true";
}

PrintTaxN::PrintTaxN(const QString &ip, int port, const QString &password, const QString &extPos, QObject *parent) :
    QObject(parent)
{
    setParams(ip, port, password);
    if (fErrors.count() == 0) {
        initErrors();
    }

    fJsonHeader["paidAmount"] = 0.0;
    fJsonHeader["paidAmountCard"] = 0.0;
    fJsonHeader["prePaymentAmount"] = 0.0;
    fJsonHeader["userExtPOS"] = extPos;
}

void PrintTaxN::setParams(const QString &ip, int port, const QString &password)
{
    fIP = ip;
    fPort = port;
    fPassword = password;
}

void PrintTaxN::initErrors()
{
    fErrors[pt_err_crn_empty] = "Crn field is empty";
    fErrors[500] =" ՀԴՄ ներքին սխալ:  Ընդհանուր տիպի չդասակարգված սխալ)";
    fErrors[400] =" Հարցման սխալ:  Վերադարձվում է երբ հարցումը չի վերծանվում)";
    fErrors[402] =" Սխալ արձանագրության տարբերակ:";
    fErrors[403] =" Չարտոնագրված միացում: Վերադարձվում է, երբ ՀԴՄ-ում կարագավորված IP հասցեն չի համընկնում կապ հաստատաց սարքի IP հասցեի հետ)";
    fErrors[404] =" Սխալ գործողության կոդ:  Վերադարձվում է, երբ Գլխագրում նշված գործողության կոդը սխալ է)";
    fErrors[101] =" Գաղտնաբառով կոդավորման սխալ:";
    fErrors[102] =" Սեսիայի բանալիով կոդավորման սխալ:";
    fErrors[103] =" Գլխագրի ֆորմատի սխալ:";
    fErrors[104] =" Հարցման հերթական համարի սխալ:";
    fErrors[105] =" JSON ֆորմատավորման սխալ:";
    fErrors[141] =" Վերջին կտրոնի գրառումը բացակայում է:";
    fErrors[142] =" Վերջին կտրոնը պատկանում է այլ օգտատիրի:";
    fErrors[143] =" Տպիչի ընդհանուր սխալ:";
    fErrors[144] =" Տպիչի նույնականացման սխալ:";
    fErrors[145] =" Տպիչում վերջացել է թուղթը:";
    fErrors[111] = " Օպերատորի գաղտնաբառի սխալ:";
    fErrors[112] =" Այդպիսի օպերատոր գոյություն չունի: Հնարավոր է երեք դեպք՝ 1.  Տվյալ օգտվողի դերը օպերատոր չէ  2.  Տվյալ օգտվողը ակտիվ չէ 3.  Այդպիսի օգտվող գրանցված չէ)";
    fErrors[113] =" Օպերատորը ակտիվ չէ:";
    fErrors[121] =" Սխալ օգտվող:";
    fErrors[151] =" Այդպիսի բաժին գոյություն չունի:  Այս սխալը կվերադարձվի նաև այն դեպքում, երբ տվյալ բաժինը կցված չէ օպերատորին)";
    fErrors[152] =" Վճարված գումարը ընդհանուր գումարից պակաս է:";
    fErrors[153] =" Կտրոնի գումարը գերազանզում է սահմանված շեմը:";
    fErrors[154] =" Կտրոնի գումարը պետք է լինի դրական թիվ:";
    fErrors[155] =" Անհրաժեշտ է համաժամանակեցնել ՀԴՄ-ն:";
    fErrors[157] =" Սխալ վերադարձի կտրոնի համար:";
    fErrors[158] =" Կտրոնը արդեն վերադարձված է:";
    fErrors[159] =" Ապրանքի գինը և քանակը չի կարող լինել ոչ դրական:";
    fErrors[160] =" Զեղչի տոկոսը պետք է լինի ոչ բացասական թիվ՝ 100-ից փոքր:";
    fErrors[161] =" Ապրանքի կոդը սխալ է:";
    fErrors[162] =" Ապրանքի անվանումը սխալ է:";
    fErrors[163] =" Ապրանքի չափման Միավորի դաշտը չի կարող լինել դատարկ:";
    fErrors[164] =" Անկանխիկ վճարման խափանում:";
    fErrors[165] =" Ապրանքի գինը չի կարող   լինել 0:";
    fErrors[166] =" Վերջնական գնի հաշվարկի սխալ:";
    fErrors[167] =" Անկանխիկ գումարը ավելի մեծ է քան կտրոնի ընդհանուր գումարը:";
    fErrors[168] =" Անկանխիկ գումարը ծածկում է ընդհանուր գումարը (Կանխիկ գումարը ավելորդ է):";
    fErrors[169] =" Ֆիսկալ հաշվետվության ֆիլտրների սխալ ընտրություն (մեկից ավել ֆիլտրերի դաշտ է ուղարկվել):";
    fErrors[170] =" Ֆիսկալ հաշվետվության ժամանակ սխալ ամսաթվային միջակայք է ուղարկվել: Միջակայքը չպետք է գերազանցի 2 ամիսը:";
    fErrors[171] =" Ապրանքի գնի անթույլատրելի արժեք:";
    fErrors[172] =" Կտրոնը ապրանքներով կտրոն չէ:";
    fErrors[173] =" Սխալ զեղչի տեսակ:";
    fErrors[174] =" Վերադարձվող կտրոնը գոյություն չունի:";
    fErrors[175] =" Վերադարձվող կտրոնի սխալ գրանցման համար:";
    fErrors[176] =" Վերջին կտրոնը գոյություն չունի:";
    fErrors[177] =" Նշված տիպի կտրոնների համար վերադարձ հնարավոր չէ կատարել:";
    fErrors[178] =" Հարցված գումարը հնարավոր չէ վերադարձնել:";
    fErrors[179] =" Մասնակի վճարում: Կտրոնը պետք է վերադարձվի ամբողջությամբ:";
    fErrors[180] =" Ամբողջական վերադարձի ավել գումար:";
    fErrors[181] =" Վերադարձվող ապրանքի սխալ քանակ:";
    fErrors[182] =" Վերադարձվող կտրոնը իրենից ներկայացնում է վերադարձ տիպի կտրոն:";
    fErrors[183] =" Սխալ ԱՏԳԱԱ/ԱԴԳՏ կոդ:";
    fErrors[184] =" Կանխավճարի վերադարձի անթույլատրելի հարցում:";
    fErrors[185] =" Հնարավոր չէ կատարել տվյալ կտրոնի վերադարձը: Անհրաժեշտ է ՀԴՄ ծրագրի համաժամանակեցում:";
    fErrors[186] =" Կանխավճարի դեպքում սխալ գումար:";
    fErrors[187] =" Կանխավճարի դեպքում սխալ ցուցակ:";
    fErrors[188] =" Սխալ գումարներ:";
    fErrors[189] =" Սխալ կլորացում:";
    fErrors[190] =" Վճարումը հասանելի չէ:";
    fErrors[191] =" Կանխիկի մուտքի/ելքի ժամանակ գումարը պետք է լինի մեծ 0-ից:";
    fErrors[192] =" ԱՏԳԱԱ/ԱԴԳՏ կոդը բացակայում է:";
}

int PrintTaxN::printJSON(QByteArray &jsonData, QString &err, quint8 opcode)
{
    int result = pt_err_ok;
    QByteArray out;

    if ((result = connectToHost(err))) {
        return result;
    }
    jsonLogin(out);
    quint8 fd[12];
    makeRequestHeader(&fd[0], opcode_login, out.length());

    fTcpSocket.write(reinterpret_cast<const char*>(&fd[0]), 12);
    fTcpSocket.write(out, out.length());
    fTcpSocket.flush();

    if ((result = getResponse(out, err)) != 200) {
        if (result > 0) {
            jsonData = fErrors[result].toUtf8();
        }
        return result;
    }
    decryptData(fPassSHA256, out, fSessionPass);
    char c = fSessionPass.at(fSessionPass.length() - 1);
    if (c < 8) {
        for (int i = 0; i < c; i++) {
            fSessionPass.remove(fSessionPass.length() - 1, 1);
        }
    }
    QJsonDocument jDoc = QJsonDocument::fromJson(fSessionPass);
    QJsonObject jObj(jDoc.object());
    fSessionPass = QByteArray::fromBase64(jObj.value("key").toString().toLatin1());

    cryptData(fSessionPass, jsonData, out);
    makeRequestHeader(&fd[0], opcode, out.length());

    fTcpSocket.write(reinterpret_cast<const char*>(&fd[0]), 12);
    fTcpSocket.write(out, out.length());
    fTcpSocket.flush();
    if ((result = getResponse(jsonData, err)) != 200) {
        if (result > 0) {
            jsonData = fErrors[result].toUtf8();
        }
        return result;
    }

    decryptData(fSessionPass, jsonData, out);
    if (out.length() > 0) {
        c = out.at(out.length() - 1);
    } else {
        c = 10;
    }
    if (c < 8) {
        for (int i = 0; i < c; i++) {
            out.remove(out.length() - 1, 1);
        }
    }
    jsonData = out;
    fTcpSocket.close();

    return 0;
}

void PrintTaxN::addGoods(const QString &dep, const QString &adgt, const QString &code, const QString &name, double price, double qty)
{

    QMap<QString, QVariant> data;
    data["dep"] = dep;
    data["adgCode"] = adgt;
    data["productCode"] = code;
    data["productName"] = name;
    data["price"] = price;
    data["qty"] = qty;
    data["totalPrice"] = price * qty;
    data["unit"] = QString::fromUtf8("հատ");
    fJsonGoods.append(data);

    double totalCash = 0;
    for (int i = 0; i < fJsonGoods.count(); i++) {
        QMap<QString, QVariant> &g = fJsonGoods[i];
        totalCash += g["totalPrice"].toDouble();
    }
    fJsonHeader["paidAmount"] = totalCash;
}

int PrintTaxN::makeJsonAndPrint(double card, double prepaid, QString &outInJson, QString &outOutJson, QString &err)
{
    fJsonHeader["paidAmountCard"] = card;
    fJsonHeader["prePaymentAmount"] = prepaid;
    fJsonHeader["paidAmount"] = fJsonHeader["paidAmount"].toDouble() - card - prepaid;
    QString json = QString("{\"seq\":1,\"paidAmount\":%1, \"paidAmountCard\":%2, \"partialAmount\":0, "
                           "\"prePaymentAmount\":%3, \"useExtPOS\":%4, \"mode\":2, %5 \"items\":[")
                    .arg(float_str(fJsonHeader["paidAmount"].toDouble(), 2))
                    .arg(float_str(fJsonHeader["paidAmountCard"].toDouble(), 2))
                    .arg(float_str(fJsonHeader["prePaymentAmount"].toDouble(), 2))
                    .arg(fJsonHeader["userExtPOS"].toString())
                    .arg(fPartnerTin.length() > 0 ? QString("\"partnerTin\":%1,").arg(fPartnerTin) : "");
    bool first = true;
    for (int i = 0; i < fJsonGoods.count(); i++) {
        if (first) {
            first = false;
        } else {
            json += ",";
        }
        json += "{";
        QMap<QString, QVariant> &g = fJsonGoods[i];
        bool f2 = true;
        for (QMap<QString, QVariant>::const_iterator it = g.begin(); it != g.end(); it++) {
            if (f2) {
                f2 = false;
            } else {
                json += ",";
            }
            json += "\"" + it.key() + "\":";
            switch (it.value().type()) {
            case QVariant::Double:
                json += float_str(it.value().toDouble(), 2);
                break;
            default:
                json += "\"" + it.value().toString() + "\"";
                break;
            }
        }
        json += "}";
    }
    json += "]}";
    outInJson = json;
    QByteArray jdata = json.toUtf8();
    int result = printJSON(jdata, err, opcode_PrintTaxN);
    outOutJson = jdata;
#ifdef QT_DEBUG
    outOutJson = "{\"rseq\":77,\"crn\":\"53219917\",\"sn\":\"V98745506068\",\"tin\":\"01588771\",\"taxpayer\":\"«Ջազզվե ՍՊԸ»\",\"address\":\"Արշակունյանց 34\",\"time\":1527853613000.0,\"fiscal\":\"98802057\",\"lottery\":\"00000000\",\"prize\":0,\"total\":1540.0,\"change\":0.0}";
    result = 0;
#endif
    return result;
}

int PrintTaxN::printAdvanceJson(double advanceCash, double advanceCard, QString &outInJson, QString &outOutJson, QString &err)
{
    outInJson = QString ("{\"seq\":1, "
              "\"paidAmount\":%1, \"paidAmountCard\":%2,"
              "\"prePaymentAmount\":0.0,"
              "\"mode\":3, \"useExtPOS\":%3}")
            .arg(advanceCash)
            .arg(advanceCard)
            .arg(fJsonHeader["userExtPOS"].toString());
    QByteArray jdata = outInJson.toUtf8();
    int result = printJSON(jdata, err, opcode_PrintTaxN);
    outOutJson = jdata;
    return result;
}

int PrintTaxN::printTaxback(int number, const QString &crn, QString &outInJson, QString &outOutJson, QString &err)
{
    outInJson = QString ("{\"seq\":1,\"crn\":\"%1\", \"receiptId\":%2}")
            .arg(crn)
            .arg(number);
            //.arg(number, 8, 10, QChar('0'));
    QByteArray jdata = outInJson.toUtf8();
    int result = printJSON(jdata, err, opcode_taxback);
    outOutJson = jdata;
    return result;
}
