#include "printtax.h"
#include "openssl/des.h"
#include <QDataStream>
#include <QDebug>
#include <QCryptographicHash>
#include <QByteArray>
#include <QTcpSocket>
#include <QHostAddress>
#include <QJsonObject>
#ifdef WIN32
    #include <winsock2.h>
#endif

quint8 firstdata[] = {213, 128, 212, 180, 213, 132, 0, 5, 2, 0, 0, 0};
QMap<int, QString> PrintTax::fErrors;

#define opcode_login 2
#define opcode_printtax 4

int PrintTax::connectToHost(QString &err)
{
    fTcpSocket.connectToHost(QHostAddress(fIP), fPort);
    if (!fTcpSocket.waitForConnected(5000)) {
        err = fTcpSocket.errorString();
        return pt_err_cannot_connect_to_host;
    }
    return pt_err_ok;
}

void PrintTax::jsonLogin(QByteArray &out)
{
    fPassSHA256 = QCryptographicHash::hash(fPassword.toLatin1(), QCryptographicHash::Sha256).mid(0, 24);
    QByteArray authStr = QString("{\"password\":\"%1\",\"cashier\":3,\"pin\":\"3\"}").arg(fPassword).toUtf8();
    cryptData(fPassSHA256, authStr, out);
}

void PrintTax::makeRequestHeader(quint8 *dst, quint8 request, quint16 dataLen)
{
    memcpy(dst, &firstdata[0], 12);
    dst[8] = request;
    char chLen[2];
    memcpy(&chLen[0], &dataLen, sizeof(qint16));
    dst[10] = chLen[1];
    dst[11] = chLen[0];
}

int PrintTax::getResponse(QByteArray &out, QString &err)
{
    out.clear();
    quint8 fd[11];
    quint64 bytesTotal;
    if (fTcpSocket.waitForReadyRead(5000)) {
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

void PrintTax::cryptData(const QByteArray &k, QByteArray &inData, QByteArray &outData)
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

void PrintTax::decryptData(const QByteArray &k, QByteArray &inData, QByteArray &outData)
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

PrintTax::PrintTax(const QString &ip, int port, const QString &password, QObject *parent) :
    QObject(parent)
{
    fIP = ip;
    fPort = port;
    fPassword = password;
    if (fErrors.count() == 0) {
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
}

int PrintTax::printJSON(QByteArray &jsonData, QString &err)
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
    makeRequestHeader(&fd[0], opcode_printtax, out.length());

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
