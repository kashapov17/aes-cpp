#ifndef AES_H
#define AES_H

#include <QVector>
#include <QByteArray>

using std::array;

const int nb = 4;
const int nr = 14;
const int nk = 8;

class aes
{
private:
    struct aesSettings {
        uint nb;
        uint nr;
        uint nk;
    } settings;

    aesSettings aes128Settings = {.nb = 4, .nr = 14, .nk=8};
    aesSettings aes192Settings = {.nb = 4, .nr = 12, .nk=6};
    aesSettings aes256Settings = {.nb = 4, .nr = 10, .nk=4};

    using StateVector = QVector<QVector<uint8_t>>;
    StateVector state;

    void subBytes(bool inv = false);
    void shiftRows(bool inv = false);
    void mixColumns(bool inv = false);
    void addRoundKey(QVector<QVector<uint8_t>> key_schedule, unsigned int round = 0);

    QVector<QVector<uint8_t>> keyExpansion(QVector<unsigned char> key);

    QVector<uint8_t> leftRightShift(QVector<uint8_t> array, unsigned int count, bool inv = false);

    uint8_t mul_by_02(uint8_t num);
    uint8_t mul_by_03(uint8_t num);
    uint8_t mul_by_09(uint8_t num);
    uint8_t mul_by_0b(uint8_t num);
    uint8_t mul_by_0d(uint8_t num);
    uint8_t mul_by_0e(uint8_t num);

public:
    enum mode {aes128, aes192, aes256};
    aes(mode m);
    void setMode(mode m);

    const uint blockSize = 16;
    QVector<uint8_t> encrypt(QVector<uint8_t> plainBytes, QVector<uint8_t> key);
    QVector<uint8_t> decrypt(QVector<uint8_t> plainCipher, QVector<uint8_t> key);
};
#endif // AES_256_H
