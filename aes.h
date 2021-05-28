#ifndef AES_H
#define AES_H

#include <QVector>
#include <array>
#include <QByteArray>

using std::array;

const int nb = 4;
const int nr = 14;
const int nk = 8;

class aes
{
private:
    enum mode {aes128, aes192, aes256};
    struct aesSettings {
        uint nb;
        uint nr;
        uint nk;
    } settings;

    aesSettings aes128Settings = {.nb = 4, .nr = 14, .nk=8};
    aesSettings aes192Settings = {.nb = 4, .nr = 12, .nk=6};
    aesSettings aes256Settings = {.nb = 4, .nr = 10, .nk=4};

    void setMode(mode m);

    const uint blockSize = 16;
    array<array<unsigned char, nb>, 4> state;

    void subBytes(bool inv = false);
    void shiftRows(bool inv = false);
    void mixColumns(bool inv = false);
    void addRoundKey(array<array<unsigned char, nb * (nr + 1)>, 4> key_schedule, unsigned int round = 0);

    array<array<unsigned char, nb * (nr + 1)>, 4> keyExpansion(QVector<unsigned char> key);

    array<unsigned char, nb> leftRightShift(array<unsigned char, nb> array, unsigned int count, bool inv = false);

    uint8_t mul_by_02(uint8_t num);
    uint8_t mul_by_03(uint8_t num);
    uint8_t mul_by_09(uint8_t num);
    uint8_t mul_by_0b(uint8_t num);
    uint8_t mul_by_0d(uint8_t num);
    uint8_t mul_by_0e(uint8_t num);

public:
    aes();

    array<unsigned char, 16> encrypt(array<unsigned char, 16> input_bytes, QVector<unsigned char> key);
    array<unsigned char, 16> decrypt(array<unsigned char, 16> cipher, QVector<unsigned char>  key);
};
#endif // AES_256_H
