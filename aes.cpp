#include "aes.h"
#include "tables.h"

aes::aes()
{}

void aes::setMode(mode m) {
    if (m == aes128)
        settings = aes128Settings;
    else
        settings = aes256Settings;
}

array<uint8_t, 16> aes::encrypt(array<uint8_t, 16> plainBytes, QVector<uint8_t> key) {
    for (uint r = 0; r < 4; r++) {
        for (uint c = 0; c < nb; c++) state[r][c] = plainBytes[r + 4 * c];
    }

    array<array<uint8_t, nb * (nr + 1)>, 4> key_schedule = keyExpansion(key);

    addRoundKey(key_schedule);

    uint rnd;
    for (rnd = 1; rnd < nr; rnd++) {
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey(key_schedule, rnd);
    }

    subBytes();
    shiftRows();
    addRoundKey(key_schedule, rnd);

    array<uint8_t, 16> output;
    for (uint r = 0; r < 4; r++) {
         for (uint c = 0; c < nb; c++) output[r + 4 * c] = state[r][c];
    }

    return output;
}

array<uint8_t, 16> aes::decrypt(array<uint8_t, 16> cipher, QVector<uint8_t>  key)
{
    for (uint r = 0; r < 4; r++) {
        for (uint c = 0; c < nb; c++) state[r][c] = cipher[r + 4 * c];
    }

    array<array<uint8_t, nb * (nr + 1)>, 4> key_schedule = keyExpansion(key);

    addRoundKey(key_schedule, nr);

    uint rnd = nr - 1;
    while (rnd >= 1)
    {
        shiftRows(true);
        subBytes(true);
        addRoundKey(key_schedule, rnd);
        mixColumns(true);

        rnd--;
    }

    shiftRows(true);
    subBytes(true);
    addRoundKey(key_schedule, rnd);

    array<uint8_t, 16> output;
    for (uint r = 0; r < 4; r++)
    {
         for (uint c = 0; c < nb; c++) output[r + 4 * c] = state[r][c];
    }

    return output;
}

void aes::subBytes(bool inv) {
    array<uint8_t, 256> box;

    if (inv == false) box = sbox;
    else  box = inv_sbox;

    uint row;
    uint col;
    uint8_t box_elem;

    for (uint i = 0; i < state.size(); i++) {
       for (uint j = 0; j < state[i].size(); j++) {
           row = state[i][j] / 0x10;
           col = state[i][j] % 0x10;

           box_elem = box[16 * row + col];
           state[i][j] = box_elem;
       }
    }
}

array<uint8_t, nb> aes::leftRightShift(array<uint8_t, nb> array, uint count, bool inv) {
    uint8_t el;

    if (inv == false) {
        while(count--) {
            el = array[0];
            for(uint i = 0; i < array.size() - 1; i++) {
                array[i] = array[i + 1];
            }
            array[array.size() - 1] = el;
        }
    }
    else {
        while(count--) {
            el = array[array.size() - 1];
            for(uint i = array.size() - 1; i > 0; i--) {
                array[i] = array[i - 1];
            }
            array[0] = el;
        }
    }
    return array;
}

void aes::shiftRows(bool inv) {
    uint count = 1;

    for(uint i = 1; i < state.size(); i++) {
        state[i] = leftRightShift(state[i], count, inv);
        count++;
    }
}

uint8_t aes::mul_by_02(uint8_t num) {
    uint8_t res;

    if (num < 0x80) res = (num << 1);
    else res = (num << 1) ^ 0x1b;

    return res % 0x100;
}


uint8_t aes::mul_by_03(uint8_t num) {
    return (mul_by_02(num) ^ num);
}


uint8_t aes::mul_by_09(uint8_t num) {
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ num;
}


uint8_t aes::mul_by_0b(uint8_t num) {
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num;
}


uint8_t aes::mul_by_0d(uint8_t num) {
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num;
}


uint8_t aes::mul_by_0e(uint8_t num) {
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ mul_by_02(num);
}

void aes::mixColumns(bool inv) {
    uint8_t s0, s1, s2, s3;

    for(uint i = 0; i < nb; i++) {
        if(!inv) {
            s0 = mul_by_02(state[0][i]) ^ mul_by_03(state[1][i]) ^ state[2][i] ^ state[3][i];
            s1 = state[0][i] ^ mul_by_02(state[1][i]) ^ mul_by_03(state[2][i]) ^ state[3][i];
            s2 = state[0][i] ^ state[1][i] ^ mul_by_02(state[2][i]) ^ mul_by_03(state[3][i]);
            s3 = mul_by_03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ mul_by_02(state[3][i]);
        }
        else {
            s0 = mul_by_0e(state[0][i]) ^ mul_by_0b(state[1][i]) ^ mul_by_0d(state[2][i]) ^ mul_by_09(state[3][i]);
            s1 = mul_by_09(state[0][i]) ^ mul_by_0e(state[1][i]) ^ mul_by_0b(state[2][i]) ^ mul_by_0d(state[3][i]);
            s2 = mul_by_0d(state[0][i]) ^ mul_by_09(state[1][i]) ^ mul_by_0e(state[2][i]) ^ mul_by_0b(state[3][i]);
            s3 = mul_by_0b(state[0][i]) ^ mul_by_0d(state[1][i]) ^ mul_by_09(state[2][i]) ^ mul_by_0e(state[3][i]);
        }
        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
}

void aes::addRoundKey(array<array<uint8_t, nb * (nr + 1)>, 4> key_schedule, uint round) {
    uint8_t s0, s1, s2, s3;

    for(uint col = 0; col < nb; col++) {
        s0 = state[0][col] ^ key_schedule[0][nb * round + col];
        s1 = state[1][col] ^ key_schedule[1][nb * round + col];
        s2 = state[2][col] ^ key_schedule[2][nb * round + col];
        s3 = state[3][col] ^ key_schedule[3][nb * round + col];

        state[0][col] = s0;
        state[1][col] = s1;
        state[2][col] = s2;
        state[3][col] = s3;
    }
}

array<array<uint8_t, nb * (nr + 1)>, 4> aes::keyExpansion(QVector<uint8_t> key)
{
    QVector <uint8_t> key_symbols = key;

    if (key_symbols.size() < 4 * nk) {
        for (uint i = 4 * nk - key_symbols.size(); i > 0; i--) key_symbols.push_back(0x01);
    }

    array<array<uint8_t, nb * (nr + 1)>, 4> key_schedule;

    for (uint r = 0; r < 4; r++) {
        for (uint c = 0; c < nk; c++) key_schedule[r][c] = key_symbols[r + 4 * c];
    }

    uint8_t s, sbox_row, sbox_col, sbox_elem ;
    array<uint8_t, 4> tmp;
    for(int col = nk; col < nb*(nr + 1); col++) {
        if (col % nk == 0) {
            for(uint row = 1; row < 4; row++) tmp[row - 1] =  key_schedule[row][col - 1];
            tmp[3] = key_schedule[0][col - 1];

            for (uint j = 0; j < tmp.size(); j++) {
                sbox_row = tmp[j] / 0x10;
                sbox_col = tmp[j] % 0x10;
                sbox_elem = sbox[16 * sbox_row + sbox_col];
                tmp[j] = sbox_elem;
            }

            for(uint row = 0; row < 4; row++) {
                s = (key_schedule[row][col - 4]) ^ (tmp[row]) ^ (con[row][int(col / nk - 1)]);
                key_schedule[row][col] = s;
            }

        }
        else {
            for (uint row = 0; row < 4; row++) {
                s = key_schedule[row][col - 4] ^ key_schedule[row][col - 1];
                key_schedule[row][col] = s;
            }
        }
    }
    return key_schedule;
}
