#include "aes_128.h"

AES_128::AES_128()
{

}

array<unsigned char, 16> AES_128::encrypt(array<unsigned char, 16> input_bytes, QVector<unsigned char> key)
{
    array<array<unsigned char, nb>, 4> state;
    for (unsigned int r = 0; r < 4; r++)
    {
        for (unsigned int c = 0; c < nb; c++) state[r][c] = input_bytes[r + 4 * c];
    }

    array<array<unsigned char, nb * (nr + 1)>, 4> key_schedule = key_expansion(key);

    state = addRoundKey(state, key_schedule);

    unsigned int rnd;
    for (rnd = 1; rnd < nr; rnd++)
    {
        state = subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);
        state = addRoundKey(state, key_schedule, rnd);
    }

    state = subBytes(state);
    state = shiftRows(state);
    state = addRoundKey(state, key_schedule, rnd);

    array<unsigned char, 16> output;
    for (unsigned int r = 0; r < 4; r++)
    {
         for (unsigned int c = 0; c < nb; c++) output[r + 4 * c] = state[r][c];
    }

    return output;
}

array<unsigned char, 16> AES_128::decrypt(array<unsigned char, 16> cipher, QVector<unsigned char>  key)
{
    array<array<unsigned char, nb>, 4> state;
    for (unsigned int r = 0; r < 4; r++)
    {
        for (unsigned int c = 0; c < nb; c++) state[r][c] = cipher[r + 4 * c];
    }

    array<array<unsigned char, nb * (nr + 1)>, 4> key_schedule = key_expansion(key);

    state = addRoundKey(state, key_schedule, nr);

    unsigned int rnd = nr - 1;
    while (rnd >= 1)
    {
        state = shiftRows(state, true);
        state = subBytes(state, true);
        state = addRoundKey(state, key_schedule, rnd);
        state = mixColumns(state, true);

        rnd--;
    }

    state = shiftRows(state, true);
    state = subBytes(state, true);
    state = addRoundKey(state, key_schedule, rnd);

    array<unsigned char, 16> output;
    for (unsigned int r = 0; r < 4; r++)
    {
         for (unsigned int c = 0; c < nb; c++) output[r + 4 * c] = state[r][c];
    }

    return output;
}

array<array<unsigned char, nb>, 4> AES_128::subBytes(array<array<unsigned char, nb>, 4> state, bool inv)
{
    array<unsigned char, 256> box;

    if (inv == false) box = sbox;
    else  box = inv_sbox;

    unsigned long long row;
    unsigned long long col;
    unsigned char box_elem;

    for (unsigned long long i = 0; i < state.size(); i++)
    {
       for (unsigned long long j = 0; j < state[i].size(); j++)
       {
           row = state[i][j] / 0x10;
           col = state[i][j] % 0x10;

           box_elem = box[16 * row + col];
           state[i][j] = box_elem;
       }
    }

    return state;
}

array<unsigned char, nb> AES_128::leftRightShift(array<unsigned char, nb> array, unsigned int count, bool inv)
{
    unsigned char el;

    if (inv == false)
    {
        while(count--)
        {
            el = array[0];
            for(unsigned long long i = 0; i < array.size() - 1; i++)
            {
                array[i] = array[i + 1];
            }
            array[array.size() - 1] = el;
        }
    }
    else
    {
        while(count--)
        {
            el = array[array.size() - 1];
            for(unsigned long long i = array.size() - 1; i > 0; i--)
            {
                array[i] = array[i - 1];
            }
            array[0] = el;
        }
    }
    return array;
}

array<array<unsigned char, nb>, 4> AES_128::shiftRows(array<array<unsigned char, nb>, 4> state, bool inv)
{
    unsigned int count = 1;

    for(unsigned long long i = 1; i < state.size(); i++)
    {
        state[i] = leftRightShift(state[i], count, inv);
        count++;
    }

    return state;
}

unsigned char AES_128::mul_by_02(unsigned char num)
{
    unsigned char res;

    if (num < 0x80) res = (num << 1);
    else res = (num << 1) ^ 0x1b;

    return res % 0x100;
}


unsigned char AES_128::mul_by_03(unsigned char num)
{
    return (mul_by_02(num) ^ num);
}


unsigned char AES_128::mul_by_09(unsigned char num)
{
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ num;
}


unsigned char AES_128::mul_by_0b(unsigned char num)
{
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num;
}


unsigned char AES_128::mul_by_0d(unsigned char num)
{
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num;
}


unsigned char AES_128::mul_by_0e(unsigned char num)
{
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ mul_by_02(num);
}

array<array<unsigned char, nb>, 4> AES_128::mixColumns(array<array<unsigned char, nb>, 4> state, bool inv)
{
    unsigned char s0, s1, s2, s3;

    for(unsigned long long i = 0; i < nb; i++)
    {
        if(inv == false)
        {
            s0 = mul_by_02(state[0][i]) ^ mul_by_03(state[1][i]) ^ state[2][i] ^ state[3][i];
            s1 = state[0][i] ^ mul_by_02(state[1][i]) ^ mul_by_03(state[2][i]) ^ state[3][i];
            s2 = state[0][i] ^ state[1][i] ^ mul_by_02(state[2][i]) ^ mul_by_03(state[3][i]);
            s3 = mul_by_03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ mul_by_02(state[3][i]);
        }
        else
        {
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

    return state;
}

array<array<unsigned char, nb>, 4> AES_128::addRoundKey(array<array<unsigned char, nb>, 4> state, array<array<unsigned char, nb * (nr + 1)>, 4> key_schedule, unsigned int round)
{
    unsigned char s0, s1, s2, s3;

    for(unsigned long long col = 0; col < nk; col++)
    {
        s0 = state[0][col] ^ key_schedule[0][nb * round + col];
        s1 = state[1][col] ^ key_schedule[1][nb * round + col];
        s2 = state[2][col] ^ key_schedule[2][nb * round + col];
        s3 = state[3][col] ^ key_schedule[3][nb * round + col];

        state[0][col] = s0;
        state[1][col] = s1;
        state[2][col] = s2;
        state[3][col] = s3;
    }

    return state;
}

array<array<unsigned char, nb * (nr + 1)>, 4> AES_128::key_expansion(QVector<unsigned char> key)
{
    QVector <unsigned char> key_symbols = key;

    if (key_symbols.size() < 4 * nk)
    {
        for (unsigned long long i = 4 * nk - key_symbols.size(); i > 0; i--) key_symbols.push_back(0x01);
    }

    array<array<unsigned char, nb * (nr + 1)>, 4> key_schedule;

    for (unsigned int r = 0; r < 4; r++)
    {
        for (unsigned int c = 0; c < nk; c++) key_schedule[r][c] = key_symbols[r + 4 * c];
    }

    unsigned char s, sbox_row, sbox_col, sbox_elem ;
    array<unsigned char, 4> tmp;
    for(int col = nk; col < nb*(nr + 1); col++)
    {
        if (col % nk == 0)
        {
            for(unsigned long long row = 1; row < 4; row++) tmp[row - 1] =  key_schedule[row][col - 1];
            tmp[3] = key_schedule[0][col - 1];

            for (unsigned long long j = 0; j < tmp.size(); j++)
            {
                sbox_row = tmp[j] / 0x10;
                sbox_col = tmp[j] % 0x10;
                sbox_elem = sbox[16 * sbox_row + sbox_col];
                tmp[j] = sbox_elem;
            }

            for(unsigned long long row = 0; row < 4; row++)
            {
                s = (key_schedule[row][col - 4]) ^ (tmp[row]) ^ (con[row][int(col / nk - 1)]);
                key_schedule[row][col] = s;
            }

        }
        else
        {
            for (unsigned long long row = 0; row < 4; row++)
            {
                s = key_schedule[row][col - 4] ^ key_schedule[row][col - 1];
                key_schedule[row][col] = s;
            }
        }
    }

    return key_schedule;
}










