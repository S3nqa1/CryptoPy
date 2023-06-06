from bitarray import bitarray
import time


class DES(object):

    def __init__(self):
        self.keys = list()
        self.s_box_table = self.s_block()
        self.init_block = self.init_block()
        self.end_block = self.end_block()

    @staticmethod
    def init_block():
        file = open('init_table.txt', mode='r')
        text = file.read().replace('\n', ' ').split(' ')
        replace_table = list()
        for i in text:
            replace_table.append(int(i))
        return replace_table

    @staticmethod
    def end_block():
        file = open('end_table.txt', mode='r')
        text = file.read().replace('\n', ' ').split(' ')
        replace_table = list()
        for i in text:
            replace_table.append(int(i))
        return replace_table

    @staticmethod
    def s_block():
        file = open('table.txt', mode='r')
        text = file.read().replace('\n', ' ').split(' ')
        for i in text:
            if i == '':
                text.remove(i)
        s_box_table = list()
        list2 = list()
        list3 = list()
        for i in range(0, 512):
            list3.append(int(text[i]))
            if (i + 1) % 16 == 0:
                list2.append(list3)
                list3 = list()
            if len(list2) == 4:
                s_box_table.append(list2)
                list2 = list()
        return s_box_table

    @staticmethod
    def bit_encoding(string):
        return bitarray(''.join([bin(int('1' + hex(c)[2:], 16))[3:] for c in string.encode('utf-8')])).to01()

    @staticmethod
    def bit_decoding(string_list):
        return ''.join([chr(i) for i in [int(b, 2) for b in string_list]])

    @staticmethod
    def replace_block(block, replace_table):
        result = str()
        for i in replace_table:
            result += block[i - 1]
        return result

    def processing_encode(self, enter):
        result = list()
        bits = self.bit_encoding(enter)
        if len(bits) % 64 != 0:
            for i in range(64 - len(bits) % 64):
                bits += '0'
        for i in range(len(bits) // 64):
            result.append(bits[i * 64:i * 64 + 64])
        return result

    @staticmethod
    def processing_decode(enter):
        result = list()
        input_list = enter.split('0x')[1:]
        int_list = [int('0x' + i, 16) for i in input_list]
        for i in int_list:
            binary_data = str(bin(i))[2:]
            while len(binary_data) < 64:
                binary_data = '0' + binary_data
            result.append(binary_data)
        return result

    def key_conversion(self, key):
        while len(key) < 64:
            key += '0'
        first_key = key[:64]
        key_replace_table = (
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
        return self.replace_block(first_key, key_replace_table)

    def key_spin(self, key):
        key_converted = self.key_conversion(key)
        left = key_converted[0:28]
        right = key_converted[28:56]
        spin_table = (1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28)
        for i in range(1, 17):
            left_after_spin = left[spin_table[i - 1]:] + left[:spin_table[i - 1]]
            right_after_spin = right[spin_table[i - 1]:] + right[:spin_table[i - 1]]
            yield left_after_spin + right_after_spin

    def key_selection_replacement(self, key):
        self.keys = list()
        key_select_table = (
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        )
        for child_key56 in self.key_spin(key):
            self.keys.append(self.replace_block(child_key56, key_select_table))

    def init_replace_block(self, block):
        return self.replace_block(block, self.init_block)

    def end_replace_block(self, block):
        return self.replace_block(block, self.end_block)

    @staticmethod
    def block_extend(block):
        extended_block = str()
        extend_table = (
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        )
        for i in extend_table:
            extended_block += block[i - 1]
        return extended_block

    @staticmethod
    def xor(str1, str2):
        result = str()
        size = len(str1) if len(str1) > len(str2) else len(str2)
        for i in range(size):
            result += '0' if str1[i] == str2[i] else '1'
        return result

    def s_block_replacement(self, block48):
        result = str()
        for i in range(8):
            row_bit = (block48[i * 6] + block48[i * 6 + 5]).encode("utf-8")
            line_bit = (block48[i * 6 + 1: i * 6 + 5]).encode("utf-8")
            row = int(row_bit, 2)
            line = int(line_bit, 2)
            data = self.s_box_table[i][row][line]
            no_full = str(bin(data))[2:]
            while len(no_full) < 4:
                no_full = '0' + no_full
            result += no_full
        return result

    def s_block_compression(self, num, block48):
        result_xor = self.xor(block48, self.keys[num])
        return self.s_block_replacement(result_xor)

    def p_block_replacement(self, block32):
        p_box_replace_table = (
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
        )
        return self.replace_block(block32, p_box_replace_table)

    def f_function(self, right, is_decode, num):
        right = self.block_extend(right)
        if is_decode:
            sbc_result = self.s_block_compression(15 - num, right)
        else:
            sbc_result = self.s_block_compression(num, right)
        return self.p_block_replacement(sbc_result)

    def iteration(self, block, key, is_decode):
        self.key_selection_replacement(key)
        for i in range(0, 16):
            left, right = block[0: 32], block[32: 64]
            next_left = right
            f_result = self.f_function(right, is_decode, i)
            right = self.xor(left, f_result)
            block = next_left + right
        return block[32:] + block[:32]

    def encrypt_ecb(self, enter, key):
        """Electronic Codebook Encryption"""
        result = str()
        blocks = list()
        blocks = self.processing_encode(enter)
        for block in blocks:
            irb_result = self.init_replace_block(block)
            block_result = self.iteration(irb_result, key, is_decode=False)
            block_result = self.end_replace_block(block_result)
            result += str(hex(int(block_result.encode(), 2)))
        return result

    def decrypt_ecb(self, cipher, key):
        """Electronic Codebook Decryption"""
        result = list()
        blocks = list()
        blocks = self.processing_decode(cipher)
        for block in blocks:
            irb_result = self.init_replace_block(block)
            block_result = self.iteration(irb_result, key, is_decode=True)
            block_result = self.end_replace_block(block_result)
            for i in range(0, len(block_result), 8):
                result.append(block_result[i: i + 8])
        return self.bit_decoding(result)

    def encrypt_cbc(self, enter, key):
        """Cipher-Block Chaining Encryption"""
        result = str()
        blocks = list()
        blocks = self.processing_encode(enter)
        init_vector = '0110010001101001011101100110100101110011011010010110111101101110'
        res_xor = self.xor(blocks[0], init_vector)
        for i in range(0, len(blocks)):
            blocks[i] = res_xor
            irb_result = self.init_replace_block(blocks[i])
            block_result = self.iteration(irb_result, key, is_decode=False)
            block_result = self.end_replace_block(block_result)
            result += str(hex(int(block_result.encode(), 2)))
            if i < len(blocks) - 1:
                res_xor = self.xor(block_result, blocks[i + 1])
        return result

    def decrypt_cbc(self, cipher, key):
        """Cipher-Block Chaining Decryption"""
        result = list()
        blocks = list()
        blocks = self.processing_decode(cipher)
        init_vector = '0110010001101001011101100110100101110011011010010110111101101110'
        res_xor = str()
        for i in range(0, len(blocks)):
            irb_result = self.init_replace_block(blocks[i])
            block_result = self.iteration(irb_result, key, is_decode=True)
            block_result = self.end_replace_block(block_result)
            if i == 0:
                res_xor = self.xor(block_result, init_vector)
            if 0 < i < len(blocks):
                res_xor = self.xor(block_result, blocks[i - 1])
            for j in range(0, len(block_result), 8):
                result.append(res_xor[j: j + 8])
        return self.bit_decoding(result)

    def menu(des_unit):
        def readfile(filename):
            try:
                file = open(filename, mode='r', encoding='utf-8')
                file_text = file.read()
                file_text = file_text.replace('\n', ' ')
                file_text = file_text.replace(' ', '')
                file.close()
                return file_text
            except FileNotFoundError:
                print('File not found! Check the path.')
                raise SystemExit(0)

        def writefile(filename, data):
            try:
                file = open(filename, mode='w')
                file_text = file.write(data)
                file.close()
                return file_text
            except FileNotFoundError:
                print('File not found! Check the path.')
                raise SystemExit(0)

        print('Menu:')
        print('Options:\n  1 - ECB Encryption\n  2 - ECB Decryption\n  3 - CBC Encryption\n  4 - CBC Decryption\n 0 - '
              'Back\n')
        while True:
            option = int(input('Enter option to choose the action: '))
            if option == 0:
                print('\nExit.')
                break
            elif option == 1:
                file = open('binary_key.txt', mode='r')
                keys = file.read()
                plaintext = readfile('plaintext.txt')
                start = time.time()
                print('Start: ', start)
                ciphertext = des_unit.encrypt_ecb(plaintext, keys)
                print('Time spent: ', time.time() - start)
                writefile('encrypted_text_DES_ECB.txt', ciphertext)
            elif option == 2:
                file = open('binary_key.txt', mode='r')
                keys = file.read()
                ciphertext = open('encrypted_text_DES_ECB.txt', mode='r').read()
                start = time.time()
                print('Start: ', start)
                plaintext = des_unit.decrypt_ecb(ciphertext, keys)
                print('Decrypted!\nTime spent: ', time.time() - start)
                writefile('decrypted_text_DES_ECB.txt', plaintext)
            elif option == 3:
                file = open('binary_key.txt', mode='r')
                keys = file.read()
                plaintext = readfile('plaintext.txt')
                start = time.time()
                print('Start: ', start)
                ciphertext = des_unit.encrypt_cbc(plaintext, keys)
                print('Encrypted!\nTime spent: ', time.time() - start)
                writefile('encrypted_text_DES_CBC.txt', ciphertext)
            elif option == 4:
                file = open('binary_key.txt', mode='r')
                keys = file.read()
                ciphertext = readfile('encrypted_text_DES_CBC.txt')
                print('File is read! Start decrypting...')
                start = time.time()
                plaintext = des_unit.decrypt_cbc(ciphertext, keys)
                print('Decrypted!\nTime spent: ', time.time() - start)
                with open('decrypted_text_DES_CBC.txt', 'w') as file:
                    file.write(str(plaintext))
            else:
                print('Invalid value')
                break

