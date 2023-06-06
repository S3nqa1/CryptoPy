import time


class AES:

    def __init__(self, master_key: bytes):
        self._rounds_by_key_size = {16: 10, 24: 12, 32: 14}
        self._s_box = self._s_box_reading('aes_s_box.txt')
        self._s_box_inv = self._s_box_reading('aes_s_box_inverse.txt')
        self._r_con = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                       0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
                       0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
                       0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39)
        assert len(master_key) in self._rounds_by_key_size, 'Key length shall be equal to 16|24|32 bytes!'
        self._n_rounds = self._rounds_by_key_size[len(master_key)]
        self._key_matrices = self._key_expansion(master_key)

    @staticmethod
    def _s_box_reading(filename: str):
        file = open(filename, mode='r')
        text = file.read().replace('\n', ' ').split(' ')
        result_box = list()
        for i in range(0, 256):
            result_box.append(int(text[i], 16))
        return result_box

    @staticmethod
    def pad(plaintext: bytes):
        padding_len = 16 - (len(plaintext) % 16)
        padding = bytes([padding_len] * padding_len)
        return plaintext + padding

    @staticmethod
    def unpad(plaintext: bytes):
        padding_len = plaintext[-1]
        assert padding_len > 0
        message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
        assert all(p == padding_len for p in padding)
        return message

    @staticmethod
    def _split_blocks(message: bytes, block_size: int = 16) -> list:
        assert len(message) % block_size == 0
        return [message[i:i + 16] for i in range(0, len(message), block_size)]

    def _sub_bytes(self, s: list) -> None:
        for i in range(4):
            for j in range(4):
                s[i][j] = self._s_box[s[i][j]]

    def _sub_bytes_inverse(self, s: list) -> None:
        for i in range(4):
            for j in range(4):
                s[i][j] = self._s_box_inv[s[i][j]]

    @staticmethod
    def _shift_rows(s: list) -> None:
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

    @staticmethod
    def _shift_rows_inverse(s: list) -> None:
        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

    @staticmethod
    def _bytes_to_matrix(text: bytes) -> list:
        return [list(text[i:i + 4]) for i in range(0, len(text), 4)]

    @staticmethod
    def _matrix_to_bytes(matrix: list) -> bytes:
        return bytes(sum(matrix, list()))

    @staticmethod
    def _xor_bytes(a, b) -> bytes:
        return bytes(i ^ j for i, j in zip(a, b))

    @staticmethod
    def _add_round_key(s: list, k: list) -> None:
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]

    @staticmethod
    def _x_time(a: int):
        return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    def _mix_single_column(self, a: list) -> None:
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ self._x_time(a[0] ^ a[1])
        a[1] ^= t ^ self._x_time(a[1] ^ a[2])
        a[2] ^= t ^ self._x_time(a[2] ^ a[3])
        a[3] ^= t ^ self._x_time(a[3] ^ u)

    def _mix_columns(self, s: list) -> None:
        for i in range(4):
            self._mix_single_column(s[i])

    def _mix_columns_inverse(self, s: list) -> None:
        for i in range(4):
            u = self._x_time(self._x_time(s[i][0] ^ s[i][2]))
            v = self._x_time(self._x_time(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v
        self._mix_columns(s)

    def _key_expansion(self, master_key: bytes) -> list:
        """ Expands and returns a list of key matrices for the given master_key. """
        ''' Initialize round keys with raw key material. '''
        key_columns = self._bytes_to_matrix(master_key)
        iteration_size = len(master_key) // 4
        index = 1
        while len(key_columns) < (self._n_rounds + 1) * 4:
            ''' Copy previous word. '''
            word = list(key_columns[-1])
            ''' Perform schedule_core once every "row". '''
            if len(key_columns) % iteration_size == 0:
                ''' Circular shift. '''
                word.append(word.pop(0))
                ''' Map to S-BOX. '''
                word = [self._s_box[b] for b in word]
                ''' XOR with first byte of R-CON, since the others bytes of R-CON are 0. '''
                word[0] ^= self._r_con[index]
                index += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                ''' Run word through S-box in the fourth iteration when using a 256-bit key. '''
                word = [self._s_box[b] for b in word]
            ''' XOR with equivalent word from previous iteration. '''
            word = self._xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(list(word))
        ''' Group key words in 4x4 byte matrices. '''
        return [key_columns[4 * i: 4 * (i + 1)] for i in range(len(key_columns) // 4)]

    def _encrypt_block(self, plaintext: bytes) -> bytes:
        assert len(plaintext) == 16
        plain_state = self._bytes_to_matrix(plaintext)
        self._add_round_key(plain_state, self._key_matrices[0])
        for i in range(1, self._n_rounds):
            self._sub_bytes(plain_state)
            self._shift_rows(plain_state)
            self._mix_columns(plain_state)
            self._add_round_key(plain_state, self._key_matrices[i])
        self._sub_bytes(plain_state)
        self._shift_rows(plain_state)
        self._add_round_key(plain_state, self._key_matrices[-1])
        return self._matrix_to_bytes(plain_state)

    def _decrypt_block(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) == 16
        cipher_state = self._bytes_to_matrix(ciphertext)
        self._add_round_key(cipher_state, self._key_matrices[-1])
        self._shift_rows_inverse(cipher_state)
        self._sub_bytes_inverse(cipher_state)
        for i in range(self._n_rounds - 1, 0, -1):
            self._add_round_key(cipher_state, self._key_matrices[i])
            self._mix_columns_inverse(cipher_state)
            self._shift_rows_inverse(cipher_state)
            self._sub_bytes_inverse(cipher_state)
        self._add_round_key(cipher_state, self._key_matrices[0])
        return self._matrix_to_bytes(cipher_state)

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        blocks = list()
        for plaintext_block in self._split_blocks(plaintext):
            block = self._encrypt_block(plaintext_block)
            blocks.append(block)
        return b''.join(blocks)

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        blocks = list()
        for ciphertext_block in self._split_blocks(ciphertext):
            block = self._decrypt_block(ciphertext_block)
            blocks.append(block)
        return b''.join(blocks)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16
        blocks = list()
        previous = iv
        for plaintext_block in self._split_blocks(plaintext):
            block = self._encrypt_block(self._xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block
        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16
        blocks = list()
        previous = iv
        for ciphertext_block in self._split_blocks(ciphertext):
            blocks.append(self._xor_bytes(previous, self._decrypt_block(ciphertext_block)))
            previous = ciphertext_block
        return b''.join(blocks)

    def menu(aes_unit):
        print('Menu:')
        print('Options:\n  1 - ECB Encryption\n  2 - ECB Decryption\n  3 - CBC Encryption\n  4 - CBC Decryption\n  '
              '0 - Back\n')
        while True:
            option = int(input('\nEnter option to choose the action: '))
            if option == 0:
                print('\nExit.')
                break
            elif option == 1:
                with open('plaintext.txt', 'r') as file:
                    plaintext = file.read().replace('\n', '').replace(' ', '')
                print('File is read! Start encrypting...')
                start = time.time()
                ciphertext = aes_unit.encrypt_ecb(aes_unit.pad(bytes(plaintext, 'utf-8')))
                print('Encrypted!\nTime spent: ', time.time() - start)
                with open('encrypted_text_AES_ECB.txt', 'w') as file:
                    file.write(str(ciphertext))
            elif option == 2:
                with open('encrypted_text_AES_ECB.txt', 'r') as file:
                    ciphertext = file.read()
                print('File is read! Start decrypting...')
                start = time.time()
                plaintext = aes_unit.unpad(aes_unit.decrypt_ecb(eval(ciphertext)))
                print('Decrypted!\nTime spent: ', time.time() - start)
                with open('decrypted_text_AES_ECB.txt', 'wb') as file:
                    file.write(plaintext)
            elif option == 3:
                with open('plaintext.txt', 'r') as file:
                    plaintext = file.read().replace('\n', '').replace(' ', '')
                init_vector = bytes(input('Enter initialization vector (16 bytes): '), 'utf-8')
                print('File is read! Start encrypting...')
                start = time.time()
                ciphertext = aes_unit.encrypt_cbc(aes_unit.pad(bytes(plaintext, 'utf-8')), iv=init_vector)
                print('Encrypted!\nTime spent: ', time.time() - start)
                with open('encrypted_text_AES_CBC.txt', 'w') as file:
                    file.write(str(ciphertext))
            elif option == 4:
                with open('encrypted_text_AES_CBC.txt', 'r') as file:
                    ciphertext = file.read()
                init_vector = bytes(input('Enter initialization vector (16 bytes): '), 'utf-8')
                print('File is read! Start decrypting...')
                start = time.time()
                plaintext = aes_unit.unpad(aes_unit.decrypt_cbc(eval(ciphertext), iv=init_vector))
                print('Decrypted!\nTime spent: ', time.time() - start)
                with open('decrypted_text_AES_CBC.txt', 'wb') as file:
                    file.write(plaintext)
