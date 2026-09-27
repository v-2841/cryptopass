"""Tests for cryptopass. Run: python3 -m unittest -v"""

import hashlib
import secrets
import unittest

import cryptopass as cp

try:
    import segno
except ImportError:
    segno = None

# From the Trezor BIP39 test vectors.
VECTORS = [
    'abandon abandon abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon about',
    'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
    'gravity machine north sort system female filter attitude volume fold '
    'club stay feature office ecology stable narrow fog',
    'all hour make first leader extend hole alien behind guard gospel lava '
    'path output census museum junior mass reopen famous sing advance salt '
    'reform',
]
FAST = 10  # log2 of scrypt N, small to keep the tests quick


def random_phrase(count):
    """Make a valid BIP39 phrase from random entropy."""
    entropy = secrets.token_bytes(count * 4 // 3)
    check_bits = count // 3
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - check_bits)
    bits = int.from_bytes(entropy, 'big') << check_bits | checksum
    return [cp.WORDS[(bits >> 11 * (count - 1 - i)) & 0x7FF]
            for i in range(count)]


class Bip39Test(unittest.TestCase):

    def test_wordlist(self):
        self.assertEqual(len(cp.WORDS), 2048)
        self.assertEqual(cp.wordlist_sha256(), cp.WORDLIST_SHA256)

    def test_vectors(self):
        for phrase in VECTORS:
            self.assertTrue(cp.bip39_valid(phrase.split()), phrase)

    def test_random_phrases(self):
        for count in cp.WORD_COUNTS:
            self.assertTrue(cp.bip39_valid(random_phrase(count)))

    def test_bad_checksum(self):
        words = VECTORS[0].split()
        words[-1] = 'abandon'
        self.assertFalse(cp.bip39_valid(words))
        self.assertFalse(cp.bip39_valid(words[:11]))
        self.assertFalse(cp.bip39_valid(['abandon'] * 11 + ['notaword']))

    def test_lookup(self):
        self.assertEqual(cp.lookup('aban'), ['abandon'])
        self.assertEqual(cp.lookup('act'),
                         ['act', 'action', 'actor', 'actress', 'actual'])
        self.assertEqual(cp.lookup('zoo'), ['zoo'])
        self.assertEqual(cp.lookup('zz'), [])
        self.assertEqual(len(cp.lookup('')), 2048)


class CryptoTest(unittest.TestCase):

    def test_round_trip(self):
        passwords = ['a', 'correct horse battery staple',
                     'пароль с пробелами и 🔑', 'x' * 5000]
        for phrase in VECTORS:
            words = phrase.split()
            for password in passwords:
                code = cp.encrypt(words, password, FAST)
                self.assertEqual(cp.decrypt(code, password), words)

    def test_all_lengths(self):
        for count in cp.WORD_COUNTS:
            words = random_phrase(count)
            code = cp.encrypt(words, 'pw', FAST)
            self.assertEqual(len(code), cp.code_len(count))
            self.assertEqual(cp.decrypt(code, 'pw'), words)

    def test_non_bip39_phrase(self):
        words = ['zoo'] * 12
        self.assertFalse(cp.bip39_valid(words))
        self.assertEqual(cp.decrypt(cp.encrypt(words, 'pw', FAST), 'pw'),
                         words)

    def test_fresh_salt(self):
        words = VECTORS[0].split()
        codes = {cp.encrypt(words, 'pw', FAST) for _ in range(5)}
        self.assertEqual(len(codes), 5)

    def test_wrong_password(self):
        code = cp.encrypt(VECTORS[0].split(), 'right', FAST)
        for password in ('wrong', 'Right', 'right ', ''):
            with self.assertRaises(cp.DecryptError):
                cp.decrypt(code, password)

    def test_tampered_payload(self):
        code = cp.encrypt(VECTORS[3].split(), 'pw', FAST)
        payload = cp.from_code(code)
        for pos in range(cp.HEADER_LEN, len(payload)):
            broken = bytearray(payload)
            broken[pos] ^= 1
            with self.assertRaises(cp.DecryptError):
                cp.decrypt(cp.to_code(bytes(broken)), 'pw')

    def test_unicode_normalization(self):
        composed, decomposed = 'café', 'café'
        code = cp.encrypt(VECTORS[0].split(), composed, FAST)
        self.assertEqual(cp.decrypt(code, decomposed), VECTORS[0].split())

    def test_default_level(self):
        log_n = cp.LEVELS[0][0]
        code = cp.encrypt(VECTORS[0].split(), 'pw', log_n)
        self.assertEqual(cp.decrypt(code, 'pw'), VECTORS[0].split())

    def test_known_code(self):
        # Locks the format: this code must decrypt in every future version.
        code = ('0461-6001-081G-8186-0W40-J2GB-1G6G-W3WV-9PDT-NEBC-0FK5-'
                '5YJP-8RAJ-V20D-VGYP-0YKE-MHT7-TXZK-Y050')
        salt = bytes(range(16))
        words = VECTORS[0].split()
        self.assertEqual(cp.encrypt(words, 'pw', 19, salt=salt),
                         cp.clean_code(code))
        self.assertEqual(cp.decrypt(code, 'pw'), words)


class CodeTest(unittest.TestCase):

    def setUp(self):
        self.words = VECTORS[3].split()
        self.code = cp.encrypt(self.words, 'pw', FAST)

    def test_lengths(self):
        self.assertEqual([cp.code_len(n) for n in cp.WORD_COUNTS],
                         [76, 84, 88, 96, 104])

    def test_forgiving_input(self):
        messy = self.code.lower().replace('0', 'o').replace('1', 'l')
        messy = ' - '.join(messy[i:i + 4] for i in range(0, len(messy), 4))
        self.assertEqual(cp.decrypt(messy, 'pw'), self.words)

    def test_expected_len(self):
        self.assertIsNone(cp.expected_len(self.code[:4]))
        self.assertEqual(cp.expected_len(self.code[:5]), len(self.code))
        with self.assertRaises(cp.CodeError):
            cp.expected_len('ZZZZZ')

    def test_single_typo_is_located(self):
        for pos in range(len(self.code)):
            old = self.code[pos]
            new = cp.ALPHABET[(cp.DIGITS[old] + 7) % 32]
            typo = self.code[:pos] + new + self.code[pos + 1:]
            try:
                cp.from_code(typo)
            except cp.TypoError as error:
                self.assertIn((pos, old), error.fixes)
            except cp.CodeError:
                # A typo in the first group can change the stated length.
                self.assertLess(pos, 5)
            else:
                self.fail(f'typo at {pos} was not detected')

    def test_swap_is_located(self):
        code = self.code
        pos = next(i for i in range(20, len(code) - 1)
                   if code[i] != code[i + 1])
        swapped = code[:pos] + code[pos + 1] + code[pos] + code[pos + 2:]
        with self.assertRaises(cp.TypoError) as context:
            cp.from_code(swapped)
        self.assertIn((pos, code[pos:pos + 2]), context.exception.fixes)

    def test_wrong_length(self):
        for text in (self.code[:-1], self.code + '0', self.code[:-4]):
            with self.assertRaises(cp.CodeError) as context:
                cp.from_code(text)
            self.assertNotIsInstance(context.exception, cp.TypoError)

    def test_code_lines(self):
        lines = cp.code_lines(self.code)
        self.assertEqual(lines[0], '-'.join(
            self.code[i:i + 4] for i in range(0, 16, 4)))
        self.assertEqual(cp.clean_code('\n'.join(lines)), self.code)
        self.assertTrue(all(len(line) <= 19 for line in lines))

    def test_bad_characters(self):
        with self.assertRaises(cp.CodeError):
            cp.from_code(self.code[:10] + 'U' + self.code[11:])
        self.assertIsNone(cp.clean_char('U'))
        self.assertEqual(cp.clean_char('-'), '')
        self.assertEqual(cp.clean_char('o'), '0')


def byte_aligned(text, version):
    """True if the QR data ends exactly on a byte after the terminator."""
    length = len(cp._qr_bits(text, version))
    length += min(4, cp._qr_capacity(version) * 8 - length)
    return length % 8 == 0


class QrTest(unittest.TestCase):

    @unittest.skipIf(segno is None, 'segno is not installed')
    def test_matches_segno(self):
        samples = ['A', '01', 'HELLO WORLD', 'Z' * 150, '9' * 395]
        samples += ['-'.join(cp.code_lines(
            cp.encrypt(random_phrase(n), 'pw', FAST)))
            for n in cp.WORD_COUNTS]
        for text in samples:
            for mask in range(8):
                mine = cp.qr_matrix(text, mask)
                version = (len(mine) - 17) // 4
                if byte_aligned(text, version):
                    # segno then adds a whole zero byte of padding, while
                    # ISO 18004 adds none: see test_padding.
                    continue
                ref = segno.make_qr(text, error='l', mask=mask,
                                    version=version, mode='alphanumeric',
                                    boost_error=False)
                self.assertEqual(ref.version, version)
                ref_rows = [[bool(x) for x in row] for row in ref.matrix]
                self.assertEqual(mine, ref_rows, (text, mask))

    def test_padding(self):
        # 119 characters: 668 data bits plus a 4-bit terminator make exactly
        # 84 bytes, so the pad codewords follow at once.
        text = 'A' * 119
        self.assertTrue(byte_aligned(text, 5))
        codewords = cp._qr_codewords(text, 5)
        self.assertEqual(codewords[84:88], [0xEC, 0x11, 0xEC, 0x11])

    def test_code_versions(self):
        # Fits an 80x24 terminal: at most version 5 (37 modules).
        for count in cp.WORD_COUNTS:
            code = cp.encrypt(random_phrase(count), 'pw', FAST)
            text = '-'.join(cp.code_lines(code))
            self.assertLessEqual(len(cp.qr_matrix(text)), 37)


if __name__ == '__main__':
    unittest.main()
