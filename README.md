# cryptopass

Encrypt a crypto wallet seed phrase (BIP39) with a password and get a short
code that you can write down on paper. Later, decrypt the code with the same
password to get the phrase back.

- One Python file, standard library only: nothing to install.
- Runs in the terminal. You type the words one by one with autocomplete from
  the BIP39 word list. The app can check your written copy of the code and
  can show the code as a QR code.
- The key comes from the password through scrypt, which needs a lot of
  memory, so every password guess is expensive. A wrong password is always
  detected.
- The format is small and open. You can decrypt a code without this app
  using about 30 lines of Python (see below).

## Run

On Linux and macOS (Python 3.8 or newer):

```sh
curl -fsSL https://raw.githubusercontent.com/v-2841/cryptopass/main/cryptopass.py | python3
```

The app reads the keyboard straight from the terminal, so piping the script
into Python works.

A safer way is to download the file, look through it, and then run your
local copy:

```sh
curl -fsSLO https://raw.githubusercontent.com/v-2841/cryptopass/main/cryptopass.py
less cryptopass.py
python3 cryptopass.py
```

On Windows, or with the macOS system Python (which is built without scrypt),
use [uv](https://docs.astral.sh/uv/). It provides a suitable Python and, on
Windows, the `windows-curses` package. WSL also works.

```sh
uv run https://raw.githubusercontent.com/v-2841/cryptopass/main/cryptopass.py
```

## How to use

The main menu has three modes: **Encrypt**, **Decrypt** and **Help**.
**Esc** goes back one step, and **Ctrl+C** quits at any time.

### Encrypt

1. Choose the number of words: 12, 15, 18, 21 or 24.
2. Type the words. Suggestions appear as you type, and only BIP39 words can
   be entered.
   - **Enter** (or **Tab**) takes the highlighted suggestion, and **↑ ↓**
     choose another one.
   - **Space** accepts a word once it is typed in full or is the only
     match, so you can also just type the words with spaces between them.
   - **← →** move between words, and **F2** hides the words on screen.
   - You can paste the whole phrase, including a numbered list.

   When all words are entered, the BIP39 checksum is checked. Phrases that
   have no BIP39 checksum (Electrum, for example) can still be encrypted
   after a warning.
3. Enter the password twice and choose a protection level.
4. Write the code down. Press **V** to type it back from your paper and check
   the copy. Press **C** to see the code without line numbers, ready to select
   with the mouse and copy, or **Q** to show it as a QR code (a phone shows
   it as plain text, line by line, as on paper).

### Decrypt

1. Type the code. Case, dashes and spaces do not matter. The code has no
   letters O, I or L: typing them counts as 0 or 1. If you made a typo,
   cryptopass usually shows where it is and what the right character is.
2. Enter the password. A wrong password or a damaged code is reported, and
   no phrase is shown in that case.
3. Press **Space** to show the words.

## Security

- **The password is the only protection.** Anyone who gets the code can try
  passwords offline for as long as they like. scrypt makes each guess
  expensive, but a short or common password will still be found. Use six or
  more random words, or a long random password.
- **A forgotten password cannot be recovered.** Nobody, including the author,
  can decrypt a code without its password.
- **Run the app offline, on a computer you trust.** Disconnect from the
  internet before typing a real seed phrase. The app never uses the network
  and never writes to disk. For the most protection, run it from a live
  system such as [Tails](https://tails.net).
- **Check what you run.** The app is a single readable file: download it,
  look through it, and run your local copy.
- **Store the code and the password in different places.** Write
  "cryptopass" and the project URL next to the code, so that you or your
  heirs know how to decrypt it.
- **Known limits.** Python cannot erase secrets from memory, and some
  terminals keep what was on the screen. The app uses the terminal's
  alternate screen, which disappears when the app exits. To be safe, close
  the terminal after you decrypt a phrase.

## Format

A code for a 12-word phrase looks like this:

```
0461-6PA8-JPRZ-TRXF
2J29-RVE4-KWND-FZZK
JSF4-5DB2-B8CE-F8G2
W1YX-920E-3K78-MXWV
4YX7-FNP1-KG10
```

A code has 76 to 104 characters, depending on the number of words. It is
[Crockford's base32](https://www.crockford.com/base32.html) (`0-9 A-Z`
without I, L, O and U) of the following bytes:

| Bytes     | Content                                                   |
|-----------|-----------------------------------------------------------|
| 1         | format version, `1`                                       |
| 1         | number of words `n`: 12, 15, 18, 21 or 24                 |
| 1         | scrypt cost `log2(N)`, with `r = 8` and `p = 1`           |
| 16        | random salt                                               |
| ⌈11n/8⌉   | encrypted word indices                                    |
| 8         | authentication tag                                        |
| 3         | checksum: the first 3 bytes of SHA-256 of all bytes above |

Bits are written most significant first. The code is padded with zero bits
to a whole number of 4-character groups.

Encryption works like this, with `L = ⌈11n/8⌉`:

1. `key = scrypt(password, salt, N, r = 8, p = 1, length = L + 32)`. The
   password is normalized to Unicode NFKC and encoded as UTF-8.
2. The index of each word in the BIP39 English list (0 to 2047) takes
   11 bits. The indices are packed into `L` bytes and XORed with the first
   `L` bytes of the key. The salt is new every time, so the same key stream
   is never used twice.
3. `tag` is the first 8 bytes of
   `HMAC-SHA256(key[L:], version ‖ n ‖ log2(N) ‖ salt ‖ ciphertext)`.

The checksum only catches typos. The tag separates a wrong password from
the right one. Everything is built from standard primitives in Python's
`hashlib`: scrypt ([RFC 7914](https://www.rfc-editor.org/rfc/rfc7914)) and
HMAC-SHA256.

The protection levels are Standard (`N = 2^18`, 256 MiB of memory), Strong
(`N = 2^19`, 512 MiB, the default) and Paranoid (`N = 2^20`, 1 GiB).

### Decrypting without cryptopass

You need Python 3 and the BIP39 English word list,
[english.txt](https://github.com/bitcoin/bips/blob/ce1862ac6bcffa1dd20aad858380e51e66e949ea/bip-0039/english.txt).
The list has not changed since 2014, and the same list is built into
`cryptopass.py` (the `WORDS` constant). The script below checks the file's
SHA-256, so a wrong or damaged list cannot give you wrong words.

```python
import getpass
import hashlib
import hmac
import unicodedata

code = input('Code: ')
password = getpass.getpass('Password: ')
wordlist = open('english.txt', 'rb').read().replace(b'\r\n', b'\n')
assert hashlib.sha256(wordlist).hexdigest() == (
    '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda'
), 'this is not the BIP39 English word list'
words = wordlist.decode().split()

alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
code = code.upper().replace('-', '').replace(' ', '')
code = code.replace('O', '0').replace('I', '1').replace('L', '1')
value = 0
for char in code:
    value = value * 32 + alphabet.index(char)
bits = 5 * len(code)
raw = (value >> bits % 8).to_bytes(bits // 8, 'big')
n, log_n = raw[1], raw[2]
size = (11 * n + 7) // 8
payload, check = raw[:27 + size], raw[27 + size:30 + size]
assert hashlib.sha256(payload).digest()[:3] == check, 'typo in the code'
salt, cipher, tag = payload[3:19], payload[19:19 + size], payload[19 + size:]
secret = unicodedata.normalize('NFKC', password).encode()
key = hashlib.scrypt(secret, salt=salt, n=2 ** log_n, r=8, p=1,
                     maxmem=2 ** 31 - 1, dklen=size + 32)
mac = hmac.new(key[size:], payload[:19 + size], 'sha256').digest()[:8]
assert hmac.compare_digest(mac, tag), 'wrong password'
plain = int.from_bytes(bytes(a ^ b for a, b in zip(cipher, key)), 'big')
plain >>= 8 * size - 11 * n
print(' '.join(words[(plain >> 11 * (n - 1 - i)) & 2047] for i in range(n)))
```

## Tests

```sh
python3 -m unittest -v
```

One test compares the built-in QR encoder with the
[segno](https://pypi.org/project/segno/) library. It is skipped when segno
is not installed.

## License

[MIT](LICENSE) © 2026 Vitaliy Pavlov
