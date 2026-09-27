#!/usr/bin/env python3
# /// script
# requires-python = '>=3.8'
# dependencies = ['windows-curses; sys_platform == "win32"']
# ///
# Copyright (c) 2026 Vitaliy Pavlov
# SPDX-License-Identifier: MIT
"""cryptopass: encrypt a BIP39 seed phrase with a password.

A single-file terminal app built only on the Python standard library.
It turns a seed phrase into a code that is easy to write down on paper,
and turns the code back into the phrase with the same password.

See README.md for how to run it and for a description of the format.
"""

import bisect
import hashlib
import hmac
import locale
import math
import os
import secrets
import sys
import unicodedata

try:
    import curses
except ImportError:  # Windows without the windows-curses package
    curses = None

APP_VERSION = '1.0.0'
REPO_URL = 'github.com/v-2841/cryptopass'
RUN_WITH_UV = ('uv run https://raw.githubusercontent.com/v-2841/cryptopass/'
               'main/cryptopass.py')

# Code format, see README.md.
FORMAT_VERSION = 1
WORD_COUNTS = (12, 15, 18, 21, 24)
HEADER_LEN = 3
SALT_LEN = 16
TAG_LEN = 8
CHECK_LEN = 3
SCRYPT_R = 8
SCRYPT_P = 1
LOG_N_RANGE = range(10, 21)
ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'  # Crockford's base32
DIGITS = {char: value for value, char in enumerate(ALPHABET)}
LOOKALIKES = {'O': '0', 'I': '1', 'L': '1'}
GROUP = 4
LINE_GROUPS = 4

# Protection levels offered when encrypting: (log2 of scrypt N, name, cost).
LEVELS = (
    (18, 'Standard', '256 MiB of memory, about 1 s'),
    (19, 'Strong', '512 MiB of memory, about 2 s'),
    (20, 'Paranoid', '1 GiB of memory, about 4 s'),
)
DEFAULT_LEVEL = 1

# The BIP39 English word list, exactly as published with BIP39.
WORDLIST_SHA256 = (
    '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda')
WORDS = '''
abandon ability able about above absent absorb abstract absurd abuse access
accident account accuse achieve acid acoustic acquire across act action actor
actress actual adapt add addict address adjust admit adult advance advice
aerobic affair afford afraid again age agent agree ahead aim air airport aisle
alarm album alcohol alert alien all alley allow almost alone alpha already also
alter always amateur amazing among amount amused analyst anchor ancient anger
angle angry animal ankle announce annual another answer antenna antique anxiety
any apart apology appear apple approve april arch arctic area arena argue arm
armed armor army around arrange arrest arrive arrow art artefact artist artwork
ask aspect assault asset assist assume asthma athlete atom attack attend
attitude attract auction audit august aunt author auto autumn average avocado
avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag
balance balcony ball bamboo banana banner bar barely bargain barrel base basic
basket battle beach bean beauty because become beef before begin behave behind
believe below belt bench benefit best betray better between beyond bicycle bid
bike bind biology bird birth bitter black blade blame blanket blast bleak bless
blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus
book boost border boring borrow boss bottom bounce box boy bracket brain brand
brass brave bread breeze brick bridge brief bright bring brisk broccoli broken
bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk
bullet bundle bunker burden burger burst bus business busy butter buyer buzz
cabbage cabin cable cactus cage cake call calm camera camp can canal cancel
candy cannon canoe canvas canyon capable capital captain car carbon card cargo
carpet carry cart case cash casino castle casual cat catalog catch category
cattle caught cause caution cave ceiling celery cement census century cereal
certain chair chalk champion change chaos chapter charge chase chat cheap check
cheese chef cherry chest chicken chief child chimney choice choose chronic
chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify
claw clay clean clerk clever click client cliff climb clinic clip clock clog
close cloth cloud clown club clump cluster clutch coach coast coconut code
coffee coil coin collect color column combine come comfort comic common company
concert conduct confirm congress connect consider control convince cook cool
copper copy coral core corn correct cost cotton couch country couple course
cousin cover coyote crack cradle craft cram crane crash crater crawl crazy
cream credit creek crew cricket crime crisp critic crop cross crouch crowd
crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard
curious current curtain curve cushion custom cute cycle dad damage damp dance
danger daring dash daughter dawn day deal debate debris decade december decide
decline decorate decrease deer defense define defy degree delay deliver demand
demise denial dentist deny depart depend deposit depth deputy derive describe
desert design desk despair destroy detail detect develop device devote diagram
dial diamond diary dice diesel diet differ digital dignity dilemma dinner
dinosaur direct dirt disagree discover disease dish dismiss disorder display
distance divert divide divorce dizzy doctor document dog doll dolphin domain
donate donkey donor door dose double dove draft dragon drama drastic draw dream
dress drift drill drink drip drive drop drum dry duck dumb dune during dust
dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo
ecology economy edge edit educate effort egg eight either elbow elder electric
elegant element elephant elevator elite else embark embody embrace emerge
emotion employ empower empty enable enact end endless endorse enemy energy
enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter
entire entry envelope episode equal equip era erase erode erosion error erupt
escape essay essence estate eternal ethics evidence evil evoke evolve exact
example excess exchange excite exclude excuse execute exercise exhaust exhibit
exile exist exit exotic expand expect expire explain expose express extend
extra eye eyebrow fabric face faculty fade faint faith fall false fame family
famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite
feature february federal fee feed feel female fence festival fetch fever few
fiber fiction field figure file film filter final find fine finger finish fire
firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight
flip float flock floor flower fluid flush fly foam focus fog foil fold follow
food foot force forest forget fork fortune forum forward fossil foster found
fox fragile frame frequent fresh friend fringe frog front frost frown frozen
fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap
garage garbage garden garlic garment gas gasp gate gather gauge gaze general
genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl
give glad glance glare glass glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain
grant grape grass gravity great green grid grief grit grocery group grow grunt
guard guess guide guilt guitar gun gym habit hair half hammer hamster hand
happy harbor hard harsh harvest hat have hawk hazard head health heart heavy
hedgehog height hello helmet help hen hero hidden high hill hint hip hire
history hobby hockey hold hole holiday hollow home honey hood hope horn horror
horse hospital host hotel hour hover hub huge human humble humor hundred hungry
hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill
illegal illness image imitate immense immune impact impose improve impulse inch
include income increase index indicate indoor industry infant inflict inform
inhale inherit initial inject injury inmate inner innocent input inquiry insane
insect inside inspire install intact interest into invest invite involve iron
island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly
jewel job join joke journey joy judge juice jump jungle junior junk just
kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen
kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp
language laptop large later latin laugh laundry lava law lawn lawsuit layer
lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend
length lens leopard lesson letter level liar liberty library license life lift
light like limb limit link lion liquid list little live lizard load loan
lobster local lock logic lonely long loop lottery loud lounge love loyal lucky
luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail
main major make mammal man manage mandate mango mansion manual maple marble
march margin marine market marriage mask mass master match material math matrix
matter maximum maze meadow mean measure meat mechanic medal media melody melt
member memory mention menu mercy merge merit merry mesh message metal method
middle midnight milk million mimic mind minimum minor minute miracle mirror
misery miss mistake mix mixed mixture mobile model modify mom moment monitor
monkey monster month moon moral more morning mosquito mother motion motor
mountain mouse move movie much muffin mule multiply muscle museum mushroom
music must mutual myself mystery myth naive name napkin narrow nasty nation
nature near neck need negative neglect neither nephew nerve nest net network
neutral never news next nice night noble noise nominee noodle normal north nose
notable note nothing notice novel now nuclear number nurse nut oak obey object
oblige obscure observe obtain obvious occur ocean october odor off offer office
often oil okay old olive olympic omit once one onion online only open opera
opinion oppose option orange orbit orchard order ordinary organ orient original
orphan ostrich other outdoor outer output outside oval oven over own owner
oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther
paper parade parent park parrot party pass patch path patient patrol pattern
pause pave payment peace peanut pear peasant pelican pen penalty pencil people
pepper perfect permit person pet phone photo phrase physical piano picnic
picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place
planet plastic plate play please pledge pluck plug plunge poem poet point polar
pole police pond pony pool popular portion position possible post potato
pottery poverty powder power practice praise predict prefer prepare present
pretty prevent price pride primary print priority prison private prize problem
process produce profit program project promote proof property prosper protect
proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase
purity purpose purse push put puzzle pyramid quality quantum quarter question
quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise
rally ramp ranch random range rapid rare rate rather raven raw razor ready real
reason rebel rebuild recall receive recipe record recycle reduce reflect reform
refuse region regret regular reject relax release relief rely remain remember
remind remove render renew rent reopen repair repeat replace report require
rescue resemble resist resource response result retire retreat return reunion
reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid
ring riot ripple risk ritual rival river road roast robot robust rocket romance
roof rookie room rose rotate rough round route royal rubber rude rug rule run
runway rural sad saddle sadness safe sail salad salmon salon salt salute same
sample sand satisfy satoshi sauce sausage save say scale scan scare scatter
scene scheme school science scissors scorpion scout scrap screen script scrub
sea search season seat second secret section security seed seek segment select
sell seminar senior sense sentence series service session settle setup seven
shadow shaft shallow share shed shell sheriff shield shift shine ship shiver
shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling
sick side siege sight sign silent silk silly silver similar simple since sing
siren sister situate six size skate sketch ski skill skin skirt skull slab slam
sleep slender slice slide slight slim slogan slot slow slush small smart smile
smoke smooth snack snake snap sniff snow soap soccer social sock soda soft
solar soldier solid solution solve someone song soon sorry sort soul sound soup
source south space spare spatial spawn speak special speed spell spend sphere
spice spider spike spin spirit split spoil sponsor spoon sport spot spray
spread spring spy square squeeze squirrel stable stadium staff stage stairs
stamp stand start state stay steak steel stem step stereo stick still sting
stock stomach stone stool story stove strategy street strike strong struggle
student stuff stumble style subject submit subway success such sudden suffer
sugar suggest suit summer sun sunny sunset super supply supreme sure surface
surge surprise surround survey suspect sustain swallow swamp swap swarm swear
sweet swift swim swing switch sword symbol symptom syrup system table tackle
tag tail talent talk tank tape target task taste tattoo taxi teach team tell
ten tenant tennis tent term test text thank that theme then theory there they
thing this thought three thrive throw thumb thunder ticket tide tiger tilt
timber time tiny tip tired tissue title toast tobacco today toddler toe
together toilet token tomato tomorrow tone tongue tonight tool tooth top topic
topple torch tornado tortoise toss total tourist toward tower town toy track
trade traffic tragic train transfer trap trash travel tray treat tree trend
trial tribe trick trigger trim trip trophy trouble truck true truly trumpet
trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve
twenty twice twin twist two type typical ugly umbrella unable unaware uncle
uncover under undo unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon upper upset urban urge
usage use used useful useless usual utility vacant vacuum vague valid valley
valve van vanish vapor various vast vault vehicle velvet vendor venture venue
verb verify version very vessel veteran viable vibrant vicious victory video
view village vintage violin virtual virus visa visit visual vital vivid vocal
voice void volcano volume vote voyage wage wagon wait walk wall walnut want
warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel
weather web wedding weekend weird welcome west wet whale what wheat wheel when
where whip whisper wide width wife wild will win window wine wing wink winner
winter wire wisdom wise wish witness wolf woman wonder wood wool word work
world worry worth wrap wreck wrestle wrist write wrong yard year yellow you
young youth zebra zero zone zoo
'''.split()
INDEX = {word: index for index, word in enumerate(WORDS)}


class CodeError(Exception):
    """The code is malformed; the message is meant for the user."""


class TypoError(CodeError):
    """The code checksum does not match (a typo somewhere)."""

    def __init__(self, message, fixes):
        super().__init__(message)
        self.fixes = fixes


class DecryptError(Exception):
    """Wrong password or damaged code."""


# BIP39 -------------------------------------------------------------------

def wordlist_sha256():
    """Hash the built-in word list the way the published file is hashed."""
    return hashlib.sha256(('\n'.join(WORDS) + '\n').encode()).hexdigest()


def lookup(prefix):
    """Return the BIP39 words that start with prefix."""
    start = bisect.bisect_left(WORDS, prefix)
    end = bisect.bisect_left(WORDS, prefix + '{', start)  # '{' follows 'z'
    return WORDS[start:end]


def bip39_valid(words):
    """Check that the words form a BIP39 phrase with a valid checksum."""
    count = len(words)
    if count not in WORD_COUNTS or any(w not in INDEX for w in words):
        return False
    bits = 0
    for word in words:
        bits = bits << 11 | INDEX[word]
    check_bits = count // 3
    entropy = (bits >> check_bits).to_bytes(count * 4 // 3, 'big')
    digest = hashlib.sha256(entropy).digest()[0]
    return (digest >> (8 - check_bits)) == (bits & ((1 << check_bits) - 1))


# Encryption --------------------------------------------------------------

def _cipher_len(count):
    return (11 * count + 7) // 8


def _pack(words):
    """Pack word indices, 11 bits each, into bytes padded with zero bits."""
    bits = 0
    for word in words:
        bits = bits << 11 | INDEX[word]
    size = _cipher_len(len(words))
    return (bits << (size * 8 - 11 * len(words))).to_bytes(size, 'big')


def _derive(password, salt, log_n, length):
    secret = unicodedata.normalize('NFKC', password).encode('utf-8')
    return hashlib.scrypt(
        secret, salt=salt, n=1 << log_n, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=2 ** 31 - 1, dklen=length)


def encrypt(words, password, log_n, salt=None):
    """Encrypt a phrase and return the code (without dashes)."""
    plain = _pack(words)
    header = bytes((FORMAT_VERSION, len(words), log_n))
    salt = salt or secrets.token_bytes(SALT_LEN)
    key = _derive(password, salt, log_n, len(plain) + 32)
    body = header + salt + bytes(a ^ b for a, b in zip(plain, key))
    tag = hmac.new(key[len(plain):], body, 'sha256').digest()[:TAG_LEN]
    return to_code(body + tag)


def decrypt(code, password):
    """Decrypt a code and return the words."""
    payload = from_code(code)
    count, log_n = payload[1], payload[2]
    size = _cipher_len(count)
    body, tag = payload[:-TAG_LEN], payload[-TAG_LEN:]
    salt = body[HEADER_LEN:HEADER_LEN + SALT_LEN]
    key = _derive(password, salt, log_n, size + 32)
    mac = hmac.new(key[size:], body, 'sha256').digest()[:TAG_LEN]
    if not hmac.compare_digest(mac, tag):
        raise DecryptError('Wrong password or damaged code.')
    cipher = body[HEADER_LEN + SALT_LEN:]
    bits = int.from_bytes(bytes(a ^ b for a, b in zip(cipher, key)), 'big')
    bits >>= size * 8 - 11 * count
    return [WORDS[(bits >> 11 * (count - 1 - i)) & 0x7FF]
            for i in range(count)]


# Code text ---------------------------------------------------------------

def _data_len(count):
    return HEADER_LEN + SALT_LEN + _cipher_len(count) + TAG_LEN + CHECK_LEN


def code_len(count):
    """Number of code characters for a phrase of count words."""
    chars = (_data_len(count) * 8 + 4) // 5
    return (chars + GROUP - 1) // GROUP * GROUP


CODE_LENGTHS = {code_len(count): count for count in WORD_COUNTS}


def to_code(payload):
    """Append the checksum and write the payload in base32."""
    data = payload + hashlib.sha256(payload).digest()[:CHECK_LEN]
    length = code_len(payload[1])
    value = int.from_bytes(data, 'big') << (length * 5 - len(data) * 8)
    return ''.join(ALPHABET[(value >> 5 * (length - 1 - i)) & 31]
                   for i in range(length))


def clean_char(char):
    """Map a typed character to a code character.

    Returns '' for separators and None for characters codes never use.
    """
    char = char.upper()
    char = LOOKALIKES.get(char, char)
    if char in DIGITS:
        return char
    if char in ' -':
        return ''
    return None


def clean_code(text):
    """Uppercase, map look-alike letters, drop spaces and dashes."""
    chars = []
    for char in text:
        clean = clean_char(char)
        if clean is None:
            raise CodeError(f'"{char}" is never used in codes.')
        chars.append(clean)
    return ''.join(chars)


def expected_len(code):
    """Return the full code length its first group implies, or None."""
    if len(code) < 5:
        return None
    value = 0
    for char in code[:5]:
        value = value * 32 + DIGITS[char]
    header = value >> 1  # the first 3 bytes are 24 of these 25 bits
    version, count, log_n = header >> 16, (header >> 8) & 255, header & 255
    if FORMAT_VERSION < version < 8:
        raise CodeError('This code needs a newer version of cryptopass.')
    if (version != FORMAT_VERSION or count not in WORD_COUNTS
            or log_n not in LOG_N_RANGE):
        raise CodeError('Not a cryptopass code: check the first group.')
    return code_len(count)


def _unpack(code):
    """Decode a clean code; return the payload or None if it is invalid."""
    count = CODE_LENGTHS.get(len(code))
    if count is None:
        return None
    value = 0
    for char in code:
        value = value * 32 + DIGITS[char]
    size = _data_len(count)
    padding = len(code) * 5 - size * 8
    if value & ((1 << padding) - 1):
        return None
    data = (value >> padding).to_bytes(size, 'big')
    payload, check = data[:-CHECK_LEN], data[-CHECK_LEN:]
    if hashlib.sha256(payload).digest()[:CHECK_LEN] != check:
        return None
    if (payload[0] != FORMAT_VERSION or payload[1] != count
            or payload[2] not in LOG_N_RANGE):
        return None
    return payload


def find_typos(code):
    """Find single-character fixes that make the checksum valid.

    Tries every substitution of one character and every swap of two
    neighbours. Returns a list of (position, replacement) pairs.
    """
    fixes = []
    for pos, old in enumerate(code):
        for new in ALPHABET:
            if new != old and _unpack(code[:pos] + new + code[pos + 1:]):
                fixes.append((pos, new))
    for pos in range(len(code) - 1):
        pair = code[pos + 1] + code[pos]
        if pair[0] != pair[1] and _unpack(
                code[:pos] + pair + code[pos + 2:]):
            fixes.append((pos, pair))
    return fixes


def from_code(text):
    """Validate a code and return its payload bytes."""
    code = clean_code(text)
    payload = _unpack(code)
    if payload:
        return payload
    try:
        total = expected_len(code)
    except CodeError:
        if len(code) not in CODE_LENGTHS:
            raise
        total = len(code)  # the typo may be in the first group
    if total is None:
        raise CodeError('The code is too short.')
    if len(code) != total:
        raise CodeError(f'The code must have {total} characters, '
                        f'not {len(code)}. Is a group missing?')
    raise TypoError('The code has a typo.', find_typos(code))


def code_place(pos):
    """Describe where a character is, as a person reads the code."""
    group = pos // GROUP
    return (f'line {group // LINE_GROUPS + 1}, '
            f'group {group % LINE_GROUPS + 1}')


# QR code (alphanumeric mode, error correction level M) -------------------

QR_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
# version: (EC codewords per block, ((block count, data codewords), ...))
QR_BLOCKS = {
    1: (10, ((1, 16),)),
    2: (16, ((1, 28),)),
    3: (26, ((1, 44),)),
    4: (18, ((2, 32),)),
    5: (24, ((2, 43),)),
    6: (16, ((4, 27),)),
    7: (18, ((4, 31),)),
    8: (22, ((2, 38), (2, 39))),
    9: (22, ((3, 36), (2, 37))),
    10: (26, ((4, 43), (1, 44))),
}
QR_ALIGN = {
    1: (), 2: (6, 18), 3: (6, 22), 4: (6, 26), 5: (6, 30), 6: (6, 34),
    7: (6, 22, 38), 8: (6, 24, 42), 9: (6, 26, 46), 10: (6, 28, 50),
}
QR_MASKS = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: r * c % 2 + r * c % 3 == 0,
    lambda r, c: (r * c % 2 + r * c % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + r * c % 3) % 2 == 0,
)


def _gf_tables():
    exp, log = [0] * 512, [0] * 256
    value = 1
    for power in range(255):
        exp[power], log[value] = value, power
        value <<= 1
        if value & 0x100:
            value ^= 0x11D
    for power in range(255, 512):
        exp[power] = exp[power - 255]
    return exp, log


GF_EXP, GF_LOG = _gf_tables()


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def _qr_ecc(data, degree):
    """Reed-Solomon error correction codewords for one block."""
    generator = [1]
    for power in range(degree):
        generator = [a ^ _gf_mul(b, GF_EXP[power])
                     for a, b in zip(generator + [0], [0] + generator)]
    remainder = [0] * degree
    for byte in data:
        factor = byte ^ remainder.pop(0)
        remainder.append(0)
        for i, coef in enumerate(generator[1:]):
            remainder[i] ^= _gf_mul(coef, factor)
    return remainder


def _qr_capacity(version):
    return sum(count * size for count, size in QR_BLOCKS[version][1])


def _qr_bits(text, version):
    """Data bits of a single alphanumeric segment."""
    bits = ['0010', format(len(text), '09b' if version < 10 else '011b')]
    for i in range(0, len(text) - 1, 2):
        pair = 45 * QR_CHARS.index(text[i]) + QR_CHARS.index(text[i + 1])
        bits.append(format(pair, '011b'))
    if len(text) % 2:
        bits.append(format(QR_CHARS.index(text[-1]), '06b'))
    return ''.join(bits)


def _qr_codewords(text, version):
    """Data plus error correction codewords, interleaved."""
    capacity = _qr_capacity(version) * 8
    bits = _qr_bits(text, version)
    bits += '0' * min(4, capacity - len(bits))
    bits += '0' * (-len(bits) % 8)
    data = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]
    for i in range(capacity // 8 - len(data)):
        data.append((0xEC, 0x11)[i % 2])
    degree, groups = QR_BLOCKS[version]
    blocks = []
    for count, size in groups:
        for _ in range(count):
            blocks.append(data[:size])
            data = data[size:]
    eccs = [_qr_ecc(block, degree) for block in blocks]
    out = []
    for i in range(max(len(block) for block in blocks)):
        out += [block[i] for block in blocks if i < len(block)]
    for i in range(degree):
        out += [ecc[i] for ecc in eccs]
    return out


def _qr_format_bits(put, size, mask):
    data = mask  # level M is 0b00
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    bits = (data << 10 | rem) ^ 0x5412
    for i in range(15):
        dark = bool(bits >> i & 1)
        if i < 6:
            put(i, 8, dark)
        elif i < 8:
            put(i + 1, 8, dark)
        elif i == 8:
            put(8, 7, dark)
        else:
            put(8, 14 - i, dark)
        if i < 8:
            put(8, size - 1 - i, dark)
        else:
            put(size - 15 + i, 8, dark)
    put(size - 8, 8, True)


def _qr_penalty(grid):
    score = 0
    for line in grid + [list(column) for column in zip(*grid)]:
        run = 1
        for a, b in zip(line, line[1:] + [None]):
            if a == b:
                run += 1
                continue
            if run >= 5:
                score += run - 2
            run = 1
        text = ''.join('1' if dark else '0' for dark in line)
        for pattern in ('10111010000', '00001011101'):
            score += 40 * sum(text.startswith(pattern, i)
                              for i in range(len(text)))
    size = len(grid)
    for r in range(size - 1):
        for c in range(size - 1):
            if (grid[r][c] == grid[r][c + 1] == grid[r + 1][c]
                    == grid[r + 1][c + 1]):
                score += 3
    dark = sum(map(sum, grid))
    total = size * size
    return score + 10 * (abs(dark * 20 - total * 10) // total)


def qr_matrix(text, mask=None):
    """Encode text (QR alphanumeric characters) as a QR code, level M.

    Returns a list of rows of booleans, True for dark modules.
    """
    version = next((v for v in QR_BLOCKS
                    if len(_qr_bits(text, v)) <= _qr_capacity(v) * 8), None)
    if version is None:
        raise ValueError('Text is too long for a QR code.')
    size = 17 + 4 * version
    grid = [[False] * size for _ in range(size)]
    function = [[False] * size for _ in range(size)]

    def put(r, c, dark):
        grid[r][c] = dark
        function[r][c] = True

    for i in range(size):
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    for top, left in ((0, 0), (0, size - 7), (size - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                if 0 <= top + dr < size and 0 <= left + dc < size:
                    ring = max(abs(dr - 3), abs(dc - 3))
                    put(top + dr, left + dc, ring not in (2, 4))
    centers = QR_ALIGN[version]
    for r in centers:
        for c in centers:
            corner = (r == centers[0] or c == centers[0]) and (
                r == c or centers[-1] in (r, c))
            if corner:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    put(r + dr, c + dc, max(abs(dr), abs(dc)) != 1)
    if version >= 7:
        rem = version
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = version << 12 | rem
        for i in range(18):
            dark = bool(bits >> i & 1)
            put(size - 11 + i % 3, i // 3, dark)
            put(i // 3, size - 11 + i % 3, dark)
    _qr_format_bits(put, size, 0)  # reserve the format areas

    codewords = _qr_codewords(text, version)
    bits = ''.join(format(byte, '08b') for byte in codewords)
    i = 0
    for right in range(size - 1, 0, -2):
        if right <= 6:
            right -= 1
        upward = (right + 1) & 2 == 0
        for vert in range(size):
            r = size - 1 - vert if upward else vert
            for c in (right, right - 1):
                if not function[r][c] and i < len(bits):
                    grid[r][c] = bits[i] == '1'
                    i += 1

    def masked(number):
        result = [row[:] for row in grid]
        check = QR_MASKS[number]
        for r in range(size):
            for c in range(size):
                if not function[r][c] and check(r, c):
                    result[r][c] = not result[r][c]

        def put_format(r, c, dark):
            result[r][c] = dark

        _qr_format_bits(put_format, size, number)
        return result

    if mask is not None:
        return masked(mask)
    return min((masked(n) for n in range(8)), key=_qr_penalty)


# Terminal user interface -------------------------------------------------

def strength(password):
    """Very rough password entropy estimate in bits."""
    pool = 0
    if any('a' <= c <= 'z' for c in password):
        pool += 26
    if any('A' <= c <= 'Z' for c in password):
        pool += 26
    if any('0' <= c <= '9' for c in password):
        pool += 10
    if any(c.isascii() and not c.isalnum() for c in password):
        pool += 33
    if any(not c.isascii() for c in password):
        pool += 66
    length = min(len(password), 2 * len(set(password)))
    bits = int(length * math.log2(pool)) if pool else 0
    words = password.split()
    if len(words) > 1:  # a passphrase: count about 13 bits per word
        bits = min(bits, 13 * len(words))
    return bits


def strength_label(bits):
    if bits < 45:
        return 'weak', 'err'
    if bits < 60:
        return 'fair', 'warn'
    if bits < 80:
        return 'good', 'ok'
    return 'strong', 'ok'


class UI:
    """Drawing helpers and key names on top of a curses window."""

    MIN_WIDTH = 72
    MIN_HEIGHT = 22

    def __init__(self, scr):
        self.scr = scr
        self.styles = {
            'bar': curses.A_REVERSE,
            'bold': curses.A_BOLD,
            'dim': curses.A_DIM,
            'cur': curses.A_REVERSE,
            'sel': curses.A_REVERSE | curses.A_BOLD,
        }
        self.qr_colors = False
        self.keys = {
            curses.KEY_UP: 'up', curses.KEY_DOWN: 'down',
            curses.KEY_LEFT: 'left', curses.KEY_RIGHT: 'right',
            curses.KEY_HOME: 'home', curses.KEY_END: 'end',
            curses.KEY_BACKSPACE: 'backspace', curses.KEY_DC: 'delete',
            curses.KEY_ENTER: 'enter', curses.KEY_BTAB: 'btab',
            curses.KEY_RESIZE: 'resize', curses.KEY_F2: 'f2',
            '\n': 'enter', '\r': 'enter', '\t': 'tab', '\x1b': 'esc',
            '\x7f': 'backspace', '\x08': 'backspace',
        }
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if curses.has_colors():
            try:
                curses.use_default_colors()
                background = -1
            except curses.error:
                background = curses.COLOR_BLACK
            colors = (
                ('title', curses.COLOR_CYAN),
                ('ok', curses.COLOR_GREEN),
                ('warn', curses.COLOR_YELLOW),
                ('err', curses.COLOR_RED),
            )
            for number, (name, color) in enumerate(colors, 1):
                curses.init_pair(number, color, background)
                self.styles[name] = curses.color_pair(number) | curses.A_BOLD
            curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_WHITE)
            self.styles['qr'] = curses.color_pair(5)
            self.qr_colors = True
        for name in ('title', 'ok', 'warn', 'err', 'qr'):
            self.styles.setdefault(name, curses.A_BOLD)

    @property
    def height(self):
        return self.scr.getmaxyx()[0]

    @property
    def width(self):
        return self.scr.getmaxyx()[1]

    def put(self, y, x, text, style=None):
        height, width = self.scr.getmaxyx()
        if not 0 <= y < height or x >= width:
            return
        text = text[:width - x - (y == height - 1)]
        try:
            self.scr.addstr(y, x, text, self.styles.get(style, 0))
        except curses.error:
            pass

    def lines(self, y, lines, style=None, x=4):
        """Draw lines of text; return the row after the last one."""
        for line in lines:
            self.put(y, x, line, style)
            y += 1
        return y

    def frame(self, title, hints, need=None):
        """Clear the screen, draw the bars; False if it is too small."""
        self.scr.erase()
        height, width = self.scr.getmaxyx()
        need_width, need_height = need or (self.MIN_WIDTH, self.MIN_HEIGHT)
        if width < need_width or height < need_height:
            self.put(0, 0, 'Please make the terminal at least '
                     f'{need_width}x{need_height}.', 'warn')
            return False
        self.put(0, 0, f' cryptopass · {title}'.ljust(width), 'bar')
        self.put(height - 1, 0, f' {hints}'.ljust(width), 'bar')
        return True

    def key(self):
        """Wait for a key; return its name or the typed character."""
        self.scr.refresh()
        while True:
            try:
                key = self.scr.get_wch()
            except curses.error:
                continue
            name = self.keys.get(key)
            if name is None and isinstance(key, str) and key.isprintable():
                name = key
            if name:
                return name

    def busy(self, lines):
        self.frame('working', 'Please wait…')
        self.lines(3, lines)
        self.scr.refresh()


def choose(ui, title, intro, items, index=0, hotkeys=''):
    """Let the user pick one of the items; return its index or None."""
    width = max(len(item) for item in items) + 4
    while True:
        if ui.frame(title, '↑↓ choose · Enter select · Esc back'):
            y = ui.lines(2, intro) + 1
            for i, item in enumerate(items):
                if i == index:
                    ui.put(y + i, 4, f'▸ {item}'.ljust(width), 'sel')
                else:
                    ui.put(y + i, 4, f'  {item}')
        key = ui.key()
        if key == 'up':
            index = (index - 1) % len(items)
        elif key == 'down':
            index = (index + 1) % len(items)
        elif key == 'enter':
            return index
        elif key == 'esc':
            return None
        elif len(key) == 1 and key.lower() in hotkeys:
            return hotkeys.index(key.lower())


def grid_columns(count):
    return 4 if count % 4 == 0 else 3


def draw_words(ui, y, words, hidden):
    """Draw the words in a numbered grid; return the row after it."""
    columns = grid_columns(len(words))
    for i, word in enumerate(words):
        row, column = divmod(i, columns)
        x = 4 + column * 17
        ui.put(y + row, x, f'{i + 1:>2}.', 'dim')
        ui.put(y + row, x + 4, '••••••' if hidden else word,
               'dim' if hidden else 'bold')
    return y + (len(words) + columns - 1) // columns


def enter_words(ui, cells):
    """Edit the seed words in place; return True once all are valid."""
    count = len(cells)
    columns = grid_columns(count)
    current = next((i for i, w in enumerate(cells) if w not in INDEX), 0)
    choice, picked, hidden, note = 0, False, False, None
    hints = 'Enter take word · ↑↓ choose · ←→ move · F2 hide · Esc back'
    while True:
        text = cells[current]
        matches = lookup(text) if text else []
        options = matches[:5]
        if ui.frame(f'Encrypt · {count} words', hints):
            ui.lines(2, [
                'Type the words of your seed phrase, or paste the whole '
                'phrase.',
                'Only words from the BIP39 list can be entered.'])
            for i, word in enumerate(cells):
                row, column = divmod(i, columns)
                y, x = 5 + row, 4 + column * 17
                ui.put(y, x, f'{i + 1:>2}.', 'dim')
                x += 4
                if i == current:
                    ghost = options[choice][len(text):] if options else ''
                    ui.put(y, x, text, 'sel')
                    if ghost:
                        ui.put(y, x + len(text), ghost, 'dim')
                    else:
                        ui.put(y, x + len(text), ' ', 'cur')
                elif not word:
                    ui.put(y, x, '________', 'dim')
                elif hidden:
                    ui.put(y, x, '••••••', 'dim')
                else:
                    ui.put(y, x, word, None if word in INDEX else 'err')
            y = 6 + (count - 1) // columns + 1
            for j, option in enumerate(options):
                if j == choice:
                    ui.put(y + j, 6, f'▸ {option}'.ljust(12), 'sel')
                else:
                    ui.put(y + j, 6, f'  {option}')
            if len(matches) > len(options):
                ui.put(y + len(options), 8,
                       f'… and {len(matches) - len(options)} more', 'dim')
            if note:
                ui.put(ui.height - 2, 4, *note)
        key = ui.key()
        note = None
        accept = None
        if key == 'esc':
            return False
        elif key == 'f2':
            hidden = not hidden
        elif key in ('up', 'down') and options:
            step = 1 if key == 'down' else -1
            choice = (choice + step) % len(options)
            picked = True
        elif key in ('enter', 'tab') and options:
            accept = options[choice]
        elif key == ' ' and text:
            # Space separates typed or pasted words, so it only accepts a
            # word that is typed in full or is the only match.
            if text in INDEX and not picked:
                accept = text
            elif len(matches) == 1 or picked:
                accept = options[choice]
            else:
                note = (f'{len(matches)} words start with "{text}": keep '
                        'typing or press Enter.', 'warn')
        elif key == 'enter':
            missing = [i for i, w in enumerate(cells) if w not in INDEX]
            if not missing:
                return True
            current = missing[0]
            note = ('Some words are missing or incomplete.', 'warn')
        elif key == 'backspace':
            if text:
                cells[current] = text[:-1]
            elif current > 0:
                current -= 1
        elif key == 'delete':
            cells[current] = ''
        elif key in ('left', 'right', 'btab'):
            if text not in INDEX and len(matches) == 1:
                cells[current] = matches[0]
            step = 1 if key == 'right' else -1
            current = min(max(current + step, 0), count - 1)
        elif len(key) == 1 and key.isalpha():
            letter = key.lower()
            if 'a' <= letter <= 'z' and lookup(text + letter):
                cells[current] = text + letter
            else:
                note = (f'No BIP39 word starts with "{text + letter}".',
                        'err')
        # Digits and punctuation are ignored, so numbered lists paste well.
        if key not in ('up', 'down', 'f2', 'resize'):
            choice, picked = 0, False
        if accept:
            cells[current] = accept
            if key == 'enter' and all(w in INDEX for w in cells):
                return True
            current = min(current + 1, count - 1)


def password_screen(ui, title, confirm, note=None):
    """Ask for a password; return (password, level index) or None.

    With confirm the password is typed twice and a protection level is
    chosen, which is what encryption needs.
    """
    fields = [[], []] if confirm else [[]]
    stops = 3 if confirm else 1
    focus, level, shown, warned = 0, DEFAULT_LEVEL, False, False
    hints = 'Enter continue · F2 show password · Esc back'
    if confirm:
        hints = 'Enter continue · Tab next · ←→ level · F2 show · Esc back'
    while True:
        password = ''.join(fields[0])
        if ui.frame(title, hints):
            if confirm:
                intro = [
                    'Choose a password. Nobody can recover it: without it',
                    'the code is useless. Several random words make a good',
                    'password; any characters and any length are fine.']
            else:
                intro = ['Enter the password that was used for this code.']
            y = ui.lines(2, intro) + 1
            for i, chars in enumerate(fields):
                ui.put(y, 4, ('Password', 'Repeat')[i],
                       'bold' if focus == i else None)
                text = ''.join(chars) if shown else '•' * len(chars)
                room = ui.width - 22
                if len(text) > room:
                    text = '…' + text[-room + 1:]
                ui.put(y, 16, text)
                if focus == i:
                    ui.put(y, 16 + len(text), ' ', 'cur')
                if i == 1 and chars:
                    same = chars == fields[0]
                    ui.put(y, 18 + len(text),
                           '✓ same' if same else '✗ different',
                           'ok' if same else 'err')
                y += 1
                if i == 0 and confirm:
                    if chars:
                        bits = strength(password)
                        label, style = strength_label(bits)
                        ui.put(y, 16, f'strength: {label} (about {bits} '
                               'bits, a rough estimate)', style)
                    y += 1
            if confirm:
                name, cost = LEVELS[level][1:]
                y += 1
                ui.put(y, 4, 'Protection', 'bold' if focus == 2 else None)
                ui.put(y, 16, f'◂ {name}: {cost} ▸',
                       'sel' if focus == 2 else None)
                ui.put(y + 1, 16, 'Higher levels make guessing the '
                       'password slower.', 'dim')
            if note:
                ui.put(ui.height - 3, 4, *note)
        key = ui.key()
        if key == 'resize':
            continue
        note = None
        if key == 'esc':
            return None
        elif key == 'f2':
            shown = not shown
        elif key in ('tab', 'down'):
            focus = (focus + 1) % stops
        elif key in ('btab', 'up'):
            focus = (focus - 1) % stops
        elif key in ('left', 'right') and focus == 2:
            step = 1 if key == 'right' else -1
            level = (level + step) % len(LEVELS)
        elif key == 'backspace' and focus < len(fields):
            if fields[focus]:
                fields[focus].pop()
            warned = False
        elif key == 'enter':
            if confirm and focus == 0 and password:
                focus = 1
            elif not password:
                focus, note = 0, ('Type a password first.', 'warn')
            elif confirm and fields[1] != fields[0]:
                focus, note = 1, ("The two passwords don't match.", 'err')
            elif confirm and strength(password) < 45 and not warned:
                warned = True
                note = ('This password is weak. Press Enter again to use '
                        'it anyway.', 'warn')
            else:
                return password, level
        elif len(key) == 1 and focus < len(fields):
            fields[focus].append(key)
            warned = False


def draw_code(ui, y, code, total=None, cursor=None, marks=(), style='bold'):
    """Draw a code as numbered lines of groups; return the next row."""
    span = GROUP * LINE_GROUPS
    length = max(total or 0, len(code), 1)
    if cursor is not None:
        length = max(length, cursor + 1)
    rows = (length + span - 1) // span
    for row in range(rows):
        ui.put(y + row, 4, f'{row + 1:>2}', 'dim')
    for pos in range(length):
        row, offset = divmod(pos, span)
        x = 9 + offset + offset // GROUP
        if pos == cursor:
            char_style = 'cur'
        elif pos in marks:
            char_style = 'err'
        elif pos >= len(code):
            char_style = 'dim'
        else:
            char_style = style
        ui.put(y + row, x, code[pos] if pos < len(code) else '_', char_style)
        if offset % GROUP == GROUP - 1 and offset < span - 1 and (
                pos < length - 1):
            ui.put(y + row, x + 1, '-', 'dim')
    return y + rows


def code_screen(ui, code='', expected=None):
    """Type a code. Returns it once valid (or equal to expected), or None."""
    chars, cursor = list(code), len(code)
    marks, note, fix = set(), None, None
    longest = max(CODE_LENGTHS)
    if expected is None:
        title = 'Decrypt · the code'
        intro = ['Type the code from your paper. Dashes and spaces are '
                 'optional,', 'case does not matter.']
    else:
        title = 'Encrypt · verify your copy'
        intro = ['Type the code back from your paper to make sure it was',
                 'written down correctly.']
    hints = 'Enter continue · ←→ move · Backspace/Del erase · Esc back'
    while True:
        text = ''.join(chars)
        problem = None
        if expected is not None:
            total = len(expected)
        else:
            try:
                total = expected_len(text)
            except CodeError as error:
                total, problem = None, str(error)
        if ui.frame(title, hints):
            y = ui.lines(2, intro) + 1
            y = draw_code(ui, y, text, total, cursor, marks) + 1
            if total:
                ui.put(y, 4, f'{len(text)} of {total} characters', 'dim')
            else:
                ui.put(y, 4, f'{len(text)} characters', 'dim')
            if problem:
                ui.put(y + 1, 4, problem, 'err')
            if note:
                ui.lines(y + 2, note[0], note[1])
        key = ui.key()
        if key == 'resize':
            continue
        edited = True
        if key == 'esc':
            return None
        elif key == 'left':
            cursor, edited = max(0, cursor - 1), False
        elif key == 'right':
            cursor, edited = min(len(chars), cursor + 1), False
        elif key == 'home':
            cursor, edited = 0, False
        elif key == 'end':
            cursor, edited = len(chars), False
        elif key == 'backspace':
            if cursor:
                cursor -= 1
                chars.pop(cursor)
        elif key == 'delete':
            if cursor < len(chars):
                chars.pop(cursor)
        elif key == 'tab' and fix:
            pos, replacement = fix
            chars[pos:pos + len(replacement)] = replacement
            cursor = len(chars)
            marks, fix = set(), None
            note = (['Fixed. Press Enter to continue.'], 'ok')
            continue
        elif key == 'enter':
            edited = False
            marks, fix = set(), None
            if expected is not None:
                if text == expected:
                    return text
                marks = {i for i in range(max(len(text), len(expected)))
                         if text[i:i + 1] != expected[i:i + 1]}
                plural = '' if len(marks) == 1 else 's'
                note = ([f'Does not match: check the {len(marks)} '
                         f'highlighted character{plural}.'], 'err')
                continue
            try:
                from_code(text)
                return text
            except TypoError as error:
                if len(error.fixes) == 1:
                    fix = error.fixes[0]
                    pos, replacement = fix
                    old = text[pos:pos + len(replacement)]
                    marks = set(range(pos, pos + len(replacement)))
                    note = ([f'Probably a typo in {code_place(pos)}: '
                             f'"{old}" should be "{replacement}".',
                             'Check it against your paper; Tab applies '
                             'this fix.'], 'warn')
                else:
                    note = (['The checksum does not match, so there is a '
                             'typo.', 'Compare the code with your paper '
                             'carefully.'], 'err')
            except CodeError as error:
                note = ([str(error)], 'err')
            continue
        elif len(key) == 1:
            char = clean_char(key)
            if char is None:
                note = ([f'"{key}" is never used in codes.'], 'err')
                continue
            if not char:
                continue
            if len(chars) >= (total or longest):
                note = (['The code is already complete.'], 'warn')
                continue
            chars.insert(cursor, char)
            cursor += 1
        if edited:
            marks, note, fix = set(), None, None


def result_screen(ui, code):
    """Show the code with options to verify the copy or show a QR code."""
    verified, leaving = False, False
    note = ('✓ Self-check passed: the code decrypts back to your phrase.',
            'ok')
    while True:
        if ui.frame('Encrypt · your code',
                    'V verify your copy · Q QR code · Enter done'):
            y = ui.lines(2, [f'Write this code down exactly '
                             f'({len(code)} characters):']) + 1
            y = draw_code(ui, y, code, style='title') + 1
            y = ui.lines(y, [
                'The code has no letters O, I or L: typing them counts as '
                '0 or 1.',
                f'Write "cryptopass" and {REPO_URL} next to it.',
                'Keep the password somewhere else. Nobody can recover it.'])
            ui.put(y + 1, 4, *note)
        key = ui.key()
        if key == 'resize':
            continue
        if key in ('v', 'V'):
            leaving = False
            if code_screen(ui, expected=code) is not None:
                verified = True
                note = ('✓ Your written copy matches the code.', 'ok')
        elif key in ('q', 'Q'):
            leaving = False
            qr_screen(ui, code)
        elif key in ('enter', 'esc'):
            if verified or leaving:
                return
            leaving = True
            note = ('You have not verified your copy (V). Press Enter '
                    'again to leave.', 'warn')


def qr_screen(ui, code):
    matrix = qr_matrix(code)
    quiet = 2
    size = len(matrix) + 2 * quiet

    def dark(r, c):
        r, c = r - quiet, c - quiet
        return 0 <= r < len(matrix) and 0 <= c < len(matrix) and matrix[r][c]

    # With colours the code is black on white; without them light modules
    # are drawn with the (usually light) text colour on a dark background.
    blocks = ' ▄▀█' if ui.qr_colors else '█▀▄ '
    lines = [''.join(blocks[dark(r, c) * 2 + dark(r + 1, c)]
                     for c in range(size)) for r in range(0, size, 2)]
    while True:
        if ui.frame('Encrypt · QR code', 'Any key: back',
                    (max(size + 2, 30), len(lines) + 2)):
            height, width = ui.scr.getmaxyx()
            top = 1 + (height - 2 - len(lines)) // 2
            ui.lines(top, lines, 'qr', (width - size) // 2)
        if ui.key() != 'resize':
            return


def words_screen(ui, words):
    shown = False
    valid = bip39_valid(words)
    while True:
        if ui.frame('Decrypt · your seed phrase', 'Space show/hide · '
                    'Enter done'):
            y = ui.lines(2, ['The code was decrypted. Press Space to show '
                             'the words.']) + 1
            y = draw_words(ui, y, words, not shown) + 1
            if valid:
                ui.put(y, 4, '✓ The BIP39 checksum is valid.', 'ok')
            else:
                ui.put(y, 4, '! Not a BIP39 phrase; it was encrypted as is.',
                       'warn')
        key = ui.key()
        if key == ' ':
            shown = not shown
        elif key in ('enter', 'esc'):
            return


def message_screen(ui, title, lines, style=None):
    while True:
        if ui.frame(title, 'Any key: back'):
            ui.lines(2, lines, style)
        if ui.key() != 'resize':
            return


def run_scrypt(ui, lines, action):
    """Run a slow scrypt-based action; return its result or an error."""
    ui.busy(lines)
    try:
        return action(), None
    except (MemoryError, ValueError):
        return None, 'Not enough memory for this protection level.'
    finally:
        curses.flushinp()


def encrypt_flow(ui):
    count_index, cells, step = 0, None, 'count'
    while True:
        if step == 'count':
            index = choose(
                ui, 'Encrypt · phrase length',
                ['How many words are in your seed phrase?'],
                [f'{count} words' for count in WORD_COUNTS], count_index)
            if index is None:
                return
            count_index = index
            count = WORD_COUNTS[index]
            if cells is None or len(cells) != count:
                cells = [''] * count
            step = 'words'
        elif step == 'words':
            if not enter_words(ui, cells):
                step = 'count'
            elif bip39_valid(cells) or choose(
                    ui, 'Encrypt · checksum', [
                        'These words do not pass the BIP39 checksum, so '
                        'most likely',
                        'one of them is wrong. Please check them again.',
                        '',
                        'Some wallets (Electrum, for example) use phrases '
                        'without a',
                        'BIP39 checksum. Such a phrase can be encrypted '
                        'as is.'],
                    ['Edit the words', 'Encrypt it anyway']) == 1:
                step = 'password'
        elif step == 'password':
            note = None
            while True:
                answer = password_screen(ui, 'Encrypt · password', True, note)
                if answer is None:
                    step = 'words'
                    break
                password, level = answer
                log_n, name, cost = LEVELS[level]

                def action():
                    code = encrypt(cells, password, log_n)
                    return code, decrypt(code, password) == cells

                result, error = run_scrypt(ui, [
                    f'Encrypting ({name}: {cost})…',
                    'Then decrypting once more to double-check the result.'],
                    action)
                if error:
                    note = (error + ' Choose a lower one.', 'err')
                    continue
                code, ok = result
                if not ok:
                    message_screen(ui, 'Error', [
                        'Self-check failed: the code does not decrypt back.',
                        'This should never happen. Nothing was produced.'],
                        'err')
                    return
                result_screen(ui, code)
                return


def decrypt_flow(ui):
    code = ''
    while True:
        code = code_screen(ui, code)
        if code is None:
            return
        note = None
        while True:
            answer = password_screen(ui, 'Decrypt · password', False, note)
            if answer is None:
                break
            password = answer[0]

            def action():
                try:
                    return decrypt(code, password)
                except DecryptError:
                    return None

            words, error = run_scrypt(ui, ['Decrypting…'], action)
            if error:
                note = (error, 'err')
            elif words is None:
                note = ('Wrong password, or the code is damaged.', 'err')
            else:
                words_screen(ui, words)
                return


HELP = [
    'cryptopass encrypts a BIP39 seed phrase with your password and',
    'gives you a code (letters and digits) to write down. The code and',
    'the password together restore the phrase: here, or with the short',
    'script in the README.',
    '',
    '• Run it offline: disconnect from the internet before typing a real',
    '  seed phrase. Nothing is saved to disk or sent anywhere.',
    '• The code is only as strong as the password. Use several random',
    '  words or a long random password. A forgotten password is final.',
    '• Keep the code and the password in different places.',
    '• Verify your written copy (V on the result screen).',
    f'• Write "cryptopass" and {REPO_URL} next to the code.',
]


def app(scr):
    ui = UI(scr)
    index = 0
    while True:
        index = choose(ui, f'version {APP_VERSION}', [
            'Encrypt a seed phrase with a password and get a code that is',
            'safe to write down. Decrypt the code to get the phrase back.'],
            ['Encrypt a seed phrase      E', 'Decrypt a code             D',
             'Help and safety tips       H', 'Quit                       Q'],
            index or 0, 'edhq')
        if index == 0:
            encrypt_flow(ui)
        elif index == 1:
            decrypt_flow(ui)
        elif index == 2:
            message_screen(ui, 'help', HELP)
        else:
            return


def problem():
    """Explain what stops the app from running here, if anything."""
    if curses is None:
        return ('cryptopass needs the curses module. On Windows run it '
                f'with uv:\n  {RUN_WITH_UV}\nor inside WSL.')
    if not hasattr(hashlib, 'scrypt'):
        return ('This Python has no hashlib.scrypt (it was built without '
                'OpenSSL 1.1+,\nlike the macOS system Python). Use Python '
                f'from python.org or Homebrew,\nor run:\n  {RUN_WITH_UV}')
    if wordlist_sha256() != WORDLIST_SHA256:
        return 'The built-in word list is damaged. Download cryptopass again.'
    return None


def attach_terminal():
    """Talk to the terminal even when the script came in through a pipe."""
    if os.name != 'posix':
        return
    for fd in (0, 1):
        if not os.isatty(fd):
            try:
                tty = os.open('/dev/tty', os.O_RDWR)
            except OSError:
                sys.exit('cryptopass must be run in an interactive terminal.')
            os.dup2(tty, fd)
            os.close(tty)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help', '--version'):
        print(f'cryptopass {APP_VERSION}: run it without arguments in a '
              f'terminal.\n{REPO_URL}')
        return
    error = problem()
    if error:
        sys.exit(error)
    attach_terminal()
    try:
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error:
        pass
    os.environ.setdefault('ESCDELAY', '25')
    try:
        curses.wrapper(app)
    except KeyboardInterrupt:
        pass
    print('cryptopass closed; the screen has been cleared.')


if __name__ == '__main__':
    main()
