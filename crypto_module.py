"""
crypto_module.py  –  CTF Crypto Swiss Army Knife  v3.1
"""

import base64, binascii, hashlib, hmac as _hmac, html, itertools
import math, os, random, re, string, struct, textwrap, unicodedata
import urllib.parse, zlib
from collections import Counter
from functools import lru_cache
from itertools import cycle

from PyQt6.QtCore    import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui     import QColor, QFont, QTextCharFormat, QSyntaxHighlighter, QTextCursor
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame,
    QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy,
    QSlider, QSpinBox, QSplitter, QStackedWidget, QSystemTrayIcon,
    QStyle, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView,
)
from ui_components import ModernPanel

# ─── Yardımcı Fonksiyonlar ───────────────────────────────────────────────────

def safe_encode(text: str) -> bytes:
    return text.encode("utf-8")

def safe_decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1", "cp1252", "iso-8859-9"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("latin-1", errors="replace")

def _fmt_hex(data: bytes, cols: int = 16) -> str:
    lines = []
    for i in range(0, len(data), cols):
        chunk  = data[i:i+cols]
        hex_   = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}:  {hex_:<{cols*3-1}}  {ascii_}")
    return "\n".join(lines)

def _is_printable(text: str, threshold: float = 0.75) -> bool:
    if not text: return False
    ratio = sum(c.isprintable() for c in text) / len(text)
    return ratio >= threshold

def _looks_like_flag(text: str) -> bool:
    patterns = [r"[A-Za-z0-9_]+\{[^}]+\}", r"flag\{.*?\}", r"CTF\{.*?\}",
                r"picoCTF\{.*?\}", r"HTB\{.*?\}", r"THM\{.*?\}"]
    return any(re.search(p, text, re.I) for p in patterns)

# ═══════════════════════════════════════════════════════════════════════════════
#  1. ENCODING / DECODING
# ═══════════════════════════════════════════════════════════════════════════════

class Encoder:

    @staticmethod
    def base16_enc(t): return base64.b16encode(safe_encode(t)).decode()
    @staticmethod
    def base16_dec(t):
        try: return safe_decode(base64.b16decode(t.strip().upper()))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base32_enc(t): return base64.b32encode(safe_encode(t)).decode()
    @staticmethod
    def base32_dec(t):
        try:
            t = t.strip().upper(); pad = t + "=" * ((8 - len(t) % 8) % 8)
            return safe_decode(base64.b32decode(pad))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base45_enc(t):
        ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
        data = safe_encode(t); res = []
        for i in range(0, len(data) - 1, 2):
            n = data[i] * 256 + data[i+1]
            c, n = divmod(n, 45*45); b, a = divmod(n, 45)
            res += [ALPHABET[a], ALPHABET[b], ALPHABET[c]]
        if len(data) % 2:
            b, a = divmod(data[-1], 45); res += [ALPHABET[a], ALPHABET[b]]
        return "".join(res)

    @staticmethod
    def base45_dec(t):
        ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
        try:
            t = t.strip(); res = []
            for i in range(0, len(t) - 2, 3):
                n = ALPHABET.index(t[i]) + ALPHABET.index(t[i+1])*45 + ALPHABET.index(t[i+2])*45*45
                res += [n >> 8, n & 255]
            if len(t) % 3 == 2:
                n = ALPHABET.index(t[-2]) + ALPHABET.index(t[-1])*45; res.append(n)
            return safe_decode(bytes(res))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base58_enc(t):
        ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(safe_encode(t), "big"); res = ""
        while num: num, r = divmod(num, 58); res = ALPHA[r] + res
        return res or "1"

    @staticmethod
    def base58_dec(t):
        ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        try:
            num = 0
            for ch in t.strip(): num = num * 58 + ALPHA.index(ch)
            length = (num.bit_length() + 7) // 8
            return safe_decode(num.to_bytes(length, "big"))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base62_enc(t):
        ALPHA = string.digits + string.ascii_letters
        num = int.from_bytes(safe_encode(t), "big"); res = ""
        while num: num, r = divmod(num, 62); res = ALPHA[r] + res
        return res or "0"

    @staticmethod
    def base62_dec(t):
        ALPHA = string.digits + string.ascii_letters
        try:
            num = 0
            for ch in t.strip(): num = num * 62 + ALPHA.index(ch)
            length = (num.bit_length() + 7) // 8
            return safe_decode(num.to_bytes(length, "big"))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base64_enc(t): return base64.b64encode(safe_encode(t)).decode()
    @staticmethod
    def base64_dec(t):
        try:
            t = t.strip(); pad = t + "=" * ((4 - len(t) % 4) % 4)
            return safe_decode(base64.b64decode(pad))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base64url_enc(t): return base64.urlsafe_b64encode(safe_encode(t)).decode()
    @staticmethod
    def base64url_dec(t):
        try:
            t = t.strip(); pad = t + "=" * ((4 - len(t) % 4) % 4)
            return safe_decode(base64.urlsafe_b64decode(pad))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base85_enc(t): return base64.b85encode(safe_encode(t)).decode()
    @staticmethod
    def base85_dec(t):
        try: return safe_decode(base64.b85decode(t.strip()))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def base91_enc(t):
        TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"' + "'"
        data = safe_encode(t); b = 0; n = 0; o = []
        for byte in data:
            b |= byte << n; n += 8
            if n > 13:
                v = b & 8191
                if v > 88: b >>= 13; n -= 13
                else: v = b & 16383; b >>= 14; n -= 14
                o.append(TABLE[v % 91]); o.append(TABLE[v // 91])
        if n:
            o.append(TABLE[b % 91])
            if n > 7 or b > 90: o.append(TABLE[b // 91])
        return "".join(o)

    @staticmethod
    def base91_dec(t):
        TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"' + "'"
        try:
            v = -1; b = 0; n = 0; o = bytearray()
            for ch in t.strip():
                p = TABLE.find(ch)
                if p == -1: continue
                if v < 0: v = p
                else:
                    v += p * 91; b |= v << n; n += 13 if (v & 8191) > 88 else 14; v = -1
                    while n > 7: o.append(b & 255); b >>= 8; n -= 8
            if v > -1: o.append((b | v << n) & 255)
            return safe_decode(bytes(o))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def hex_enc(t): return safe_encode(t).hex()
    @staticmethod
    def hex_dec(t):
        try:
            clean = t.strip().replace(" ","").replace("0x","").replace("\\x","").replace("\n","")
            return safe_decode(bytes.fromhex(clean))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def binary_enc(t): return " ".join(f"{b:08b}" for b in safe_encode(t))
    @staticmethod
    def binary_dec(t):
        try:
            bits = t.strip().replace(" ","").replace("\n","")
            ba = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
            return safe_decode(ba)
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def octal_enc(t): return " ".join(f"{b:03o}" for b in safe_encode(t))
    @staticmethod
    def octal_dec(t):
        try: return safe_decode(bytes(int(o, 8) for o in t.strip().split()))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def url_enc(t): return urllib.parse.quote(t, safe="")
    @staticmethod
    def url_dec(t): return urllib.parse.unquote(t)
    @staticmethod
    def url_enc_full(t): return "".join(f"%{b:02X}" for b in safe_encode(t))
    @staticmethod
    def html_enc(t): return html.escape(t, quote=True)
    @staticmethod
    def html_dec(t): return html.unescape(t)
    @staticmethod
    def html_enc_decimal(t): return "".join(f"&#{ord(c)};" for c in t)
    @staticmethod
    def html_enc_hex(t): return "".join(f"&#x{ord(c):X};" for c in t)

    MORSE_MAP = {
        'A':'.-','B':'-..','C':'-.-.'
        ,'D':'-..','E':'.','F':'..-.'
        ,'G':'--.','H':'....','I':'..','J':'.---'
        ,'K':'.-.','L':'.-..'
        ,'M':'--','N':'-.'
        ,'O':'---','P':'.--.','Q':'--.-','R':'.-.'
        ,'S':'...','T':'-'
        ,'U':'..-','V':'...-','W':'.--','X':'-..-'
        ,'Y':'-.--','Z':'--..'
        ,'0':'-----','1':'.----','2':'..---','3':'...--'
        ,'4':'....-','5':'.....','6':'-.....'
        ,'7':'--...','8':'---..','9':'----.','.':'.-.-.-'
        ,',':'--..--','?':'..--..'
    }
    MORSE_REV = {v: k for k, v in MORSE_MAP.items()}

    @classmethod
    def morse_enc(cls, t):
        result = []
        for word in t.upper().split():
            coded = [cls.MORSE_MAP.get(ch, f"?({ch})") for ch in word]
            result.append(" ".join(coded))
        return " / ".join(result)

    @classmethod
    def morse_dec(cls, t):
        try:
            words = t.strip().split(" / ")
            return " ".join("".join(cls.MORSE_REV.get(code, "?") for code in word.split()) for word in words)
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def ascii_enc(t): return " ".join(str(b) for b in safe_encode(t))
    @staticmethod
    def ascii_dec(t):
        try: return safe_decode(bytes(int(n) for n in t.strip().split()))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def unicode_enc(t): return " ".join(f"U+{ord(c):04X}" for c in t)
    @staticmethod
    def unicode_dec(t):
        try: return "".join(chr(int(u.replace("U+","").replace("u+",""), 16)) for u in t.strip().split())
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def unicode_escape_enc(t): return t.encode("unicode_escape").decode("ascii")
    @staticmethod
    def unicode_escape_dec(t):
        try: return t.encode("ascii").decode("unicode_escape")
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def uuencode_enc(t):
        import io
        data = safe_encode(t); out = io.BytesIO()
        out.write(b"begin 644 file\n")
        for i in range(0, len(data), 45):
            chunk = data[i:i+45]
            line = bytes([len(chunk) + 32])
            for j in range(0, len(chunk), 3):
                triple = chunk[j:j+3].ljust(3, b'\x00')
                line += bytes([
                    ((triple[0] >> 2) & 63) + 32,
                    (((triple[0] & 3) << 4) | ((triple[1] >> 4) & 15)) + 32,
                    (((triple[1] & 15) << 2) | ((triple[2] >> 6) & 3)) + 32,
                    (triple[2] & 63) + 32,
                ])
            out.write(line + b"\n")
        out.write(b"`\nend\n")
        return out.getvalue().decode()

    @staticmethod
    def uuencode_dec(t):
        try:
            import binascii; lines = t.strip().splitlines(); data = bytearray()
            for line in lines:
                if line.startswith("begin") or line.startswith("`") or line.startswith("end"): continue
                data += binascii.a2b_uu(line)
            return safe_decode(bytes(data))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def qp_enc(t):
        import quopri; return quopri.encodestring(safe_encode(t)).decode()
    @staticmethod
    def qp_dec(t):
        try:
            import quopri; return safe_decode(quopri.decodestring(t.encode()))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def jwt_decode(token):
        try:
            parts = token.strip().split(".")
            if len(parts) < 2: return "[HATA] Gecerli JWT degil"
            results = []
            for i, part in enumerate(parts[:2]):
                pad = part + "=" * ((4 - len(part) % 4) % 4)
                dec = safe_decode(base64.urlsafe_b64decode(pad))
                results.append(f"[{['Header','Payload'][i]}]\n{dec}")
            results.append(f"[Signature]\n{parts[2] if len(parts) > 2 else 'yok'}")
            return "\n\n".join(results)
        except Exception as e: return f"[HATA] {e}"

    BRAILLE = {'a':'⠁','b':'⠃','c':'⠉','d':'⠙','e':'⠑','f':'⠋','g':'⠛','h':'⠓',
               'i':'⠊','j':'⠚','k':'⠅','l':'⠇','m':'⠍','n':'⠝','o':'⠕','p':'⠏',
               'q':'⠟','r':'⠗','s':'⠎','t':'⠞','u':'⠥','v':'⠧','w':'⠺','x':'⠭',
               'y':'⠽','z':'⠵',' ':'⠀'}
    BRAILLE_REV = {v: k for k, v in BRAILLE.items()}

    @classmethod
    def braille_enc(cls, t): return "".join(cls.BRAILLE.get(c.lower(), c) for c in t)
    @classmethod
    def braille_dec(cls, t): return "".join(cls.BRAILLE_REV.get(c, c) for c in t)

    ZW_CHARS = {'0': '\u200b', '1': '\u200c', 'sep': '\u200d'}

    @classmethod
    def zerowidth_enc(cls, cover, secret):
        bits = "".join(f"{b:08b}" for b in safe_encode(secret))
        zw = "".join(cls.ZW_CHARS['1'] if b == '1' else cls.ZW_CHARS['0'] for b in bits)
        mid = len(cover) // 2
        return cover[:mid] + zw + cover[mid:]

    @classmethod
    def zerowidth_dec(cls, text):
        zw_0, zw_1 = cls.ZW_CHARS['0'], cls.ZW_CHARS['1']
        bits = ""
        for ch in text:
            if ch == zw_1: bits += "1"
            elif ch == zw_0: bits += "0"
        if not bits: return "[Gizli veri bulunamadi]"
        try:
            ba = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)//8*8, 8))
            return safe_decode(ba)
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def punycode_enc(t):
        try: return t.encode("idna").decode("ascii")
        except Exception as e: return f"[HATA] {e}"
    @staticmethod
    def punycode_dec(t):
        try: return t.encode("ascii").decode("idna")
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def rot5(t): return "".join(chr((ord(c)-48+5)%10+48) if c.isdigit() else c for c in t)
    @staticmethod
    def rot18(t):
        result = []
        for c in t:
            if c.isalpha():
                base = 65 if c.isupper() else 97
                result.append(chr((ord(c)-base+13)%26+base))
            elif c.isdigit(): result.append(chr((ord(c)-48+5)%10+48))
            else: result.append(c)
        return "".join(result)
    @staticmethod
    def rot47(t):
        return "".join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in t)

    @staticmethod
    def whitespace_enc(t):
        bits = "".join(f"{b:08b}" for b in safe_encode(t))
        return "".join(" " if b=="0" else "\t" for b in bits)
    @staticmethod
    def whitespace_dec(t):
        try:
            bits = "".join("0" if c==" " else "1" for c in t if c in (" ","\t"))
            ba = bytes(int(bits[i:i+8],2) for i in range(0, len(bits)//8*8, 8))
            return safe_decode(ba)
        except Exception as e: return f"[HATA] {e}"


# ═══════════════════════════════════════════════════════════════════════════════
#  2. KLASİK ŞİFRELER
# ═══════════════════════════════════════════════════════════════════════════════

class Cipher:

    @staticmethod
    def caesar(text, shift, decrypt=False):
        if decrypt: shift = -shift
        result = []
        for ch in text:
            if ch.isupper(): result.append(chr((ord(ch)-65+shift)%26+65))
            elif ch.islower(): result.append(chr((ord(ch)-97+shift)%26+97))
            else: result.append(ch)
        return "".join(result)

    @staticmethod
    def rot13(text): return Cipher.caesar(text, 13)

    @staticmethod
    def vigenere(text, key, decrypt=False):
        key = key.upper(); result = []; ki = 0
        for ch in text:
            if ch.isalpha():
                shift = ord(key[ki % len(key)]) - 65
                base = 65 if ch.isupper() else 97
                if decrypt: result.append(chr((ord(ch)-base-shift)%26+base))
                else: result.append(chr((ord(ch)-base+shift)%26+base))
                ki += 1
            else: result.append(ch)
        return "".join(result)

    @staticmethod
    def beaufort(text, key):
        key = key.upper(); result = []; ki = 0
        for ch in text:
            if ch.isalpha():
                k = ord(key[ki % len(key)]) - 65
                base = 65 if ch.isupper() else 97
                result.append(chr((k-(ord(ch)-base))%26+base)); ki += 1
            else: result.append(ch)
        return "".join(result)

    PORTA_TABLE = [
        "nopqrstuvwxyzabcdefghijklm","opqrstuvwxyznmabcdefghijkl",
        "pqrstuvwxyznomLabcdefghijk","qrstuvwxyznopmklabcdefghij",
        "rstuvwxyznopqmjklabcdefghi","stuvwxyznopqrmijklabcdefgh",
        "tuvwxyznopqrsmhijklabcdefg","uvwxyznopqrstmghijklabcdef",
        "vwxyznopqrstumfghijklabcde","wxyznopqrstuvmefghijklabcd",
        "xyznopqrstuvwmdefghijklabc","yznopqrstuvwxmcdefghijklab",
        "znopqrstuvwxymabcdefghijkl",
    ]

    @classmethod
    def porta(cls, text, key, decrypt=False):
        key = key.lower(); result = []; ki = 0
        for ch in text:
            if ch.isalpha():
                k = ord(key[ki % len(key)]) - 97
                row = cls.PORTA_TABLE[k // 2]; lower = ch.lower()
                if not decrypt:
                    idx = ord(lower) - 97; enc = row[idx]
                    result.append(enc.upper() if ch.isupper() else enc)
                else:
                    idx = row.find(ch.lower())
                    if idx == -1: result.append(ch)
                    else:
                        dec = chr(idx + 97)
                        result.append(dec.upper() if ch.isupper() else dec)
                ki += 1
            else: result.append(ch)
        return "".join(result)

    @staticmethod
    def atbash(text):
        result = []
        for ch in text:
            if ch.isupper(): result.append(chr(90-(ord(ch)-65)))
            elif ch.islower(): result.append(chr(122-(ord(ch)-97)))
            else: result.append(ch)
        return "".join(result)

    @staticmethod
    def affine_enc(text, a, b):
        result = []
        for ch in text:
            if ch.isalpha():
                base = 65 if ch.isupper() else 97
                result.append(chr((a*(ord(ch)-base)+b)%26+base))
            else: result.append(ch)
        return "".join(result)

    @staticmethod
    def affine_dec(text, a, b):
        def mod_inv(a, m):
            for x in range(1, m):
                if (a*x)%m == 1: return x
            return None
        inv = mod_inv(a, 26)
        if inv is None: return "[HATA] 'a' 26 ile aralarinda asal olmali"
        result = []
        for ch in text:
            if ch.isalpha():
                base = 65 if ch.isupper() else 97
                result.append(chr((inv*(ord(ch)-base-b))%26+base))
            else: result.append(ch)
        return "".join(result)

    @staticmethod
    def rail_fence_enc(text, rails):
        fence = [[] for _ in range(rails)]; rail, step = 0, 1
        for ch in text:
            fence[rail].append(ch)
            if rail == 0: step = 1
            elif rail == rails-1: step = -1
            rail += step
        return "".join("".join(r) for r in fence)

    @staticmethod
    def rail_fence_dec(text, rails):
        n = len(text); pattern = []; rail, step = 0, 1
        for _ in range(n):
            pattern.append(rail)
            if rail == 0: step = 1
            elif rail == rails-1: step = -1
            rail += step
        counts = [pattern.count(r) for r in range(rails)]
        fence = []; idx = 0
        for c in counts: fence.append(list(text[idx:idx+c])); idx += c
        ptrs = [0]*rails; result = []
        for r in pattern: result.append(fence[r][ptrs[r]]); ptrs[r] += 1
        return "".join(result)

    @staticmethod
    def columnar_enc(text, key):
        key = key.upper(); order = sorted(range(len(key)), key=lambda i: key[i])
        ncols = len(key); nrows = math.ceil(len(text)/ncols)
        padded = text.ljust(nrows*ncols)
        grid = [list(padded[i*ncols:(i+1)*ncols]) for i in range(nrows)]
        return "".join("".join(grid[r][c] for r in range(nrows)) for c in order)

    @staticmethod
    def columnar_dec(text, key):
        key = key.upper(); ncols = len(key); nrows = math.ceil(len(text)/ncols)
        order = sorted(range(ncols), key=lambda i: key[i])
        cols = {}; idx = 0
        for c in order: cols[c] = list(text[idx:idx+nrows]); idx += nrows
        result = []
        for r in range(nrows):
            for c in range(ncols): result.append(cols[c][r])
        return "".join(result).rstrip()

    @staticmethod
    def _playfair_square(key):
        key = key.upper().replace("J","I"); seen = set(); sq = []
        for ch in key + string.ascii_uppercase:
            if ch == "J": continue
            if ch not in seen: seen.add(ch); sq.append(ch)
        return [sq[i*5:(i+1)*5] for i in range(5)]

    @classmethod
    def _playfair_find(cls, sq, ch):
        for r, row in enumerate(sq):
            if ch in row: return r, row.index(ch)
        return 0, 0

    @classmethod
    def playfair(cls, text, key, decrypt=False):
        sq = cls._playfair_square(key); t = text.upper().replace("J","I")
        t = re.sub(r"[^A-Z]", "", t); pairs = []; i = 0
        while i < len(t):
            a = t[i]
            if i+1 < len(t):
                b = t[i+1]
                if a == b: pairs.append((a,"X")); i += 1
                else: pairs.append((a,b)); i += 2
            else: pairs.append((a,"X")); i += 1
        result = []; d = -1 if decrypt else 1
        for a, b in pairs:
            ra, ca = cls._playfair_find(sq, a); rb, cb = cls._playfair_find(sq, b)
            if ra == rb: result += [sq[ra][(ca+d)%5], sq[rb][(cb+d)%5]]
            elif ca == cb: result += [sq[(ra+d)%5][ca], sq[(rb+d)%5][cb]]
            else: result += [sq[ra][cb], sq[rb][ca]]
        return "".join(result)

    @staticmethod
    def polybius_enc(text, key="ABCDE"):
        alpha = string.ascii_uppercase.replace("J",""); sq = {}
        for i, ch in enumerate(alpha): r, c = divmod(i,5); sq[ch] = f"{key[r]}{key[c]}"
        result = []
        for ch in text.upper():
            if ch == "J": ch = "I"
            result.append(sq.get(ch, ch))
        return " ".join(result)

    @staticmethod
    def polybius_dec(text, key="ABCDE"):
        alpha = string.ascii_uppercase.replace("J",""); sq = {}
        for i, ch in enumerate(alpha): r, c = divmod(i,5); sq[f"{key[r]}{key[c]}"] = ch
        return "".join(sq.get(pair.upper(), pair) for pair in text.strip().split())

    ADFGVX_KEY = "ADFGVX"

    @classmethod
    def adfgvx_enc(cls, text, polybius_key, trans_key):
        poly = polybius_key.upper()[:36].ljust(36,"?")
        sq = {ch: (cls.ADFGVX_KEY[i//6], cls.ADFGVX_KEY[i%6]) for i, ch in enumerate(poly)}
        text = re.sub(r"[^A-Z0-9]","",text.upper())
        fractionated = "".join(a+b for ch in text for a,b in [sq.get(ch,("?","?"))])
        return Cipher.columnar_enc(fractionated, trans_key)

    @classmethod
    def adfgvx_dec(cls, text, polybius_key, trans_key):
        poly = polybius_key.upper()[:36].ljust(36,"?")
        sq = {(cls.ADFGVX_KEY[i//6], cls.ADFGVX_KEY[i%6]): ch for i, ch in enumerate(poly)}
        fractionated = Cipher.columnar_dec(text, trans_key); result = []
        for i in range(0, len(fractionated)-1, 2):
            pair = (fractionated[i], fractionated[i+1]); result.append(sq.get(pair,"?"))
        return "".join(result)

    BACON = {ch: format(i,'05b').replace('0','A').replace('1','B')
             for i, ch in enumerate(string.ascii_uppercase)}
    BACON_REV = {v: k for k, v in BACON.items()}

    @classmethod
    def bacon_enc(cls, text): return " ".join(cls.BACON.get(ch.upper(),ch) for ch in text if ch.isalpha())
    @classmethod
    def bacon_dec(cls, text):
        text = text.upper().replace(" ",""); result = []
        for i in range(0, len(text), 5): result.append(cls.BACON_REV.get(text[i:i+5],"?"))
        return "".join(result)

    TAP_TABLE = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    @classmethod
    def tap_enc(cls, text):
        result = []
        for ch in text.upper():
            if ch == "J": ch = "I"
            if ch in cls.TAP_TABLE:
                idx = cls.TAP_TABLE.index(ch); r, c = divmod(idx, 5)
                result.append(f"{r+1} {c+1}")
        return "  ".join(result)

    @classmethod
    def tap_dec(cls, text):
        try:
            pairs = text.strip().split("  "); result = []
            for pair in pairs:
                nums = pair.strip().split()
                if len(nums) == 2:
                    r, c = int(nums[0])-1, int(nums[1])-1
                    result.append(cls.TAP_TABLE[r*5+c])
            return "".join(result)
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def _polybius_numeric(text):
        alpha = string.ascii_uppercase.replace("J",""); result = []
        for ch in text.upper():
            if ch == "J": ch = "I"
            if ch in alpha:
                idx = alpha.index(ch); r, c = divmod(idx, 5)
                result.append((r+1)*10+(c+1))
        return result

    @classmethod
    def nihilist_enc(cls, text, key):
        tp = cls._polybius_numeric(text); kp = cls._polybius_numeric(key)
        if not kp: return "[HATA] Gecersiz key"
        return " ".join(str(tp[i]+kp[i%len(kp)]) for i in range(len(tp)))

    @classmethod
    def nihilist_dec(cls, text, key):
        try:
            kp = cls._polybius_numeric(key); nums = [int(n) for n in text.strip().split()]
            alpha = string.ascii_uppercase.replace("J",""); result = []
            for i, n in enumerate(nums):
                val = n - kp[i%len(kp)]; r, c = divmod(val, 10); idx = (r-1)*5+(c-1)
                result.append(alpha[idx] if 0<=idx<len(alpha) else "?")
            return "".join(result)
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def xor_text(text, key):
        text_b = safe_encode(text); key_b = safe_encode(key)
        result = bytes(b^k for b,k in zip(text_b, cycle(key_b)))
        return safe_decode(result)

    @staticmethod
    def xor_bytes(data, key): return bytes(b^k for b,k in zip(data, cycle(key)))

    @staticmethod
    def xor_hex(hex_data, hex_key):
        try:
            data = bytes.fromhex(hex_data.replace(" ","")); key = bytes.fromhex(hex_key.replace(" ",""))
            return Cipher.xor_bytes(data, key).hex()
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def substitution(text, key, decrypt=False):
        alpha = string.ascii_uppercase; key = key.upper()
        if len(key) != 26: return "[HATA] Key tam 26 harf olmali"
        if decrypt: table = str.maketrans(key, alpha)
        else: table = str.maketrans(alpha, key)
        return text.upper().translate(table)

    @staticmethod
    def rc4(data, key):
        S = list(range(256)); j = 0
        for i in range(256): j = (j+S[i]+key[i%len(key)])%256; S[i],S[j] = S[j],S[i]
        i = j = 0; out = []
        for byte in data:
            i = (i+1)%256; j = (j+S[i])%256; S[i],S[j] = S[j],S[i]
            out.append(byte^S[(S[i]+S[j])%256])
        return bytes(out)

    @staticmethod
    def rc4_text(text, key): return Cipher.rc4(safe_encode(text), safe_encode(key)).hex()
    @staticmethod
    def rc4_hex(hex_data, key):
        try: return safe_decode(Cipher.rc4(bytes.fromhex(hex_data.replace(" ","")), safe_encode(key)))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def chain_decode(text, methods):
        steps = []
        current = text
        fn_map = {
            "base64": Encoder.base64_dec, "base32": Encoder.base32_dec,
            "base16": Encoder.base16_dec, "base58": Encoder.base58_dec,
            "base85": Encoder.base85_dec, "base91": Encoder.base91_dec,
            "hex": Encoder.hex_dec, "binary": Encoder.binary_dec,
            "octal": Encoder.octal_dec, "url": Encoder.url_dec,
            "html": Encoder.html_dec, "rot13": Cipher.rot13,
            "rot47": Encoder.rot47, "rot18": Encoder.rot18,
            "atbash": Cipher.atbash, "morse": Encoder.morse_dec,
            "ascii": Encoder.ascii_dec, "unicode": Encoder.unicode_dec,
            "braille": Encoder.braille_dec, "qp": Encoder.qp_dec,
        }
        known = ", ".join(sorted(fn_map.keys()))
        for m in methods:
            m = m.strip()
            if not m:
                continue
            fn = fn_map.get(m.lower())
            if fn:
                try:
                    result = fn(current)
                    # [HATA] içeriyorsa hatayı kısa göster, adımı durdur
                    if isinstance(result, str) and result.startswith("[HATA]"):
                        short_err = result.split(":")[0] + ": geçersiz giriş"
                        steps.append((m, current, f"⚠️ {short_err}"))
                        break  # Hatalı adımdan sonra dur
                    steps.append((m, current, result))
                    current = result
                except Exception as e:
                    steps.append((m, current, f"⚠️ Hata: geçersiz giriş"))
                    break
            else:
                steps.append((m, current, f"❓ Bilinmeyen yöntem: '{m}' | Kullanılabilir: {known}"))
        return steps


# ═══════════════════════════════════════════════════════════════════════════════
#  3. HASH & HMAC
# ═══════════════════════════════════════════════════════════════════════════════

class Hasher:
    ALGOS = ["md5","sha1","sha224","sha256","sha384","sha512","sha3_256","sha3_512","blake2b","blake2s"]

    @staticmethod
    def hash_text(text, algo):
        try: return hashlib.new(algo, safe_encode(text)).hexdigest()
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def hash_bytes(data, algo):
        try: return hashlib.new(algo, data).hexdigest()
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def hash_file(path, algo):
        try:
            h = hashlib.new(algo)
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
            return h.hexdigest()
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def hmac_sign(text, key, algo):
        try: return _hmac.new(safe_encode(key), safe_encode(text), algo).hexdigest()
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def crc32(text): return format(zlib.crc32(safe_encode(text)) & 0xFFFFFFFF, "08x")
    @staticmethod
    def adler32(text): return format(zlib.adler32(safe_encode(text)) & 0xFFFFFFFF, "08x")

    @staticmethod
    def pbkdf2(password, salt, iterations=100000, algo="sha256"):
        try:
            dk = hashlib.pbkdf2_hmac(algo, safe_encode(password), safe_encode(salt), iterations)
            return dk.hex()
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def hash_all(text):
        results = {}
        for algo in Hasher.ALGOS: results[algo] = Hasher.hash_text(text, algo)
        results["crc32"] = Hasher.crc32(text); results["adler32"] = Hasher.adler32(text)
        return results

    @staticmethod
    def identify_hash(h):
        h = h.strip()
        length_map = {
            8: ["CRC32","Adler32"], 32: ["MD5","MD4","NTLM"], 40: ["SHA-1","MySQL4/5"],
            56: ["SHA-224","SHA3-224"], 60: ["bcrypt"], 64: ["SHA-256","BLAKE2s"],
            96: ["SHA-384","SHA3-384"], 128: ["SHA-512","BLAKE2b","SHA3-512"],
        }
        hints = length_map.get(len(h), ["Bilinmiyor"]); extras = []
        if h.startswith("$2"): extras.append("bcrypt")
        if h.startswith("$6"): extras.append("SHA-512 Unix")
        out = f"Uzunluk: {len(h)} karakter\n"
        out += f"Muhtemel: {', '.join(hints)}\n"
        if extras: out += f"Ek ipucu: {', '.join(extras)}\n"
        try: bytes.fromhex(h); out += "Format: Hexadecimal ✓\n"
        except: out += "Format: Hexadecimal degil\n"
        return out

    @staticmethod
    def multi_hash_compare(text, target_hash):
        target = target_hash.strip().lower()
        for algo in Hasher.ALGOS + ["crc32","adler32"]:
            h = Hasher.crc32(text) if algo=="crc32" else (Hasher.adler32(text) if algo=="adler32" else Hasher.hash_text(text,algo))
            if h.lower() == target: return f"✅ ESLESTI! Algoritma: {algo}\nHash: {h}"
        return "❌ Hicbir algoritmayla esleme bulunamadi."


# ═══════════════════════════════════════════════════════════════════════════════
#  4. OTOMATİK TESPİT
# ═══════════════════════════════════════════════════════════════════════════════

class AutoDetect:

    @staticmethod
    def detect(text):
        hints = []; t = text.strip()
        b64c = set(string.ascii_letters + string.digits + "+/=")
        if all(c in b64c for c in t) and len(t) % 4 == 0 and len(t) >= 4:
            hints.append(("Base64", "yüksek"))
        b32c = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
        if all(c in b32c for c in t.upper()) and len(t) % 8 == 0:
            hints.append(("Base32", "yüksek"))
        b16c = set("0123456789ABCDEFabcdef")
        if all(c in b16c for c in t) and len(t) % 2 == 0:
            hints.append(("Hex / Base16", "yüksek"))
        if all(c in "01 \n" for c in t):
            bits = t.replace(" ","").replace("\n","")
            if len(bits) % 8 == 0: hints.append(("Binary", "yüksek"))
        if all(c in ".-/ \n" for c in t) and (".-" in t or "-." in t):
            hints.append(("Morse Kodu", "yüksek"))
        if "%" in t and re.search(r"%[0-9A-Fa-f]{2}", t):
            hints.append(("URL Encoding", "yüksek"))
        if "&amp;" in t or "&lt;" in t or "&#" in t:
            hints.append(("HTML Entity", "yüksek"))
        if t.count(".") == 2 and all(c in string.ascii_letters+string.digits+"-_.=" for c in t):
            hints.append(("JWT Token", "orta"))
        hc = t.replace(" ","")
        if all(c in "0123456789abcdefABCDEF" for c in hc) and len(hc) in (32,40,56,64,96,128):
            hints.append((Hasher.identify_hash(hc), "orta"))
        parts = t.split()
        if all(p.isdigit() for p in parts) and all(0 <= int(p) <= 127 for p in parts):
            hints.append(("ASCII Decimal", "yüksek"))
        if t.replace(" ","").isalpha(): hints.append(("ROT13/Caesar/Vigenere/Atbash olabilir", "düşük"))
        if t.startswith("begin"): hints.append(("UUEncode", "yüksek"))
        if re.search(r"=[0-9A-Fa-f]{2}", t): hints.append(("Quoted-Printable", "yüksek"))
        if any('\u2800' <= c <= '\u28ff' for c in t): hints.append(("Braille", "yüksek"))
        if any(c in '\u200b\u200c\u200d' for c in t): hints.append(("Zero-Width Steg", "yüksek"))
        if re.fullmatch(r"[AB ]+", t.upper()): hints.append(("Bacon Sifresi", "orta"))
        if not hints: hints.append(("Tespit edilemedi – manuel inceleme gerekli", "bilinmiyor"))
        return hints

    @staticmethod
    def try_all_encodings(text):
        results = {}
        fns = {
            "Base64": Encoder.base64_dec, "Base64 URL": Encoder.base64url_dec,
            "Base32": Encoder.base32_dec, "Base16": Encoder.base16_dec,
            "Base58": Encoder.base58_dec, "Base85": Encoder.base85_dec,
            "Base91": Encoder.base91_dec, "Hex": Encoder.hex_dec,
            "Binary": Encoder.binary_dec, "Octal": Encoder.octal_dec,
            "URL": Encoder.url_dec, "HTML": Encoder.html_dec,
            "ASCII Dec": Encoder.ascii_dec, "Morse": Encoder.morse_dec,
            "QP": Encoder.qp_dec, "UUEncode": Encoder.uuencode_dec,
            "ROT13": Cipher.rot13, "ROT47": Encoder.rot47,
            "Atbash": Cipher.atbash, "Braille": Encoder.braille_dec,
        }
        for name, fn in fns.items():
            try:
                out = fn(text)
                if out and "[HATA]" not in str(out) and out != text and len(out) > 0:
                    if _is_printable(out, 0.65):
                        flag = " 🚩FLAG!" if _looks_like_flag(out) else ""
                        results[name + flag] = out
            except Exception: pass
        return results

    @staticmethod
    def deep_decode(text, max_depth=5):
        history = [(0, "Orijinal", text)]; current = text
        for depth in range(1, max_depth+1):
            results = AutoDetect.try_all_encodings(current)
            if not results: break
            best_key = None; best_val = None
            for k, v in results.items():
                if "FLAG" in k: best_key, best_val = k, v; break
            if not best_key: best_key, best_val = next(iter(results.items()))
            if best_val == current: break
            history.append((depth, best_key, best_val)); current = best_val
        return history


# ═══════════════════════════════════════════════════════════════════════════════
#  5. FREKANS ANALİZİ
# ═══════════════════════════════════════════════════════════════════════════════

class FreqAnalysis:

    EN_FREQ = {
        'E':12.7,'T':9.1,'A':8.2,'O':7.5,'I':7.0,'N':6.7,'S':6.3,'H':6.1,
        'R':6.0,'D':4.3,'L':4.0,'C':2.8,'U':2.8,'M':2.4,'W':2.4,'F':2.2,
        'G':2.0,'Y':2.0,'P':1.9,'B':1.5,'V':1.0,'K':0.8,'J':0.2,'X':0.2,'Q':0.1,'Z':0.1
    }
    TR_FREQ = {
        'A':11.92,'E':8.91,'N':7.49,'R':6.72,'L':5.92,'I':5.11,'D':4.70,
        'K':4.68,'M':3.75,'U':3.23,'Y':3.33,'T':3.01,'S':3.01,'B':2.84,
        'O':2.45,'Z':1.50,'G':1.25,'H':1.21,'V':0.95,'C':0.97,'P':0.79,'F':0.46
    }

    @staticmethod
    def analyse(text):
        text = text.upper(); letters = [c for c in text if c.isalpha()]
        if not letters: return {}, 0
        freq = Counter(letters); total = len(letters)
        return {c: round(freq[c]/total*100, 2) for c in freq}, total

    @staticmethod
    def chi_square(text, ref_freq):
        text = "".join(c for c in text.upper() if c.isalpha()); n = len(text)
        if n == 0: return float("inf")
        freq = Counter(text); chi = 0.0
        for ch in string.ascii_uppercase:
            observed = freq.get(ch, 0)
            expected = ref_freq.get(ch, 0.01)/100*n
            chi += (observed-expected)**2/expected
        return chi

    @staticmethod
    def index_of_coincidence(text):
        text = "".join(c for c in text.upper() if c.isalpha()); n = len(text)
        if n < 2: return 0.0
        freq = Counter(text)
        return sum(f*(f-1) for f in freq.values())/(n*(n-1))

    @staticmethod
    def kasiski_key_length(text, max_key=20):
        text = "".join(c for c in text.upper() if c.isalpha()); tris = {}
        for i in range(len(text)-3): tris.setdefault(text[i:i+3], []).append(i)
        distances = []
        for positions in tris.values():
            if len(positions) > 1:
                for j in range(1, len(positions)): distances.append(positions[j]-positions[j-1])
        if not distances: return []
        gcds = Counter()
        for d in distances:
            for k in range(2, min(d+1, max_key+1)):
                if d % k == 0: gcds[k] += 1
        return gcds.most_common(5)

    @staticmethod
    def caesar_score(text, language="EN"):
        ref = FreqAnalysis.EN_FREQ if language=="EN" else FreqAnalysis.TR_FREQ
        scores = []
        for shift in range(26):
            decoded = Cipher.caesar(text, shift, decrypt=True)
            scores.append((shift, FreqAnalysis.chi_square(decoded, ref), decoded))
        return sorted(scores, key=lambda x: x[1])

    @staticmethod
    def vigenere_crack(ciphertext, key_len, language="EN"):
        text = "".join(c for c in ciphertext.upper() if c.isalpha())
        ref = FreqAnalysis.EN_FREQ if language=="EN" else FreqAnalysis.TR_FREQ; key = []
        for i in range(key_len):
            nth = text[i::key_len]; scores = FreqAnalysis.caesar_score(nth, language)
            key.append(chr(scores[0][0]+65))
        return "".join(key)

    @staticmethod
    def substitution_hint(ciphertext, language="EN"):
        pct, _ = FreqAnalysis.analyse(ciphertext)
        ref = FreqAnalysis.EN_FREQ if language=="EN" else FreqAnalysis.TR_FREQ
        sorted_cipher = sorted(pct, key=lambda c: -pct[c])
        sorted_plain = sorted(ref, key=lambda c: -ref[c])
        mapping = dict(zip(sorted_cipher, sorted_plain))
        lines = ["Frekans bazli substitution tahmini:\n"]
        for c, p in mapping.items():
            lines.append(f"  {c} -> {p}  ({pct.get(c,0):.1f}% / {ref.get(p,0):.1f}%)")
        result = "".join(mapping.get(ch, ch) for ch in ciphertext.upper() if ch.isalpha())
        lines.append(f"\nTahmini duz metin:\n{result}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
#  6. RSA / ASİMETRİK
# ═══════════════════════════════════════════════════════════════════════════════

class RSATools:

    @staticmethod
    def egcd(a, b):
        if a == 0: return (b, 0, 1)
        g, y, x = RSATools.egcd(b%a, a); return (g, x-(b//a)*y, y)

    @staticmethod
    def modinv(a, m):
        g, x, _ = RSATools.egcd(a%m, m)
        if g != 1: raise ValueError("Modueler ters yok")
        return x % m

    @staticmethod
    def calc_d(p, q, e):
        phi = (p-1)*(q-1); return RSATools.modinv(e, phi)

    @staticmethod
    def encrypt(m, e, n): return pow(m, e, n)
    @staticmethod
    def decrypt(c, d, n): return pow(c, d, n)

    @staticmethod
    def int_to_text(n):
        try:
            length = (n.bit_length()+7)//8; return safe_decode(n.to_bytes(length,"big"))
        except Exception: return str(n)

    @staticmethod
    def text_to_int(t): return int.from_bytes(safe_encode(t), "big")

    @staticmethod
    def factor_small_n(n):
        if n < 2: return None, None
        for p in range(2, min(10**7, int(n**0.5)+2)):
            if n % p == 0: return p, n//p
        return None, None

    @staticmethod
    def wiener_attack_hint(e, n):
        d_bound = n**0.25/3
        lines = [
            "Wiener Saldirisi Analizi", "─"*40,
            f"n bit uzunlugu: {n.bit_length()}", f"e degeri: {e}",
            f"d < n^(1/4)/3 = {d_bound:.0f} olmali",
        ]
        if e > n*0.75: lines.append("✅ Wiener uygulanabilir (e cok buyuk)")
        else: lines.append("⚠️ Standart Wiener icin e cok kucuk")
        lines.append("\nAnahtar: owiener kutuphanesi → pip install owiener")
        return "\n".join(lines)

    @staticmethod
    def common_modulus_attack(c1, c2, e1, e2, n):
        try:
            from math import gcd
            if gcd(e1, e2) != 1: return "[HATA] e1 ve e2 aralarinda asal olmali"
            _, a, b = RSATools.egcd(e1, e2)
            if a < 0: c1 = RSATools.modinv(c1, n); a = -a
            if b < 0: c2 = RSATools.modinv(c2, n); b = -b
            m = (pow(c1,a,n)*pow(c2,b,n))%n
            return f"Mesaj (int): {m}\nMesaj (metin): {RSATools.int_to_text(m)}"
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def small_e_attack(c, e):
        low, high = 0, c
        while low < high:
            mid = (low+high)//2
            if mid**e < c: low = mid+1
            else: high = mid
        if low**e == c:
            return f"✅ Mesaj bulundu! m = {low}\nMetin: {RSATools.int_to_text(low)}"
        return "❌ Padding yoksa cozum bulunamadi"


# ═══════════════════════════════════════════════════════════════════════════════
#  7. CTF ARAÇ KUTUSU (Yardımcı Fonksiyonlar)
# ═══════════════════════════════════════════════════════════════════════════════

class CTFTools:

    @staticmethod
    def xor_brute_1byte(data):
        results = []
        for key in range(256):
            out = bytes(b^key for b in data)
            score = sum(c in b" \t\n" + string.printable.encode() for c in out)
            if score > len(data)*0.65:
                try:
                    text = safe_decode(out)
                    flag_bonus = 100 if _looks_like_flag(text) else 0
                    results.append((key, score+flag_bonus, text))
                except Exception: pass
        return sorted(results, key=lambda x: -x[1])[:15]

    @staticmethod
    def xor_brute_2byte(data):
        results = []
        for k1 in range(256):
            for k2 in range(256):
                key = bytes([k1, k2]); out = Cipher.xor_bytes(data, key)
                score = sum(c in string.printable.encode() for c in out)
                if score > len(data)*0.80:
                    try:
                        text = safe_decode(out)
                        if _looks_like_flag(text): results.append((f"0x{k1:02X}{k2:02X}", score, text))
                    except Exception: pass
        return sorted(results, key=lambda x: -x[1])[:10]

    @staticmethod
    def base_convert(value, from_base, to_base):
        try:
            decimal = int(value.strip(), from_base)
            if to_base == 2: return bin(decimal)[2:]
            if to_base == 8: return oct(decimal)[2:]
            if to_base == 10: return str(decimal)
            if to_base == 16: return hex(decimal)[2:].upper()
            digits = string.digits + string.ascii_uppercase
            result = ""
            while decimal: decimal, r = divmod(decimal, to_base); result = digits[r]+result
            return result or "0"
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def show_all_bases(value, from_base):
        try:
            dec = int(value.strip(), from_base)
            lines = [
                f"DEC  (10): {dec}", f"HEX  (16): {hex(dec)[2:].upper()}",
                f"OCT   (8): {oct(dec)[2:]}", f"BIN   (2): {bin(dec)[2:]}",
                f"CHR      : {chr(dec) if 0<=dec<=0x10FFFF else 'N/A'}",
            ]
            for base in (3,4,5,6,7,9,12,32,36):
                lines.append(f"BASE {base:>2}  : {CTFTools.base_convert(str(dec), 10, base)}")
            return "\n".join(lines)
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def bit_ops(a, b):
        return {
            "AND": a&b, "OR": a|b, "XOR": a^b,
            "NAND": ~(a&b)&0xFFFFFFFF, "NOR": ~(a|b)&0xFFFFFFFF,
            "NOT a": ~a&0xFFFFFFFF, "NOT b": ~b&0xFFFFFFFF,
            "SHL a x1": (a<<1)&0xFFFFFFFF, "SHR a x1": a>>1,
            "ROL a x1": ((a<<1)|(a>>31))&0xFFFFFFFF,
            "ROR a x1": ((a>>1)|(a<<31))&0xFFFFFFFF,
        }

    @staticmethod
    def ip_to_hex(ip):
        try:
            parts = ip.strip().split(".")
            if len(parts) != 4: return "[HATA] Gecersiz IPv4"
            val = sum(int(p)<<(24-8*i) for i,p in enumerate(parts))
            return f"0x{val:08X}  (decimal: {val})"
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def hex_to_ip(h):
        try:
            val = int(h.replace("0x",""), 16)
            return ".".join(str((val>>(24-8*i))&0xFF) for i in range(4))
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def unix_to_human(ts):
        try:
            import datetime
            dt = datetime.datetime.utcfromtimestamp(int(ts))
            return f"UTC: {dt.isoformat()}\nLocal: {datetime.datetime.fromtimestamp(int(ts)).isoformat()}"
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def parse_url(url):
        try:
            p = urllib.parse.urlparse(url); qs = urllib.parse.parse_qs(p.query)
            lines = [f"Scheme  : {p.scheme}", f"Host    : {p.netloc}",
                     f"Path    : {p.path}", f"Query   : {p.query}", "Query Params:"]
            for k, v in qs.items(): lines.append(f"  {k} = {', '.join(v)}")
            return "\n".join(lines)
        except Exception as e: return f"[HATA] {e}"

    @staticmethod
    def find_flags(text):
        patterns = [r"[A-Za-z0-9_]+\{[^\}]+\}", r"flag\{[^\}]+\}", r"CTF\{[^\}]+\}",
                    r"picoCTF\{[^\}]+\}", r"HTB\{[^\}]+\}", r"THM\{[^\}]+\}"]
        found = []
        for p in patterns: found.extend(re.findall(p, text, re.I))
        return list(set(found))

    @staticmethod
    def text_diff(a, b):
        import difflib
        diff = list(difflib.unified_diff(a.splitlines(), b.splitlines(),
                    lineterm="", fromfile="Metin A", tofile="Metin B"))
        return "\n".join(diff) if diff else "Iki metin ayni."


# ═══════════════════════════════════════════════════════════════════════════════
#  SÖZDIZIMI VURGULAYICI
# ═══════════════════════════════════════════════════════════════════════════════

class OutputHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc); self.rules = []
        flag_fmt = QTextCharFormat()
        flag_fmt.setForeground(QColor("#ff4444")); flag_fmt.setFontWeight(QFont.Weight.Bold)
        self.rules.append((re.compile(r"[A-Za-z0-9_]+\{[^\}]+\}"), flag_fmt))
        hex_fmt = QTextCharFormat(); hex_fmt.setForeground(QColor("#00aaff"))
        self.rules.append((re.compile(r"\b[0-9a-fA-F]{8,}\b"), hex_fmt))
        ok_fmt = QTextCharFormat(); ok_fmt.setForeground(QColor("#00ff88"))
        self.rules.append((re.compile(r"✅.*"), ok_fmt))
        err_fmt = QTextCharFormat(); err_fmt.setForeground(QColor("#ff6666"))
        self.rules.append((re.compile(r"(\[HATA\]|❌).*"), err_fmt))
        warn_fmt = QTextCharFormat(); warn_fmt.setForeground(QColor("#ffaa00"))
        self.rules.append((re.compile(r"(⚠️).*"), warn_fmt))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for m in pattern.finditer(text): self.setFormat(m.start(), m.end()-m.start(), fmt)


# ═══════════════════════════════════════════════════════════════════════════════
#  UI STİL SABİTLERİ
# ═══════════════════════════════════════════════════════════════════════════════

STYLE_INPUT  = "background:rgba(0,0,0,150); color:#00ff88; font-family:Consolas; font-size:12px; border:1px solid #1a2a1a; border-radius:5px; padding:4px;"
STYLE_OUTPUT = "background:rgba(0,0,0,170); color:#e0e0e0; font-family:Consolas; font-size:12px; border:1px solid #1a1a2a; border-radius:5px; padding:4px;"
STYLE_COMBO  = "background:rgba(0,0,0,130); color:#00ffcc; border:1px solid #223; padding:5px; border-radius:4px;"
STYLE_NAV_BTN = """
    QPushButton {
        background: transparent; border: none; border-radius: 6px;
        padding: 10px 8px; text-align: left; color: #aaaaaa; font-size: 12px;
    }
    QPushButton:hover   { background: rgba(0,200,255,25); color: #ffffff; }
    QPushButton:checked { background: rgba(0,200,255,60); color: #00ffcc; font-weight: bold; }
"""
STYLE_BTN = lambda color: f"background:{color}; color:white; font-weight:bold; border-radius:5px; padding:7px 14px;"


# ═══════════════════════════════════════════════════════════════════════════════
#  ANA SEKME – CryptoTab
# ═══════════════════════════════════════════════════════════════════════════════

class CryptoTab(QWidget):

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        root = QHBoxLayout(self)
        root.setSpacing(0); root.setContentsMargins(0,0,0,0)

        nav = QFrame()
        nav.setFixedWidth(185)
        nav.setStyleSheet("background:rgba(12,12,20,230); border-right:1px solid rgba(255,255,255,12);")
        nl = QVBoxLayout(nav)
        nl.setContentsMargins(8,12,8,12); nl.setSpacing(3)

        nav_title = QLabel("🔐  CRYPTO\n     TOOLKIT")
        nav_title.setStyleSheet("color:#00ffcc; font-size:13px; font-weight:bold; padding:6px 4px 14px 4px; line-height:1.4;")
        nl.addWidget(nav_title)

        self.stack = QStackedWidget()

        # CTF Hızlı Araçlar sayfası kaldırıldı
        pages = [
            ("⚡  Encoding / Decode",    self._page_encoding()),
            ("🏛️   Klasik Şifreler",      self._page_classic()),
            ("🔗  Zincir Decode",         self._page_chain()),
            ("🔑  Hash & HMAC",           self._page_hash()),
            ("🤖  Otomatik Tespit",       self._page_autodetect()),
            ("🗝️   RSA / Asimetrik",       self._page_rsa()),
        ]

        self.nav_btns = []
        for i, (label, page) in enumerate(pages):
            btn = QPushButton(label)
            btn.setCheckable(True); btn.setStyleSheet(STYLE_NAV_BTN)
            btn.clicked.connect(lambda _, idx=i: self._switch(idx))
            nl.addWidget(btn); self.stack.addWidget(page); self.nav_btns.append(btn)

        nl.addStretch()
        self.nav_btns[0].setChecked(True)
        root.addWidget(nav); root.addWidget(self.stack, 1)

    def _switch(self, idx):
        self.stack.setCurrentIndex(idx)
        for i, b in enumerate(self.nav_btns): b.setChecked(i == idx)

    # ── UI Yardımcılar ────────────────────────────────────────────────────────

    def _inp(self, h=80):
        w = QTextEdit(); w.setFixedHeight(h); w.setStyleSheet(STYLE_INPUT); return w

    def _out(self, h=None, read=True):
        w = QTextEdit(); w.setReadOnly(read)
        if h: w.setFixedHeight(h)
        w.setStyleSheet(STYLE_OUTPUT); OutputHighlighter(w.document()); return w

    def _label(self, text, color="#00ffcc"):
        l = QLabel(text)
        l.setStyleSheet(f"color:{color}; font-weight:bold; font-size:12px;"); return l

    def _btn(self, text, color="#0078d4"):
        b = QPushButton(text); b.setStyleSheet(STYLE_BTN(color)); return b

    def _combo(self, items):
        c = QComboBox(); c.addItems(items); c.setStyleSheet(STYLE_COMBO); return c

    def _lineedit(self, placeholder=""):
        l = QLineEdit(); l.setPlaceholderText(placeholder)
        l.setStyleSheet("background:rgba(0,0,0,130); color:#00ffcc; border:1px solid #223; padding:6px; border-radius:4px;")
        return l

    def _spinbox(self, lo, hi, val):
        s = QSpinBox(); s.setRange(lo, hi); s.setValue(val)
        s.setStyleSheet("background:rgba(0,0,0,120); color:#00ffcc; border:1px solid #333; padding:4px;")
        return s

    def _copy_btn(self, target):
        b = self._btn("📋 Kopyala", "#2a5a2a")
        b.clicked.connect(lambda: QApplication.clipboard().setText(target.toPlainText()))
        return b

    def _swap_btn(self, src, dst):
        b = self._btn("⇅ Swap", "#3a3a2a")
        b.clicked.connect(lambda: src.setPlainText(dst.toPlainText()))
        return b

    def _file_btn(self, target):
        b = self._btn("📂 Dosyadan", "#7a3a00")
        b.clicked.connect(lambda: self._load_file(target))
        return b

    def _load_file(self, edit):
        f, _ = QFileDialog.getOpenFileName(self, "Dosya Sec", "", "Tum Dosyalar (*)",
                                            options=QFileDialog.Option.DontUseNativeDialog)
        if f:
            try:
                with open(f, "rb") as fh: data = fh.read()
                try: edit.setPlainText(safe_decode(data))
                except: edit.setPlainText(data.hex())
            except Exception as e: edit.setPlainText(f"[HATA] {e}")

    def _section_title(self, text):
        l = QLabel(text)
        l.setStyleSheet("font-size:16px; font-weight:bold; color:white; margin-bottom:4px;"); return l

    def _page_shell(self):
        p = QWidget(); l = QVBoxLayout(p)
        l.setContentsMargins(14,14,14,14); l.setSpacing(8); return p, l

    # ─────────────────────────────────────────────────────────────────────────
    #  SAYFA 1 – ENCODING / DECODING
    # ─────────────────────────────────────────────────────────────────────────

    def _page_encoding(self):
        p, l = self._page_shell()
        l.addWidget(self._section_title("Encoding / Decoding"))
        self.enc_inp = self._inp(90); self.enc_out = self._out(90)
        l.addWidget(self._label("Giriş (UTF-8 destekli):")); l.addWidget(self.enc_inp)
        row = QHBoxLayout(); row.addWidget(self._label("Yöntem:"))
        self.enc_combo = self._combo([
            "Base16","Base32","Base45","Base58","Base62","Base64","Base64 URL","Base85","Base91",
            "Hex","Binary","Octal","URL Encode","URL Encode (Tam)","HTML Entity",
            "HTML Decimal","HTML Hex","Morse","ASCII Decimal","Unicode (U+)","Unicode Escape",
            "UUEncode","Quoted-Printable","JWT Decode","Braille","Zero-Width Enc","Whitespace Steg",
            "ROT5","ROT13","ROT18","ROT47","Punycode",
        ])
        row.addWidget(self.enc_combo, 1); l.addLayout(row)
        btn_r = QHBoxLayout()
        enc_b = self._btn("🔒 Encode","#005a9e"); dec_b = self._btn("🔓 Decode","#006b3c")
        enc_b.clicked.connect(self._do_encode); dec_b.clicked.connect(self._do_decode)
        btn_r.addWidget(enc_b); btn_r.addWidget(dec_b)
        btn_r.addWidget(self._file_btn(self.enc_inp)); btn_r.addWidget(self._copy_btn(self.enc_out))
        btn_r.addWidget(self._swap_btn(self.enc_inp, self.enc_out))
        cl = self._btn("🗑 Temizle","#4a1a1a")
        cl.clicked.connect(lambda: (self.enc_inp.clear(), self.enc_out.clear()))
        btn_r.addWidget(cl); l.addLayout(btn_r)
        l.addWidget(self._label("Çıkış:", "#ffaa00")); l.addWidget(self.enc_out)
        l.addWidget(self._label("⚡ Tek-Tık:", "#ffaa00"))
        grid = QGridLayout(); grid.setSpacing(4)
        quick = [
            ("Ters Çevir",  lambda: self.enc_out.setPlainText(self.enc_inp.toPlainText()[::-1])),
            ("BÜYÜK HAR",   lambda: self.enc_out.setPlainText(self.enc_inp.toPlainText().upper())),
            ("küçük harf",  lambda: self.enc_out.setPlainText(self.enc_inp.toPlainText().lower())),
            ("Title Case",  lambda: self.enc_out.setPlainText(self.enc_inp.toPlainText().title())),
            ("Boşluk Sil",  lambda: self.enc_out.setPlainText(self.enc_inp.toPlainText().replace(" ",""))),
            ("Newline Sil", lambda: self.enc_out.setPlainText(self.enc_inp.toPlainText().replace("\n",""))),
            ("Atbash",      lambda: self.enc_out.setPlainText(Cipher.atbash(self.enc_inp.toPlainText()))),
            ("ROT13",       lambda: self.enc_out.setPlainText(Cipher.rot13(self.enc_inp.toPlainText()))),
            ("ROT47",       lambda: self.enc_out.setPlainText(Encoder.rot47(self.enc_inp.toPlainText()))),
            ("ROT18",       lambda: self.enc_out.setPlainText(Encoder.rot18(self.enc_inp.toPlainText()))),
            ("Sayıları Sil",lambda: self.enc_out.setPlainText(re.sub(r"\d","",self.enc_inp.toPlainText()))),
            ("Harf Sil",    lambda: self.enc_out.setPlainText(re.sub(r"[a-zA-Z]","",self.enc_inp.toPlainText()))),
        ]
        for i, (lbl, fn) in enumerate(quick):
            b = QPushButton(lbl)
            b.setStyleSheet("background:rgba(40,40,70,200); color:#ccc; border:1px solid #333; border-radius:4px; padding:5px; font-size:11px;")
            b.clicked.connect(fn); grid.addWidget(b, i//4, i%4)
        l.addLayout(grid); l.addStretch(); return p

    def _do_encode(self):
        t, m = self.enc_inp.toPlainText(), self.enc_combo.currentText()
        enc_map = {
            "Base16": Encoder.base16_enc, "Base32": Encoder.base32_enc,
            "Base45": Encoder.base45_enc, "Base58": Encoder.base58_enc,
            "Base62": Encoder.base62_enc, "Base64": Encoder.base64_enc,
            "Base64 URL": Encoder.base64url_enc, "Base85": Encoder.base85_enc,
            "Base91": Encoder.base91_enc, "Hex": Encoder.hex_enc,
            "Binary": Encoder.binary_enc, "Octal": Encoder.octal_enc,
            "URL Encode": Encoder.url_enc, "URL Encode (Tam)": Encoder.url_enc_full,
            "HTML Entity": Encoder.html_enc, "HTML Decimal": Encoder.html_enc_decimal,
            "HTML Hex": Encoder.html_enc_hex, "Morse": Encoder.morse_enc,
            "ASCII Decimal": Encoder.ascii_enc, "Unicode (U+)": Encoder.unicode_enc,
            "Unicode Escape": Encoder.unicode_escape_enc, "UUEncode": Encoder.uuencode_enc,
            "Quoted-Printable": Encoder.qp_enc, "Braille": Encoder.braille_enc,
            "ROT5": Encoder.rot5, "ROT13": Cipher.rot13, "ROT18": Encoder.rot18,
            "ROT47": Encoder.rot47, "Punycode": Encoder.punycode_enc,
            "Whitespace Steg": Encoder.whitespace_enc,
        }
        fn = enc_map.get(m)
        self.enc_out.setPlainText(fn(t) if fn else f"[HATA] Encode desteklenmiyor: {m}")

    def _do_decode(self):
        t, m = self.enc_inp.toPlainText(), self.enc_combo.currentText()
        dec_map = {
            "Base16": Encoder.base16_dec, "Base32": Encoder.base32_dec,
            "Base45": Encoder.base45_dec, "Base58": Encoder.base58_dec,
            "Base62": Encoder.base62_dec, "Base64": Encoder.base64_dec,
            "Base64 URL": Encoder.base64url_dec, "Base85": Encoder.base85_dec,
            "Base91": Encoder.base91_dec, "Hex": Encoder.hex_dec,
            "Binary": Encoder.binary_dec, "Octal": Encoder.octal_dec,
            "URL Encode": Encoder.url_dec, "URL Encode (Tam)": Encoder.url_dec,
            "HTML Entity": Encoder.html_dec, "HTML Decimal": Encoder.html_dec,
            "HTML Hex": Encoder.html_dec, "Morse": Encoder.morse_dec,
            "ASCII Decimal": Encoder.ascii_dec, "Unicode (U+)": Encoder.unicode_dec,
            "Unicode Escape": Encoder.unicode_escape_dec, "UUEncode": Encoder.uuencode_dec,
            "Quoted-Printable": Encoder.qp_dec, "JWT Decode": Encoder.jwt_decode,
            "Braille": Encoder.braille_dec, "ROT13": Cipher.rot13, "ROT47": Encoder.rot47,
            "ROT18": Encoder.rot18, "ROT5": Encoder.rot5, "Punycode": Encoder.punycode_dec,
            "Whitespace Steg": Encoder.whitespace_dec, "Zero-Width Enc": Encoder.zerowidth_dec,
        }
        fn = dec_map.get(m)
        self.enc_out.setPlainText(fn(t) if fn else f"[HATA] Decode desteklenmiyor: {m}")

    # ─────────────────────────────────────────────────────────────────────────
    #  SAYFA 2 – KLASİK ŞİFRELER
    # ─────────────────────────────────────────────────────────────────────────

    def _page_classic(self):
        p, l = self._page_shell()
        l.addWidget(self._section_title("Klasik Şifreler"))
        self.cls_inp = self._inp(75); self.cls_out = self._out(75)
        l.addWidget(self._label("Giriş:")); l.addWidget(self.cls_inp)
        row = QHBoxLayout(); row.addWidget(self._label("Şifre:"))
        self.cls_combo = self._combo([
            "Caesar","ROT13","ROT47","ROT18","Vigenere","Beaufort","Porta",
            "Atbash","Affine","Rail Fence","Columnar","Playfair",
            "Polybius","Bacon","Tap Code","Nihilist","XOR (metin)","XOR (hex)","RC4","Substitution",
        ])
        self.cls_combo.currentTextChanged.connect(self._update_cipher_params)
        row.addWidget(self.cls_combo, 1); l.addLayout(row)
        self.param_stack = QStackedWidget(); self.param_stack.setFixedHeight(40)
        def _blank():
            w = QWidget(); QHBoxLayout(w); return w
        # 0 Caesar
        cw = QWidget(); ch = QHBoxLayout(cw); ch.setContentsMargins(0,0,0,0)
        ch.addWidget(QLabel("Shift:", styleSheet="color:#888;"))
        self.caesar_shift = self._spinbox(0, 25, 13); ch.addWidget(self.caesar_shift)
        self.param_stack.addWidget(cw)
        for _ in range(3): self.param_stack.addWidget(_blank())
        # 4 Vigenere
        vw = QWidget(); vh = QHBoxLayout(vw); vh.setContentsMargins(0,0,0,0)
        vh.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.vig_key = self._lineedit("SECRET"); vh.addWidget(self.vig_key)
        self.param_stack.addWidget(vw)
        # 5 Beaufort
        bfw = QWidget(); bfh = QHBoxLayout(bfw); bfh.setContentsMargins(0,0,0,0)
        bfh.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.beaufort_key = self._lineedit("KEY"); bfh.addWidget(self.beaufort_key)
        self.param_stack.addWidget(bfw)
        # 6 Porta
        ptw = QWidget(); pth = QHBoxLayout(ptw); pth.setContentsMargins(0,0,0,0)
        pth.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.porta_key = self._lineedit("KEY"); pth.addWidget(self.porta_key)
        self.param_stack.addWidget(ptw)
        self.param_stack.addWidget(_blank())
        # 8 Affine
        aw = QWidget(); ah = QHBoxLayout(aw); ah.setContentsMargins(0,0,0,0)
        ah.addWidget(QLabel("a:", styleSheet="color:#888;"))
        self.aff_a = self._spinbox(1,25,5); ah.addWidget(self.aff_a)
        ah.addWidget(QLabel("b:", styleSheet="color:#888;"))
        self.aff_b = self._spinbox(0,25,8); ah.addWidget(self.aff_b)
        self.param_stack.addWidget(aw)
        # 9 Rail Fence
        rw = QWidget(); rh = QHBoxLayout(rw); rh.setContentsMargins(0,0,0,0)
        rh.addWidget(QLabel("Rails:", styleSheet="color:#888;"))
        self.rf_rails = self._spinbox(2,20,3); rh.addWidget(self.rf_rails)
        self.param_stack.addWidget(rw)
        # 10 Columnar
        colk = QWidget(); colh = QHBoxLayout(colk); colh.setContentsMargins(0,0,0,0)
        colh.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.col_key = self._lineedit("ZEBRA"); colh.addWidget(self.col_key)
        self.param_stack.addWidget(colk)
        # 11 Playfair
        pfw = QWidget(); pfh = QHBoxLayout(pfw); pfh.setContentsMargins(0,0,0,0)
        pfh.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.pf_key = self._lineedit("PLAYFAIR"); pfh.addWidget(self.pf_key)
        self.param_stack.addWidget(pfw)
        # 12 Polybius
        pbw = QWidget(); pbh = QHBoxLayout(pbw); pbh.setContentsMargins(0,0,0,0)
        pbh.addWidget(QLabel("Key (5 harf):", styleSheet="color:#888;"))
        self.pb_key = self._lineedit("ABCDE"); pbh.addWidget(self.pb_key)
        self.param_stack.addWidget(pbw)
        for _ in range(2): self.param_stack.addWidget(_blank())
        # 15 Nihilist
        nihw = QWidget(); nihh = QHBoxLayout(nihw); nihh.setContentsMargins(0,0,0,0)
        nihh.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.nih_key = self._lineedit("KEY"); nihh.addWidget(self.nih_key)
        self.param_stack.addWidget(nihw)
        # 16 XOR metin
        xw = QWidget(); xh = QHBoxLayout(xw); xh.setContentsMargins(0,0,0,0)
        xh.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.xor_key = self._lineedit("key"); xh.addWidget(self.xor_key)
        self.param_stack.addWidget(xw)
        # 17 XOR hex
        xhw = QWidget(); xhh = QHBoxLayout(xhw); xhh.setContentsMargins(0,0,0,0)
        xhh.addWidget(QLabel("Hex Key:", styleSheet="color:#888;"))
        self.xor_hex_key = self._lineedit("deadbeef"); xhh.addWidget(self.xor_hex_key)
        self.param_stack.addWidget(xhw)
        # 18 RC4
        rc4w = QWidget(); rc4h = QHBoxLayout(rc4w); rc4h.setContentsMargins(0,0,0,0)
        rc4h.addWidget(QLabel("Key:", styleSheet="color:#888;"))
        self.rc4_key = self._lineedit("KEY"); rc4h.addWidget(self.rc4_key)
        self.param_stack.addWidget(rc4w)
        # 19 Substitution
        sw = QWidget(); sh2 = QHBoxLayout(sw); sh2.setContentsMargins(0,0,0,0)
        sh2.addWidget(QLabel("26-harf key:", styleSheet="color:#888;"))
        self.sub_key = self._lineedit("QWERTYUIOPASDFGHJKLZXCVBNM"); sh2.addWidget(self.sub_key)
        self.param_stack.addWidget(sw)
        l.addWidget(self.param_stack)
        btn_r = QHBoxLayout()
        eb = self._btn("🔒 Şifrele","#005a9e"); db = self._btn("🔓 Çöz","#006b3c")
        eb.clicked.connect(lambda: self._do_classic(True))
        db.clicked.connect(lambda: self._do_classic(False))
        btn_r.addWidget(eb); btn_r.addWidget(db)
        btn_r.addWidget(self._file_btn(self.cls_inp)); btn_r.addWidget(self._copy_btn(self.cls_out))
        btn_r.addWidget(self._swap_btn(self.cls_inp, self.cls_out)); l.addLayout(btn_r)
        l.addWidget(self._label("Çıkış:", "#ffaa00")); l.addWidget(self.cls_out)
        l.addWidget(self._label("Caesar Brute Force:", "#ffaa00"))
        bf_r = QHBoxLayout()
        self.bf_lang = self._combo(["İngilizce (EN)","Türkçe (TR)"])
        bf_b = self._btn("🔨 Brute Force (26 shift)","#5a3a00")
        bf_b.clicked.connect(self._caesar_brute)
        bf_r.addWidget(self.bf_lang); bf_r.addWidget(bf_b); l.addLayout(bf_r)
        self.brute_out = self._out(140); l.addWidget(self.brute_out)
        l.addStretch(); return p

    def _update_cipher_params(self, name):
        idx = {
            "Caesar":0,"ROT13":1,"ROT47":2,"ROT18":3,"Vigenere":4,"Beaufort":5,"Porta":6,
            "Atbash":7,"Affine":8,"Rail Fence":9,"Columnar":10,"Playfair":11,"Polybius":12,
            "Bacon":13,"Tap Code":14,"Nihilist":15,"XOR (metin)":16,"XOR (hex)":17,
            "RC4":18,"Substitution":19,
        }
        self.param_stack.setCurrentIndex(idx.get(name, 0))

    def _do_classic(self, encrypt=True):
        t = self.cls_inp.toPlainText(); m = self.cls_combo.currentText(); out = ""
        try:
            if m == "Caesar": out = Cipher.caesar(t, self.caesar_shift.value(), decrypt=not encrypt)
            elif m == "ROT13": out = Cipher.rot13(t)
            elif m == "ROT47": out = Encoder.rot47(t)
            elif m == "ROT18": out = Encoder.rot18(t)
            elif m == "Vigenere": out = Cipher.vigenere(t, self.vig_key.text() or "KEY", decrypt=not encrypt)
            elif m == "Beaufort": out = Cipher.beaufort(t, self.beaufort_key.text() or "KEY")
            elif m == "Porta": out = Cipher.porta(t, self.porta_key.text() or "KEY", decrypt=not encrypt)
            elif m == "Atbash": out = Cipher.atbash(t)
            elif m == "Affine":
                if encrypt: out = Cipher.affine_enc(t, self.aff_a.value(), self.aff_b.value())
                else: out = Cipher.affine_dec(t, self.aff_a.value(), self.aff_b.value())
            elif m == "Rail Fence":
                if encrypt: out = Cipher.rail_fence_enc(t, self.rf_rails.value())
                else: out = Cipher.rail_fence_dec(t, self.rf_rails.value())
            elif m == "Columnar":
                key = self.col_key.text() or "KEY"
                if encrypt: out = Cipher.columnar_enc(t, key)
                else: out = Cipher.columnar_dec(t, key)
            elif m == "Playfair": out = Cipher.playfair(t, self.pf_key.text() or "KEY", decrypt=not encrypt)
            elif m == "Polybius":
                if encrypt: out = Cipher.polybius_enc(t, self.pb_key.text() or "ABCDE")
                else: out = Cipher.polybius_dec(t, self.pb_key.text() or "ABCDE")
            elif m == "Bacon":
                if encrypt: out = Cipher.bacon_enc(t)
                else: out = Cipher.bacon_dec(t)
            elif m == "Tap Code":
                if encrypt: out = Cipher.tap_enc(t)
                else: out = Cipher.tap_dec(t)
            elif m == "Nihilist":
                key = self.nih_key.text() or "KEY"
                if encrypt: out = Cipher.nihilist_enc(t, key)
                else: out = Cipher.nihilist_dec(t, key)
            elif m == "XOR (metin)": out = Cipher.xor_text(t, self.xor_key.text() or "x")
            elif m == "XOR (hex)": out = Cipher.xor_hex(t, self.xor_hex_key.text() or "00")
            elif m == "RC4":
                if encrypt: out = Cipher.rc4_text(t, self.rc4_key.text() or "KEY")
                else: out = Cipher.rc4_hex(t, self.rc4_key.text() or "KEY")
            elif m == "Substitution":
                out = Cipher.substitution(t, self.sub_key.text() or "ABCDEFGHIJKLMNOPQRSTUVWXYZ", decrypt=not encrypt)
        except Exception as e: out = f"[HATA] {e}"
        self.cls_out.setPlainText(out)

    def _caesar_brute(self):
        t = self.cls_inp.toPlainText()
        lang = "TR" if "TR" in self.bf_lang.currentText() else "EN"
        scores = FreqAnalysis.caesar_score(t, lang)
        lines = [f"{'ROT':>4}  {'Chi²':>8}  Sonuç", "─"*70]
        for shift, chi, decoded in scores[:26]:
            flag = " ← FLAG!" if _looks_like_flag(decoded) else ""
            lines.append(f"ROT {shift:>2}  χ²={chi:>8.1f}  {decoded[:55]}{flag}")
        self.brute_out.setPlainText("\n".join(lines))

    # ─────────────────────────────────────────────────────────────────────────
    #  SAYFA 3 – ZİNCİR DECODE
    # ─────────────────────────────────────────────────────────────────────────

    def _page_chain(self):
        p, l = self._page_shell()
        l.addWidget(self._section_title("Zincir Decode (Çok Adımlı)"))
        l.addWidget(QLabel("Sırayla uygulanacak adımları gir (virgülle ayır):\nÖr: base64, hex, rot13",
                           styleSheet="color:#888; font-size:11px;"))
        self.chain_inp = self._inp(70)
        l.addWidget(self._label("Giriş:")); l.addWidget(self.chain_inp)
        step_r = QHBoxLayout(); step_r.addWidget(self._label("Adımlar (virgülle):"))
        self.chain_steps = self._lineedit("base64, hex, rot13")
        step_r.addWidget(self.chain_steps, 1); l.addLayout(step_r)
        run_b = self._btn("▶ Zinciri Çalıştır","#005a9e")
        run_b.clicked.connect(self._do_chain); l.addWidget(run_b)
        l.addWidget(self._label("Adım Adım Sonuçlar:", "#ffaa00"))
        self.chain_out = self._out(); l.addWidget(self.chain_out, 1); return p

    def _do_chain(self):
        t = self.chain_inp.toPlainText()
        if not t.strip():
            self.chain_out.setPlainText("⚠️ Giriş boş!"); return
        raw_methods = self.chain_steps.text()
        methods = [s.strip() for s in raw_methods.split(",") if s.strip()]
        if not methods:
            self.chain_out.setPlainText("⚠️ En az bir adım gir! Örnek: base64, hex, rot13"); return
        steps = Cipher.chain_decode(t, methods)
        lines = [f"{'═'*60}", f"  Başlangıç: {t[:70]}", f"{'═'*60}", ""]
        success_count = 0
        for i, (step, src, result) in enumerate(steps):
            is_error = result.startswith("⚠️") or result.startswith("❓")
            is_flag  = _looks_like_flag(result)
            status = "🚩 FLAG!" if is_flag else ("❌ HATA" if is_error else "✅")
            lines.append(f"  Adım {i+1}: [{step.upper()}]  {status}")
            lines.append(f"  {'─'*50}")
            lines.append(f"  Giriş  → {src[:75]}")
            if is_error:
                lines.append(f"  Sonuç  → {result}")
            else:
                lines.append(f"  Çıkış  → {result[:75]}")
                success_count += 1
            if is_flag:
                lines.append(f"  🚩🚩🚩  FLAG BULUNDU: {result}  🚩🚩🚩")
            lines.append("")
        lines.append(f"{'═'*60}")
        lines.append(f"  {success_count}/{len(steps)} adım başarılı")
        if success_count == len(steps):
            lines.append(f"  Son Sonuç: {steps[-1][2][:100]}")
        self.chain_out.setPlainText("\n".join(lines))

    # ─────────────────────────────────────────────────────────────────────────
    #  SAYFA 4 – HASH & HMAC  (Tam implementasyon)
    # ─────────────────────────────────────────────────────────────────────────

    def _page_hash(self):
        p, l = self._page_shell()
        l.addWidget(self._section_title("Hash & HMAC"))
        self.hash_inp = self._inp(75)
        l.addWidget(self._label("Giriş Metni:")); l.addWidget(self.hash_inp)
        row = QHBoxLayout()
        row.addWidget(self._label("Algoritma:"))
        self.hash_algo = self._combo(Hasher.ALGOS + ["crc32","adler32"])
        row.addWidget(self.hash_algo, 1)
        row.addWidget(self._label("HMAC Key (opsiyonel):"))
        self.hmac_key = self._lineedit("bos birakırsan normal hash")
        row.addWidget(self.hmac_key, 1); l.addLayout(row)
        btn_r = QHBoxLayout()
        for lbl, fn, col in [
            ("# Hash Hesapla",       self._do_hash,       "#005a9e"),
            ("📊 Tüm Algoritmalar",  self._hash_all,      "#3a5a00"),
            ("📂 Dosyadan Hash",     self._hash_file,     "#5a3a00"),
            ("🔍 Hash Tanımla",
             lambda: self.hash_out.setPlainText(Hasher.identify_hash(self.hash_inp.toPlainText())),
             "#3a3a5a"),
            ("🎯 Hash Karşılaştır",
             lambda: self.hash_out.setPlainText(
                 Hasher.multi_hash_compare(self.hash_inp.toPlainText(), self.hmac_key.text())),
             "#5a003a"),
        ]:
            b = self._btn(lbl, col); b.clicked.connect(fn); btn_r.addWidget(b)
        l.addLayout(btn_r)
        l.addWidget(self._label("PBKDF2:", "#ffaa00"))
        pb_r = QHBoxLayout()
        pb_r.addWidget(QLabel("Salt:", styleSheet="color:#888;"))
        self.pbkdf2_salt = self._lineedit("random_salt"); pb_r.addWidget(self.pbkdf2_salt)
        pb_r.addWidget(QLabel("İterasyon:", styleSheet="color:#888;"))
        self.pbkdf2_iter = self._spinbox(1000, 1000000, 100000); pb_r.addWidget(self.pbkdf2_iter)
        pb_b = self._btn("PBKDF2-SHA256","#5a3a5a")
        pb_b.clicked.connect(lambda: self.hash_out.setPlainText(
            Hasher.pbkdf2(self.hash_inp.toPlainText(), self.pbkdf2_salt.text(), self.pbkdf2_iter.value())))
        pb_r.addWidget(pb_b); l.addLayout(pb_r)
        l.addWidget(self._label("Sonuç:", "#ffaa00"))
        self.hash_out = self._out(); l.addWidget(self.hash_out, 1); return p

    def _do_hash(self):
        t, alg, key = self.hash_inp.toPlainText(), self.hash_algo.currentText(), self.hmac_key.text()
        if key: self.hash_out.setPlainText(Hasher.hmac_sign(t, key, alg))
        else: self.hash_out.setPlainText(Hasher.hash_text(t, alg))

    def _hash_all(self):
        t = self.hash_inp.toPlainText()
        res = Hasher.hash_all(t)
        self.hash_out.setPlainText("\n".join(f"{k:<12} {v}" for k, v in res.items()))

    def _hash_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Dosya Sec", "", "Tum Dosyalar (*)",
                                            options=QFileDialog.Option.DontUseNativeDialog)
        if f:
            alg = self.hash_algo.currentText()
            self.hash_out.setPlainText(f"{alg}: {Hasher.hash_file(f, alg)}\nDosya: {f}")

    # ─────────────────────────────────────────────────────────────────────────
    #  SAYFA 5 – OTOMATİK TESPİT
    # ─────────────────────────────────────────────────────────────────────────

    def _page_autodetect(self):
        p, l = self._page_shell()
        l.addWidget(self._section_title("Otomatik Tespit & Çözme"))
        l.addWidget(QLabel("Şifreli/kodlu metni yapıştır → ne olduğunu tahmin edip çözmeye çalışır",
                           styleSheet="color:#888; font-size:11px;"))
        self.auto_inp = self._inp(85)
        l.addWidget(self._label("Giriş:")); l.addWidget(self.auto_inp)
        btn_r = QHBoxLayout()
        d_b = self._btn("🔍 Tespit Et","#005a9e")
        a_b = self._btn("🤖 Hepsini Dene","#3a5a00")
        f_b = self._btn("🚩 Flag Ara","#5a0000")
        d_b.clicked.connect(self._do_detect)
        a_b.clicked.connect(self._do_try_all)
        f_b.clicked.connect(self._find_flags)
        btn_r.addWidget(d_b); btn_r.addWidget(a_b); btn_r.addWidget(f_b)
        btn_r.addWidget(self._file_btn(self.auto_inp)); l.addLayout(btn_r)
        self.auto_out = self._out()
        l.addWidget(self._label("Sonuçlar:", "#ffaa00")); l.addWidget(self.auto_out, 1); return p

    def _do_detect(self):
        t = self.auto_inp.toPlainText(); hints = AutoDetect.detect(t)
        colors = {"yüksek":"#00ff88","orta":"#ffaa00","düşük":"#ff6666","bilinmiyor":"#888"}
        html_lines = ["<b style='color:#00ffcc'>Tespit Sonuçları:</b><br><br>"]
        for name, conf in hints:
            c = colors.get(conf, "#888")
            html_lines.append(f"<span style='color:{c}'>● {name}</span> <span style='color:#555'>({conf})</span><br>")
        self.auto_out.setHtml("".join(html_lines))

    def _do_try_all(self):
        t = self.auto_inp.toPlainText(); results = AutoDetect.try_all_encodings(t)
        if not results:
            self.auto_out.setPlainText("Otomatik cozum basarisiz. Manuel deneme gerekli."); return
        lines = ["Başarılı Decode Sonuçları:\n" + "═"*60]
        for method, decoded in results.items():
            flag_mark = " ← 🚩 FLAG!" if _looks_like_flag(decoded) else ""
            lines.append(f"\n[{method}]{flag_mark}"); lines.append(decoded[:200])
        self.auto_out.setPlainText("\n".join(lines))

    def _find_flags(self):
        t = self.auto_inp.toPlainText(); flags = CTFTools.find_flags(t)
        if flags: self.auto_out.setPlainText("🚩 Bulunan Flag'ler:\n\n" + "\n".join(flags))
        else: self.auto_out.setPlainText("Standart flag formati bulunamadi.")

    # ─────────────────────────────────────────────────────────────────────────
    #  SAYFA 6 – DERİN ÇÖZME  (Tam implementasyon)
    # ─────────────────────────────────────────────────────────────────────────

    def _page_rsa(self):
        p, l = self._page_shell()
        l.addWidget(self._section_title("RSA / Asimetrik Şifreleme"))
        grid = QGridLayout()
        labels = ["p (Asal)","q (Asal)","e (Public Exp)","n (Modulus)","d (Private Exp)"]
        self.rsa_fields = {}
        for i, lbl in enumerate(labels):
            r, c = divmod(i, 2)
            grid.addWidget(QLabel(lbl+":", styleSheet="color:#888;"), r, c*2)
            le = self._lineedit(lbl)
            if lbl == "e (Public Exp)": le.setText("65537")
            self.rsa_fields[lbl] = le; grid.addWidget(le, r, c*2+1)
        l.addLayout(grid)
        btn_r1 = QHBoxLayout()
        calc_b = self._btn("⚙️ d ve n Hesapla","#5a3a00")
        wiener_b = self._btn("🔍 Wiener Analizi","#3a3a5a")
        calc_b.clicked.connect(self._rsa_calc); wiener_b.clicked.connect(self._rsa_wiener)
        btn_r1.addWidget(calc_b); btn_r1.addWidget(wiener_b); l.addLayout(btn_r1)
        l.addWidget(self._label("Mesaj / Şifreli Metin (Sayısal):"))
        self.rsa_msg = self._inp(55); l.addWidget(self.rsa_msg)
        btn_r2 = QHBoxLayout()
        for lbl, fn, col in [
            ("🔒 Şifrele (m^e mod n)",   lambda: self._rsa_crypto(True),  "#005a9e"),
            ("🔓 Deşifre (c^d mod n)",   lambda: self._rsa_crypto(False), "#006b3c"),
            ("📝 Metin → Int",            self._rsa_text2int,             "#3a3a00"),
            ("🔍 Küçük n Faktör",         self._rsa_factor,               "#5a003a"),
            ("⚡ Small-e Saldırı",        self._rsa_small_e,              "#3a5a00"),
        ]:
            b = self._btn(lbl, col); b.clicked.connect(fn); btn_r2.addWidget(b)
        l.addLayout(btn_r2)
        l.addWidget(self._label("Common Modulus Attack:", "#ffaa00"))
        cm_r = QHBoxLayout()
        self.cm_c1 = self._lineedit("c1"); self.cm_c2 = self._lineedit("c2")
        self.cm_e1 = self._lineedit("e1"); self.cm_e2 = self._lineedit("e2")
        for lbl, w in [("c1:",self.cm_c1),("c2:",self.cm_c2),("e1:",self.cm_e1),("e2:",self.cm_e2)]:
            cm_r.addWidget(QLabel(lbl)); cm_r.addWidget(w)
        cm_b = self._btn("Saldır","#5a3a3a"); cm_b.clicked.connect(self._rsa_common_mod)
        cm_r.addWidget(cm_b); l.addLayout(cm_r)
        l.addWidget(self._label("Sonuç:", "#ffaa00"))
        self.rsa_out = self._out(); l.addWidget(self.rsa_out, 1); return p

    def _rsa_get(self, key):
        try: return int(self.rsa_fields[key].text().strip())
        except: return None

    def _rsa_calc(self):
        p = self._rsa_get("p (Asal)"); q = self._rsa_get("q (Asal)"); e = self._rsa_get("e (Public Exp)")
        if not all([p, q, e]): self.rsa_out.setPlainText("[HATA] p, q ve e girilmeli"); return
        try:
            n = p*q; d = RSATools.calc_d(p, q, e)
            self.rsa_fields["n (Modulus)"].setText(str(n))
            self.rsa_fields["d (Private Exp)"].setText(str(d))
            phi = (p-1)*(q-1)
            self.rsa_out.setPlainText(f"n   = {n}\nd   = {d}\nphi = {phi}\n\nDogrulama: e*d mod phi = {(e*d)%phi} (1 olmali)")
        except Exception as ex: self.rsa_out.setPlainText(f"[HATA] {ex}")

    def _rsa_crypto(self, encrypt):
        try:
            msg = int(self.rsa_msg.toPlainText().strip()); n = self._rsa_get("n (Modulus)")
            if encrypt:
                e = self._rsa_get("e (Public Exp)"); res = RSATools.encrypt(msg, e, n)
                self.rsa_out.setPlainText(f"Şifreli (c):\n{res}")
            else:
                d = self._rsa_get("d (Private Exp)"); res = RSATools.decrypt(msg, d, n)
                self.rsa_out.setPlainText(f"Mesaj (int):\n{res}\n\nMetin:\n{RSATools.int_to_text(res)}")
        except Exception as ex: self.rsa_out.setPlainText(f"[HATA] {ex}")

    def _rsa_text2int(self):
        self.rsa_out.setPlainText(f"Metin → Int:\n{RSATools.text_to_int(self.rsa_msg.toPlainText())}")

    def _rsa_factor(self):
        n = self._rsa_get("n (Modulus)")
        if not n: self.rsa_out.setPlainText("[HATA] n girilmeli"); return
        p, q = RSATools.factor_small_n(n)
        if p:
            self.rsa_fields["p (Asal)"].setText(str(p)); self.rsa_fields["q (Asal)"].setText(str(q))
            self.rsa_out.setPlainText(f"✅ Faktorler bulundu!\np = {p}\nq = {q}")
        else: self.rsa_out.setPlainText("❌ 10^7'ye kadar faktor bulunamadi.\nFactorDB.com'a bak.")

    def _rsa_wiener(self):
        e = self._rsa_get("e (Public Exp)"); n = self._rsa_get("n (Modulus)")
        if not all([e, n]): self.rsa_out.setPlainText("[HATA] e ve n girilmeli"); return
        self.rsa_out.setPlainText(RSATools.wiener_attack_hint(e, n))

    def _rsa_small_e(self):
        try:
            c = int(self.rsa_msg.toPlainText().strip()); e = self._rsa_get("e (Public Exp)") or 3
            self.rsa_out.setPlainText(RSATools.small_e_attack(c, e))
        except Exception as ex: self.rsa_out.setPlainText(f"[HATA] {ex}")

    def _rsa_common_mod(self):
        try:
            c1 = int(self.cm_c1.text()); c2 = int(self.cm_c2.text())
            e1 = int(self.cm_e1.text()); e2 = int(self.cm_e2.text())
            n = self._rsa_get("n (Modulus)")
            self.rsa_out.setPlainText(RSATools.common_modulus_attack(c1, c2, e1, e2, n))
        except Exception as ex: self.rsa_out.setPlainText(f"[HATA] {ex}")

# ═══════════════════════════════════════════════════════════════════════════════
# CTF Hızlı Araçlar sayfası kaldırıldı (v3.1)
# ═══════════════════════════════════════════════════════════════════════════════