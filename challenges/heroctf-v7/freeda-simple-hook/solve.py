a = [
    52,
    88,
    27,
    32,
    27,
    186,
    96,
    109,
    45,
    202,
    42,
    125,
    25,
    134,
    159,
    69,
    47,
    142,
    192,
    184,
    13,
    19,
    139,
    173,
    59,
    129,
    0,
    158,
    165,
    188,
    13,
    62,
    74,
    184,
    58,
    75,
    172,
    202,
    66,
]


def java_hashcode(s):
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def to_signed32(n):
    n = n & 0xFFFFFFFF
    if n >= 0x80000000:
        return n - 0x100000000
    return n


def to_unsigned32(n):
    return n & 0xFFFFFFFF


def rotate_left(val, n):
    val = val & 0xFFFFFFFF
    n = n % 32
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


def seed():
    h1 = java_hashcode("com.heroctf.freeda1.MainActivity")
    h2 = java_hashcode("com.heroctf.freeda1.utils.CheckFlag")
    hashCode = to_signed32((h1 ^ (-1056969150)) ^ h2)
    rotated = rotate_left(to_unsigned32(hashCode), 7)
    mult = to_signed32(rotated * (-1640531527))
    return to_signed32(hashCode ^ mult)


def get_flag():
    s = seed()
    iArr = list(range(39))

    i2 = to_signed32((-1515870811) ^ s)
    for i3 in range(38, -1, -1):
        i4 = to_signed32(i2 ^ (i2 << 13))
        i5 = to_signed32(i4 ^ (to_unsigned32(i4) >> 17))
        i2 = to_signed32(i5 ^ (i5 << 5))
        unsignedLong = to_unsigned32(i2) % (i3 + 1)
        iArr[i3], iArr[unsignedLong] = iArr[unsignedLong], iArr[i3]

    bArr = bytearray(39)
    for i7 in range(39):
        i8 = ((a[iArr[i7]] & 255) - i7) & 255
        i9 = (to_unsigned32(s) >> 27) & 7
        rotated_byte = ((i8 << (8 - i9)) | (i8 >> i9)) & 255
        xor_val = (to_unsigned32(s) >> ((i7 & 3) * 8)) & 255
        bArr[i7] = rotated_byte ^ xor_val

    return bArr.decode("utf-8")


flag = get_flag()
print(flag)

# Hero{1_H0P3_Y0U_D1DN'T_S7A71C_4N4LYZ3D}
