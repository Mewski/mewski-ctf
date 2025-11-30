from PIL import Image

img = Image.open("dist/secret.png")
pixels = img.load()

bits = []
for y in range(1000, 1100):
    for x in range(1000, 1100):
        r, g, b = pixels[x, y]
        bits.append(r & 1)

data = bytes(
    int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits) - 7, 8)
)

print(data.decode("utf-8", errors="replace"))

# Hero{M4YB3_TH3_L4ST_LSB?}
