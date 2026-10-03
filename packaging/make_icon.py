"""Generate packaging/netguard.ico (shield + check mark) at all Windows icon sizes."""
import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))


def draw(size):
    s = size / 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=int(56 * s), fill=(6, 15, 34, 255))
    shield = [(128, 28), (212, 60), (212, 126), (200, 172), (168, 210), (128, 232),
              (88, 210), (56, 172), (44, 126), (44, 60)]
    d.polygon([(x * s, y * s) for x, y in shield], fill=(47, 129, 247, 255))
    inner = [(128, 52), (190, 76), (190, 126), (180, 162), (156, 192), (128, 208),
             (100, 192), (76, 162), (66, 126), (66, 76)]
    d.polygon([(x * s, y * s) for x, y in inner], fill=(17, 44, 104, 255))
    d.line([(92 * s, 128 * s), (118 * s, 154 * s), (166 * s, 102 * s)], fill=(255, 255, 255, 255),
           width=max(2, int(18 * s)), joint="curve")
    return img


if __name__ == "__main__":
    big = draw(256)
    big.save(os.path.join(HERE, "netguard.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    big.save(os.path.join(HERE, "netguard.png"))
    print("wrote netguard.ico")
