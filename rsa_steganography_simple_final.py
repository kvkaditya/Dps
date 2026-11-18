from PIL import Image, ImageDraw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def make_image(method):
    img = Image.new('L', (300, 200), 255)
    draw = ImageDraw.Draw(img)
    draw.rectangle((30, 30, 270, 170), outline=0, width=5)
    draw.ellipse((85, 65, 150, 130), fill=120)
    if method == 'binary':
        img = img.point(lambda p: 255 if p >= 128 else 0).convert('1')
    img.save('original.png')
    return img


def hide_message(img, secret, method):
    data = len(secret).to_bytes(4, 'big') + secret
    bits = ''.join(f'{b:08b}' for b in data)
    pixels = list(img.getdata())

    for i, bit in enumerate(bits):
        if method == 'binary':
            pixels[i] = 255 if bit == '1' else 0
        else:
            pixels[i] = (pixels[i] & 254) | int(bit)

    changed = sum(a != b for a, b in zip(img.getdata(), pixels))
    img.putdata(pixels)
    img.save('hidden.png')
    return changed


def get_message(method):
    img = Image.open('hidden.png')
    if method == 'binary':
        bits = ''.join('1' if p else '0' for p in img.getdata())
    else:
        bits = ''.join(str(p & 1) for p in img.getdata())

    size = int(bits[:32], 2)
    bits = bits[32:32 + size * 8]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


method = input('Choose method (binary / lsb): ').strip().lower()
if method not in ('binary', 'lsb'):
    raise ValueError('Choose binary or lsb')

message = input('Enter your secret message: ')
if len(message.encode('utf-8')) > 190:
    raise ValueError('Message must be at most 190 bytes')

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
settings = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(), label=None
)

secret = key.public_key().encrypt(message.encode('utf-8'), settings)
img = make_image(method)
changed = hide_message(img, secret, method)
found = get_message(method)
result = key.decrypt(found, settings).decode('utf-8')

print('Method:', method)
print('Original message:', message)
print('Encrypted data:', secret.hex())
print('Pixels changed:', changed)
print('Saved: original.png and hidden.png')
print('Recovered message:', result)
print('Success:', result == message)
