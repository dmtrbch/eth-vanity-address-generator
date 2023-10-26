
from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey
from sha3 import keccak_256
from random import randint

# private_key_t = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

eth_addr = ''
base16INT = 0

# x = eth_addr.startswith("0x0000")

while True:
    private_key = ''

    for x in range(64):
        value = randint(0, 15)
        private_key += '{0:x}'.format(value)

    base16INT = int(private_key, 16)

    hex_value = hex(base16INT)

    cv = Curve.get_curve('secp256k1')
    pv_key = ECPrivateKey(base16INT, cv)
    pu_key = pv_key.get_public_key()

    # equivalent alternative for illustration:
    # concat_x_y = bytes.fromhex(hex(pu_key.W.x)[2:] + hex(pu_key.W.y)[2:])

    concat_x_y = pu_key.W.x.to_bytes(
        32, byteorder='big') + pu_key.W.y.to_bytes(32, byteorder='big')
    eth_addr = '0x' + keccak_256(concat_x_y).digest()[-20:].hex()

    x = eth_addr.startswith("0x0000")
    if x:
        break

print('private key: ', hex(base16INT))
print('eth_address: ', eth_addr)
