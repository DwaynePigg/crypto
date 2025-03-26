from adfgvx import Adfgvx
from crypto import batched

grid = batched('NA1C3H8TB2OME5WRPD4F6G7I9J0KLQSUVXYZ', 6)
a = Adfgvx(grid, 'PRIVACY')
c = a.encrypt('attackat1200am')
print(c, len(c))
print(a.decrypt(c))