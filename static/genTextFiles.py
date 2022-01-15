import os
import sys
import random

dir_out = sys.argv[1]


def RandomByte():
    x = random.randint(0, 61)
    if x < 10:
        return chr(x+ord('0'))
    elif x < 36:
        return chr(x-10+ord('A'))
    else:
        return chr(x-36+ord('a'))


def genWebpageBySize(size):
    with open('./%s/%dKB' % (dir_out, size), 'w') as fout:
        array = []
        for i in range(0, size*1024):
            if (i+1) % 256 == 0:
                ch = '\n'
            elif (i+1) % 32 == 0:
                ch = ','
            else:
                ch = RandomByte()
            array.append(ch)
        fout.write(''.join(array))


size = 1
for i in range(0, 13):
    genWebpageBySize(size)
    print(i)
    size <<= 1


# '1KB','2KB','4KB','8KB','16KB','32KB','64KB','128KB','256KB','512KB','1MB','2MB','4MB','8MB'
