try:
    import psyco
    psyco.full()
except ImportError:
    pass

import binascii
import base64
import struct
import sys

block_size = 16
key_size = 32

class Serpent:
    
    def __init__(self, key=None):
        if key:
            self.set_key(key)

    def set_key(self, key):
        key_len = len(key)
        if key_len % 4:
            raise KeyError("key not a multiple of 4")
        if key_len > 32:
            raise KeyError("key_len > 32")
        
        self.key_context = [0] * 140
        
        key_word32 = [0] * 32
        i = 0
        while key:
            key_word32[i] = struct.unpack("<L", key[0:4])[0]
            key = key[4:]
            i += 1

        set_key(self.key_context, key_word32, key_len)     
        
    def decrypt(self, block):
        if len(block) % 16:
            raise ValueError("block size must be a multiple of 16")

        plaintext = b''
        
        while block:
            a, b, c, d = struct.unpack("<4L", block[:16])
            temp = [a, b, c, d]
            decrypt(self.key_context, temp)
            plaintext += struct.pack("<4L", *temp)
            block = block[16:]
            
        return plaintext
        
    def encrypt(self, block):
        if len(block) % 16:
            raise ValueError("block size must be a multiple of 16")

        ciphertext = b''
        
        while block:
            a, b, c, d = struct.unpack("<4L", block[0:16])
            temp = [a, b, c, d]
            encrypt(self.key_context, temp)
            ciphertext += struct.pack("<4L", *temp)
            block = block[16:]
            
        return ciphertext

WORD_BIGENDIAN = 0
if sys.byteorder == 'big':
    WORD_BIGENDIAN = 1

def rotr32(x, n):
    return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)

def rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def byteswap32(x):
    return ((x & 0xff) << 24) | (((x >> 8) & 0xff) << 16) | \
           (((x >> 16) & 0xff) << 8) | ((x >> 24) & 0xff)

def set_key(l_key, key, key_len):
    key_len *= 8
    if key_len > 256:
        return False
    
    i = 0
    lk = (key_len + 31) / 32
    while i < lk:
        l_key[i] = key[i]
        if WORD_BIGENDIAN:
            l_key[i] = byteswap32(key[i])
        i += 1
        
    if key_len < 256:
        while i < 8:
            l_key[i] = 0
            i += 1
        i = int(key_len / 32)
        lk = 1 << (key_len % 32)
        l_key[i] = (l_key[i] & (lk - 1)) | lk
    for i in range(132):
        lk = l_key[i] ^ l_key[i + 3] ^ l_key[i + 5] ^ l_key[i + 7] ^ 0x9e3779b9 ^ i
        l_key[i + 8] = ((lk << 11) & 0xFFFFFFFF) | (lk >> 21)

    key = l_key
    for i in range(4):
        a = key[4 * (i * 8) +  8]
        b = key[4 * (i * 8) +  9]
        c = key[4 * (i * 8) + 10]
        d = key[4 * (i * 8) + 11]        
        t1 = a ^ c     
        t2 = d ^ t1    
        t3 = a & t2    
        t4 = d ^ t3    
        t5 = b & t4    
        g = t2 ^ t5    
        t7 = a | g     
        t8 = b | d     
        t11 = a | d    
        t9 = t4 & t7   
        f = t8 ^ t9    
        t12 = b ^ t11  
        t13 = g ^ t9   
        t15 = t3 ^ t8  
        h = t12 ^ t13  
        t16 = c & t15  
        e = t12 ^ t16
        key[4 * (i * 8) +  8] = e
        key[4 * (i * 8) +  9] = f
        key[4 * (i * 8) + 10] = g
        key[4 * (i * 8) + 11] = h
        a = key[4 * (i * 8 + 1) +  8]
        b = key[4 * (i * 8 + 1) +  9]
        c = key[4 * (i * 8 + 1) + 10]
        d = key[4 * (i * 8 + 1) + 11]
        t1 = (~a) % 0x100000000        
        t2 = b ^ d     
        t3 = c & t1    
        t13 = d | t1   
        e = t2 ^ t3    
        t5 = c ^ t1    
        t6 = c ^ e     
        t7 = b & t6    
        t10 = e | t5   
        h = t5 ^ t7    
        t9 = d | t7    
        t11 = t9 & t10 
        t14 = t2 ^ h   
        g = a ^ t11    
        t15 = g ^ t13  
        f = t14 ^ t15
        key[4 * (i * 8 + 1) +  8] = e
        key[4 * (i * 8 + 1) +  9] = f
        key[4 * (i * 8 + 1) + 10] = g
        key[4 * (i * 8 + 1) + 11] = h
        a = key[4 * (i * 8 + 2) +  8]
        b = key[4 * (i * 8 + 2) +  9]
        c = key[4 * (i * 8 + 2) + 10]
        d = key[4 * (i * 8 + 2) + 11]
        t1 = (~a) % 0x100000000        
        t2 = b ^ t1    
        t3 = a | t2    
        t4 = d | t2    
        t5 = c ^ t3    
        g = d ^ t5     
        t7 = b ^ t4    
        t8 = t2 ^ g    
        t9 = t5 & t7   
        h = t8 ^ t9    
        t11 = t5 ^ t7  
        f = h ^ t11    
        t13 = t8 & t11 
        e = t5 ^ t13
        key[4 * (i * 8 + 2) +  8] = e
        key[4 * (i * 8 + 2) +  9] = f
        key[4 * (i * 8 + 2) + 10] = g
        key[4 * (i * 8 + 2) + 11] = h
        a = key[4 * (i * 8 + 3) +  8]
        b = key[4 * (i * 8 + 3) +  9]
        c = key[4 * (i * 8 + 3) + 10]
        d = key[4 * (i * 8 + 3) + 11]
        t1 = a ^ d     
        t2 = a & d     
        t3 = c ^ t1    
        t6 = b & t1    
        t4 = b ^ t3    
        t10 = (~t3) % 0x100000000      
        h = t2 ^ t4    
        t7 = a ^ t6    
        t14 = (~t7) % 0x100000000      
        t8 = c | t7    
        t11 = t3 ^ t7  
        g = t4 ^ t8    
        t12 = h & t11  
        f = t10 ^ t12  
        e = t12 ^ t14
        key[4 * (i * 8 + 3) +  8] = e
        key[4 * (i * 8 + 3) +  9] = f
        key[4 * (i * 8 + 3) + 10] = g
        key[4 * (i * 8 + 3) + 11] = h
        a = key[4 * (i * 8 + 4) +  8]
        b = key[4 * (i * 8 + 4) +  9]
        c = key[4 * (i * 8 + 4) + 10]
        d = key[4 * (i * 8 + 4) + 11]
        t1 = (~c) % 0x100000000        
        t2 = b ^ c     
        t3 = b | t1    
        t4 = d ^ t3    
        t5 = a & t4    
        t7 = a ^ d     
        h = t2 ^ t5    
        t8 = b ^ t5    
        t9 = t2 | t8   
        t11 = d & t3   
        f = t7 ^ t9    
        t12 = t5 ^ f   
        t15 = t1 | t4  
        t13 = h & t12  
        g = t11 ^ t13  
        t16 = t12 ^ g  
        e = t15 ^ t16
        key[4 * (i * 8 + 4) +  8] = e
        key[4 * (i * 8 + 4) +  9] = f
        key[4 * (i * 8 + 4) + 10] = g
        key[4 * (i * 8 + 4) + 11] = h
        a = key[4 * (i * 8 + 5) +  8]
        b = key[4 * (i * 8 + 5) +  9]
        c = key[4 * (i * 8 + 5) + 10]
        d = key[4 * (i * 8 + 5) + 11]
        t1 = (~a) % 0x100000000        
        t2 = a ^ d     
        t3 = b ^ t2    
        t4 = t1 | t2   
        t5 = c ^ t4    
        f = b ^ t5     
        t13 = (~t5) % 0x100000000      
        t7 = t2 | f    
        t8 = d ^ t7    
        t9 = t5 & t8   
        g = t3 ^ t9    
        t11 = t5 ^ t8  
        e = g ^ t11    
        t14 = t3 & t11 
        h = t13 ^ t14
        key[4 * (i * 8 + 5) +  8] = e
        key[4 * (i * 8 + 5) +  9] = f
        key[4 * (i * 8 + 5) + 10] = g
        key[4 * (i * 8 + 5) + 11] = h
        a = key[4 * (i * 8 + 6) +  8]
        b = key[4 * (i * 8 + 6) +  9]
        c = key[4 * (i * 8 + 6) + 10]
        d = key[4 * (i * 8 + 6) + 11]
        t1 = (~a) % 0x100000000        
        t2 = a ^ b     
        t3 = a ^ d     
        t4 = c ^ t1    
        t5 = t2 | t3   
        e = t4 ^ t5    
        t7 = d & e     
        t8 = t2 ^ e    
        t10 = t1 | e   
        f = t7 ^ t8    
        t11 = t2 | t7  
        t12 = t3 ^ t10 
        t14 = b ^ t7   
        g = t11 ^ t12  
        t15 = f & t12  
        h = t14 ^ t15
        key[4 * (i * 8 + 6) +  8] = e
        key[4 * (i * 8 + 6) +  9] = f
        key[4 * (i * 8 + 6) + 10] = g
        key[4 * (i * 8 + 6) + 11] = h
        a = key[4 * (i * 8 + 7) +  8]
        b = key[4 * (i * 8 + 7) +  9]
        c = key[4 * (i * 8 + 7) + 10]
        d = key[4 * (i * 8 + 7) + 11]
        t1 = a ^ d     
        t2 = d & t1    
        t3 = c ^ t2    
        t4 = b | t3    
        h = t1 ^ t4    
        t6 = (~b) % 0x100000000        
        t7 = t1 | t6   
        e = t3 ^ t7    
        t9 = a & e     
        t10 = t1 ^ t6  
        t11 = t4 & t10 
        g = t9 ^ t11   
        t13 = a ^ t3   
        t14 = t10 & g  
        f = t13 ^ t14
        key[4 * (i * 8 + 7) +  8] = e
        key[4 * (i * 8 + 7) +  9] = f
        key[4 * (i * 8 + 7) + 10] = g
        key[4 * (i * 8 + 7) + 11] = h
    a = key[4 * 32 +  8]
    b = key[4 * 32 +  9]
    c = key[4 * 32 + 10]
    d = key[4 * 32 + 11]
    t1 = a ^ c     
    t2 = d ^ t1    
    t3 = a & t2    
    t4 = d ^ t3    
    t5 = b & t4    
    g = t2 ^ t5    
    t7 = a | g     
    t8 = b | d     
    t11 = a | d    
    t9 = t4 & t7   
    f = t8 ^ t9    
    t12 = b ^ t11  
    t13 = g ^ t9   
    t15 = t3 ^ t8  
    h = t12 ^ t13  
    t16 = c & t15  
    e = t12 ^ t16
    key[4 * 32 +  8] = e
    key[4 * 32 +  9] = f
    key[4 * 32 + 10] = g
    key[4 * 32 + 11] = h

def encrypt(key, in_blk):
    a = in_blk[0]
    b = in_blk[1]
    c = in_blk[2]
    d = in_blk[3]
    if WORD_BIGENDIAN:
        a = byteswap32(a)
        b = byteswap32(b)
        c = byteswap32(c)
        d = byteswap32(d)

    for i in range(4):
        a ^= key[4 * (i * 8) +  8]
        b ^= key[4 * (i * 8) +  9]
        c ^= key[4 * (i * 8) + 10]
        d ^= key[4 * (i * 8) + 11]
        t1 = a ^ d     
        t2 = a & d     
        t3 = c ^ t1    
        t6 = b & t1    
        t4 = b ^ t3    
        t10 = (~t3) % 0x100000000      
        h = t2 ^ t4    
        t7 = a ^ t6    
        t14 = (~t7) % 0x100000000      
        t8 = c | t7    
        t11 = t3 ^ t7  
        g = t4 ^ t8    
        t12 = h & t11  
        f = t10 ^ t12  
        e = t12 ^ t14
        e = rotl32(e, 13)
        g = rotl32(g, 3)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        h = rotl32(h, 7)
        f = rotl32(f, 1)
        e ^= f ^ h
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e = rotl32(e, 5)
        g = rotl32(g, 22)
        e ^= key[4 * (i * 8 + 1) +  8]
        f ^= key[4 * (i * 8 + 1) +  9]
        g ^= key[4 * (i * 8 + 1) + 10]
        h ^= key[4 * (i * 8 + 1) + 11]
        t1 = (~e) % 0x100000000        
        t2 = f ^ t1    
        t3 = e | t2    
        t4 = h | t2    
        t5 = g ^ t3    
        c = h ^ t5     
        t7 = f ^ t4    
        t8 = t2 ^ c    
        t9 = t5 & t7   
        d = t8 ^ t9    
        t11 = t5 ^ t7  
        b = d ^ t11    
        t13 = t8 & t11 
        a = t5 ^ t13
        a = rotl32(a, 13)
        c = rotl32(c, 3)
        d ^= c ^ ((a << 3) & 0xFFFFFFFF)
        b ^= a ^ c
        d = rotl32(d, 7)
        b = rotl32(b, 1)
        a ^= b ^ d
        c ^= d ^ ((b << 7) & 0xFFFFFFFF)
        a = rotl32(a, 5)
        c = rotl32(c, 22)
        a ^= key[4 * (i * 8 + 2) +  8]
        b ^= key[4 * (i * 8 + 2) +  9]
        c ^= key[4 * (i * 8 + 2) + 10]
        d ^= key[4 * (i * 8 + 2) + 11]
        t1 = (~a) % 0x100000000        
        t2 = b ^ d     
        t3 = c & t1    
        t13 = d | t1   
        e = t2 ^ t3    
        t5 = c ^ t1    
        t6 = c ^ e     
        t7 = b & t6    
        t10 = e | t5   
        h = t5 ^ t7    
        t9 = d | t7    
        t11 = t9 & t10 
        t14 = t2 ^ h   
        g = a ^ t11    
        t15 = g ^ t13  
        f = t14 ^ t15
        e = rotl32(e, 13)
        g = rotl32(g, 3)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        h = rotl32(h, 7)
        f = rotl32(f, 1)
        e ^= f ^ h
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e = rotl32(e, 5)
        g = rotl32(g, 22)
        e ^= key[4 * (i * 8 + 3) +  8]
        f ^= key[4 * (i * 8 + 3) +  9]
        g ^= key[4 * (i * 8 + 3) + 10]
        h ^= key[4 * (i * 8 + 3) + 11]
        t1 = e ^ g     
        t2 = h ^ t1    
        t3 = e & t2    
        t4 = h ^ t3    
        t5 = f & t4    
        c = t2 ^ t5    
        t7 = e | c     
        t8 = f | h     
        t11 = e | h    
        t9 = t4 & t7   
        b = t8 ^ t9    
        t12 = f ^ t11  
        t13 = c ^ t9   
        t15 = t3 ^ t8  
        d = t12 ^ t13  
        t16 = g & t15  
        a = t12 ^ t16
        a = rotl32(a, 13)
        c = rotl32(c, 3)
        d ^= c ^ ((a << 3) & 0xFFFFFFFF)
        b ^= a ^ c
        d = rotl32(d, 7)
        b = rotl32(b, 1)
        a ^= b ^ d
        c ^= d ^ ((b << 7) & 0xFFFFFFFF)
        a = rotl32(a, 5)
        c = rotl32(c, 22)
        a ^= key[4 * (i * 8 + 4) +  8]
        b ^= key[4 * (i * 8 + 4) +  9]
        c ^= key[4 * (i * 8 + 4) + 10]
        d ^= key[4 * (i * 8 + 4) + 11]
        t1 = a ^ d     
        t2 = d & t1    
        t3 = c ^ t2    
        t4 = b | t3    
        h = t1 ^ t4    
        t6 = (~b) % 0x100000000        
        t7 = t1 | t6   
        e = t3 ^ t7    
        t9 = a & e     
        t10 = t1 ^ t6  
        t11 = t4 & t10 
        g = t9 ^ t11   
        t13 = a ^ t3   
        t14 = t10 & g  
        f = t13 ^ t14
        e = rotl32(e, 13)
        g = rotl32(g, 3)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        h = rotl32(h, 7)
        f = rotl32(f, 1)
        e ^= f ^ h
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e = rotl32(e, 5)
        g = rotl32(g, 22)
        e ^= key[4 * (i * 8 + 5) +  8]
        f ^= key[4 * (i * 8 + 5) +  9]
        g ^= key[4 * (i * 8 + 5) + 10]
        h ^= key[4 * (i * 8 + 5) + 11]
        t1 = (~e) % 0x100000000        
        t2 = e ^ f     
        t3 = e ^ h     
        t4 = g ^ t1    
        t5 = t2 | t3   
        a = t4 ^ t5    
        t7 = h & a     
        t8 = t2 ^ a    
        t10 = t1 | a   
        b = t7 ^ t8    
        t11 = t2 | t7  
        t12 = t3 ^ t10 
        t14 = f ^ t7   
        c = t11 ^ t12  
        t15 = b & t12  
        d = t14 ^ t15
        a = rotl32(a, 13)
        c = rotl32(c, 3)
        d ^= c ^ ((a << 3) & 0xFFFFFFFF)
        b ^= a ^ c
        d = rotl32(d, 7)
        b = rotl32(b, 1)
        a ^= b ^ d
        c ^= d ^ ((b << 7) & 0xFFFFFFFF)
        a = rotl32(a, 5)
        c = rotl32(c, 22)
        a ^= key[4 * (i * 8 + 6) +  8]
        b ^= key[4 * (i * 8 + 6) +  9]
        c ^= key[4 * (i * 8 + 6) + 10]
        d ^= key[4 * (i * 8 + 6) + 11]
        t1 = (~a) % 0x100000000        
        t2 = a ^ d     
        t3 = b ^ t2    
        t4 = t1 | t2   
        t5 = c ^ t4    
        f = b ^ t5     
        t13 = (~t5) % 0x100000000      
        t7 = t2 | f    
        t8 = d ^ t7    
        t9 = t5 & t8   
        g = t3 ^ t9    
        t11 = t5 ^ t8  
        e = g ^ t11    
        t14 = t3 & t11 
        h = t13 ^ t14
        e = rotl32(e, 13)
        g = rotl32(g, 3)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        h = rotl32(h, 7)
        f = rotl32(f, 1)
        e ^= f ^ h
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e = rotl32(e, 5)
        g = rotl32(g, 22)
        e ^= key[4 * (i * 8 + 7) +  8]
        f ^= key[4 * (i * 8 + 7) +  9]
        g ^= key[4 * (i * 8 + 7) + 10]
        h ^= key[4 * (i * 8 + 7) + 11]
        t1 = (~g) % 0x100000000        
        t2 = f ^ g     
        t3 = f | t1    
        t4 = h ^ t3    
        t5 = e & t4    
        t7 = e ^ h     
        d = t2 ^ t5    
        t8 = f ^ t5    
        t9 = t2 | t8   
        t11 = h & t3   
        b = t7 ^ t9    
        t12 = t5 ^ b   
        t15 = t1 | t4  
        t13 = d & t12  
        c = t11 ^ t13  
        t16 = t12 ^ c  
        a = t15 ^ t16
        if i != 3:
            a = rotl32(a, 13)
            c = rotl32(c, 3)
            d ^= c ^ ((a << 3) & 0xFFFFFFFF)
            b ^= a ^ c
            d = rotl32(d, 7)
            b = rotl32(b, 1)
            a ^= b ^ d
            c ^= d ^ ((b << 7) & 0xFFFFFFFF)
            a = rotl32(a, 5)
            c = rotl32(c, 22)
    a ^= key[4 * 32 +  8]
    b ^= key[4 * 32 +  9]
    c ^= key[4 * 32 + 10]
    d ^= key[4 * 32 + 11]
    if WORD_BIGENDIAN:
        a = byteswap32(a)
        b = byteswap32(b)
        c = byteswap32(c)
        d = byteswap32(d)    
    in_blk[0] = a
    in_blk[1] = b
    in_blk[2] = c
    in_blk[3] = d

def decrypt(key, in_blk):
    a = in_blk[0]
    b = in_blk[1]
    c = in_blk[2]
    d = in_blk[3]
    if WORD_BIGENDIAN:
        a = byteswap32(a)
        b = byteswap32(b)
        c = byteswap32(c)
        d = byteswap32(d)
    
    for i in range(4, 0, -1):
        a ^= key[4 * (i * 8) +  8]
        b ^= key[4 * (i * 8) +  9]
        c ^= key[4 * (i * 8) + 10]
        d ^= key[4 * (i * 8) + 11]
        if i != 4:
            c = rotr32(c, 22)
            a = rotr32(a, 5)
            c ^= d ^ ((b << 7) & 0xFFFFFFFF)
            a ^= b ^ d
            d = rotr32(d, 7)
            b = rotr32(b, 1)
            d ^= c ^ ((a << 3) & 0xFFFFFFFF)
            b ^= a ^ c
            c = rotr32(c, 3)
            a = rotr32(a, 13)
        t1 = a & b     
        t2 = a | b     
        t3 = c | t1    
        t4 = d & t2    
        h = t3 ^ t4    
        t6 = (~d) % 0x100000000        
        t7 = b ^ t4    
        t8 = h ^ t6    
        t11 = c ^ t7   
        t9 = t7 | t8   
        f = a ^ t9     
        t12 = d | f    
        e = t11 ^ t12  
        t14 = a & h    
        t15 = t3 ^ f   
        t16 = e ^ t14  
        g = t15 ^ t16
        e ^= key[4 * (i * 8 - 1) +  8]
        f ^= key[4 * (i * 8 - 1) +  9]
        g ^= key[4 * (i * 8 - 1) + 10]
        h ^= key[4 * (i * 8 - 1) + 11]
        g = rotr32(g, 22)
        e = rotr32(e, 5)
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e ^= f ^ h
        h = rotr32(h, 7)
        f = rotr32(f, 1)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        g = rotr32(g, 3)
        e = rotr32(e, 13)
        t1 = (~e) % 0x100000000        
        t2 = e ^ f     
        t3 = g ^ t2    
        t4 = g | t1    
        t5 = h ^ t4    
        t13 = h & t1   
        b = t3 ^ t5    
        t7 = t3 & t5   
        t8 = t2 ^ t7   
        t9 = f | t8    
        d = t5 ^ t9    
        t11 = f | d    
        a = t8 ^ t11   
        t14 = t3 ^ t11 
        c = t13 ^ t14
        a ^= key[4 * (i * 8 - 2) +  8]
        b ^= key[4 * (i * 8 - 2) +  9]
        c ^= key[4 * (i * 8 - 2) + 10]
        d ^= key[4 * (i * 8 - 2) + 11]
        c = rotr32(c, 22)
        a = rotr32(a, 5)
        c ^= d ^ ((b << 7) & 0xFFFFFFFF)
        a ^= b ^ d
        d = rotr32(d, 7)
        b = rotr32(b, 1)
        d ^= c ^ ((a << 3) & 0xFFFFFFFF)
        b ^= a ^ c
        c = rotr32(c, 3)
        a = rotr32(a, 13)
        t1 = (~c) % 0x100000000        
        t2 = b & t1    
        t3 = d ^ t2    
        t4 = a & t3    
        t5 = b ^ t1    
        h = t4 ^ t5    
        t7 = b | h     
        t8 = a & t7    
        f = t3 ^ t8    
        t10 = a | d    
        t11 = t1 ^ t7  
        e = t10 ^ t11  
        t13 = a ^ c    
        t14 = b & t10  
        t15 = t4 | t13 
        g = t14 ^ t15
        e ^= key[4 * (i * 8 - 3) +  8]
        f ^= key[4 * (i * 8 - 3) +  9]
        g ^= key[4 * (i * 8 - 3) + 10]
        h ^= key[4 * (i * 8 - 3) + 11]
        g = rotr32(g, 22)
        e = rotr32(e, 5)
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e ^= f ^ h
        h = rotr32(h, 7)
        f = rotr32(f, 1)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        g = rotr32(g, 3)
        e = rotr32(e, 13)
        t1 = g ^ h     
        t2 = g | h     
        t3 = f ^ t2    
        t4 = e & t3    
        b = t1 ^ t4    
        t6 = e ^ h     
        t7 = f | h     
        t8 = t6 & t7   
        d = t3 ^ t8    
        t10 = (~e) % 0x100000000       
        t11 = g ^ d    
        t12 = t10 | t11
        a = t3 ^ t12   
        t14 = g | t4   
        t15 = t7 ^ t14 
        t16 = d | t10  
        c = t15 ^ t16
        a ^= key[4 * (i * 8 - 4) +  8]
        b ^= key[4 * (i * 8 - 4) +  9]
        c ^= key[4 * (i * 8 - 4) + 10]
        d ^= key[4 * (i * 8 - 4) + 11]
        c = rotr32(c, 22)
        a = rotr32(a, 5)
        c ^= d ^ ((b << 7) & 0xFFFFFFFF)
        a ^= b ^ d
        d = rotr32(d, 7)
        b = rotr32(b, 1)
        d ^= c ^ ((a << 3) & 0xFFFFFFFF)
        b ^= a ^ c
        c = rotr32(c, 3)
        a = rotr32(a, 13)
        t1 = b ^ c     
        t2 = b | c     
        t3 = a ^ c     
        t7 = a ^ d     
        t4 = t2 ^ t3   
        t5 = d | t4    
        t9 = t2 ^ t7   
        e = t1 ^ t5    
        t8 = t1 | t5   
        t11 = a & t4   
        g = t8 ^ t9    
        t12 = e | t9   
        f = t11 ^ t12  
        t14 = a & g    
        t15 = t2 ^ t14 
        t16 = e & t15  
        h = t4 ^ t16
        e ^= key[4 * (i * 8 - 5) +  8]
        f ^= key[4 * (i * 8 - 5) +  9]
        g ^= key[4 * (i * 8 - 5) + 10]
        h ^= key[4 * (i * 8 - 5) + 11]
        g = rotr32(g, 22)
        e = rotr32(e, 5)
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e ^= f ^ h
        h = rotr32(h, 7)
        f = rotr32(f, 1)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        g = rotr32(g, 3)
        e = rotr32(e, 13)
        t1 = f ^ h     
        t2 = (~t1) % 0x100000000       
        t3 = e ^ g     
        t4 = g ^ t1    
        t7 = e | t2    
        t5 = f & t4    
        t8 = h ^ t7    
        t11 = (~t4) % 0x100000000      
        a = t3 ^ t5    
        t9 = t3 | t8   
        t14 = h & t11  
        d = t1 ^ t9    
        t12 = a | d    
        b = t11 ^ t12  
        t15 = t3 ^ t12 
        c = t14 ^ t15
        a ^= key[4 * (i * 8 - 6) +  8]
        b ^= key[4 * (i * 8 - 6) +  9]
        c ^= key[4 * (i * 8 - 6) + 10]
        d ^= key[4 * (i * 8 - 6) + 11]
        c = rotr32(c, 22)
        a = rotr32(a, 5)
        c ^= d ^ ((b << 7) & 0xFFFFFFFF)
        a ^= b ^ d
        d = rotr32(d, 7)
        b = rotr32(b, 1)
        d ^= c ^ ((a << 3) & 0xFFFFFFFF)
        b ^= a ^ c
        c = rotr32(c, 3)
        a = rotr32(a, 13)
        t1 = a ^ d     
        t2 = a & b     
        t3 = b ^ c     
        t4 = a ^ t3    
        t5 = b | d     
        t7 = c | t1    
        h = t4 ^ t5    
        t8 = b ^ t7    
        t11 = (~t2) % 0x100000000      
        t9 = t4 & t8   
        f = t1 ^ t9    
        t13 = t9 ^ t11 
        t12 = h & f    
        g = t12 ^ t13  
        t15 = a & d    
        t16 = c ^ t13  
        e = t15 ^ t16
        e ^= key[4 * (i * 8 - 7) +  8]
        f ^= key[4 * (i * 8 - 7) +  9]
        g ^= key[4 * (i * 8 - 7) + 10]
        h ^= key[4 * (i * 8 - 7) + 11]
        g = rotr32(g, 22)
        e = rotr32(e, 5)
        g ^= h ^ ((f << 7) & 0xFFFFFFFF)
        e ^= f ^ h
        h = rotr32(h, 7)
        f = rotr32(f, 1)
        h ^= g ^ ((e << 3) & 0xFFFFFFFF)
        f ^= e ^ g
        g = rotr32(g, 3)
        e = rotr32(e, 13)
        t1 = (~e) % 0x100000000
        t2 = e ^ f
        t3 = t1 | t2
        t4 = h ^ t3
        t7 = h & t2
        t5 = g ^ t4
        t8 = t1 ^ t7
        c = t2 ^ t5
        t11 = e & t4
        t9 = c & t8
        t14 = t5 ^ t8
        b = t4 ^ t9
        t12 = t5 | b
        d = t11 ^ t12
        a = d ^ t14
    a ^= key[4 * 0 +  8]
    b ^= key[4 * 0 +  9]
    c ^= key[4 * 0 + 10]
    d ^= key[4 * 0 + 11]
    if WORD_BIGENDIAN:
        a = byteswap32(a)
        b = byteswap32(b)
        c = byteswap32(c)
        d = byteswap32(d)    
    in_blk[0] = a
    in_blk[1] = b
    in_blk[2] = c
    in_blk[3] = d

def serpent_cbc_encrypt(key, data, iv=b'\x00'*16):
    out = b""
    last = iv
    for i in range(int((len(data)/16))):
        temp = data[i*16:(i+1)*16]
        to_encode = b""
        for j in range(4):
            temp1 = struct.unpack_from('<I', temp[j*4:])[0]
            temp2 = struct.unpack_from('<I', last[j*4:])[0]
            to_encode += struct.pack('<I',((temp1 ^ temp2) & 0xffffffff))
        last= Serpent(key).encrypt(to_encode)
        out += last
    return out

def serpent_cbc_decrypt(key,data,iv=b'\x00'*16):
    out2 = b""
    last = iv
    for i in range(int((len(data)/16))):
        temp = Serpent(key).decrypt(data[i*16:(i+1)*16])
        to_decode = b""
        for j in range(4):
            temp1 = struct.unpack_from('<I', temp[j*4:])[0]
            temp2 = struct.unpack_from('<I', last[j*4:])[0]
            to_decode += struct.pack('<I',((temp1 ^ temp2) & 0xffffffff))
        out2 += to_decode
        last = data[i*16:(i+1)*16]
    return out2