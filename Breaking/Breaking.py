import serpent
import itertools as it
import collections
import time
from bitstring import BitArray

def to_bytes(data):
    return bytes(data, 'utf-8')

def bytes_to_bits(byte_string):
    bits = BitArray(bytes=byte_string)
    return bits.bin

def bits_to_string(bits):
    characters = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    output_string = ''.join(characters)
    return output_string

def brute_force(src_text, enc_text):
    symbols = []
    for j in range(65,91):
        symbols.append(chr(j))
    for j in range(97,123):
        symbols.append(chr(j))
    for j in range(48,58):
        symbols.append(chr(j))        
    perm_set = it.product(symbols, repeat=16)
    c = 1
    for i in perm_set:
        print(f"{c} " + str(time.perf_counter()))
        dec = serpent.Serpent(to_bytes("".join(i))).decrypt(enc_text)
        print(f"{c} " + str(time.perf_counter()))
        try:
            data = dec.decode("utf-8")
        except:
            data = None
        if data == src_text:
            print("Ключ: " + "".join(i))
            break
        c += 1

testdata = 'Proverka shifra!'
#testdata = 'Everything is ai'
testkey = 'Jhnstc3SBxLQi4Aj'
#testkey = 'AAAAAAAAAAAAAAAz'
enc = serpent.Serpent(to_bytes(testkey)).encrypt(to_bytes(testdata))
#brute_force(testdata, enc)

def linear_method(cipher):
    freq = collections.Counter(cipher)
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)   
    freq_letters = 'etaoinshrdlcumwfgypbvkxjqz'
    replace_dict = {}
    for i in range(len(sorted_freq)):
        replace_dict[sorted_freq[i][0]] = freq_letters[i]
    decrypted_text = ''.join([replace_dict.get(char) for char in cipher])
    return decrypted_text

print(linear_method(bits_to_string(bytes_to_bits(enc))))

def differential_method(data1, data2):
    testkey = 'Jhnstc3SBxLQi4Aj'
    enc1 = bytes_to_bits(serpent.Serpent(to_bytes(testkey)).encrypt(to_bytes(data1)))
    enc2 = bytes_to_bits(serpent.Serpent(to_bytes(testkey)).encrypt(to_bytes(data2)))
    diff = []
    for i in range(len(enc1)):
        diff_bit = int(enc1[i]) ^ int(enc2[i])
        diff.append(str(diff_bit))
    return "".join(diff)

testdata1 = 'Everyone sees the world in ones own way. I shall not live in ban'
testdata2 = 'Everyone sees tte world in ones own way. I shall not live in ban'
#print(differential_method(testdata1, testdata2))