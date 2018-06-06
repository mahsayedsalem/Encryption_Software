
# coding: utf-8

# # Security Project
# 
# This notebook is an implementation for the AES algorithm written in vanilla python3 and some ciphers using pycipher library
# 
# <h3> Problem Statement: </h3>
# 
# An encryption ready-to-production software which uses encryption algorithms to encrypt plain texts using multiple encryption algorithms, one of which is written from scratch while the other encryptions are produced using an encryption library. 
# 
# 
# <h4>Steps: </h4>
# 1.	Take a plain message and a key
# 2.	Divide the plain message into 128bits and pad the final remaining. .
# 3.	Translate them into Hex
# 4.	Get the first RoundKey:
#     •	Divide the key into 4 parts
#     •	Left-shift to the last part
#     •	Byte Substitution to the output of the last step
#     •	Add Round constant to the output of the last step
# 5.	Xor between the first part of the key and the output of the last step
# 6.	Xor between the second part of the key and the output of the last step
# 7.	Xor between the third part of the key and the output of the last step
# 8.	Xor between the fourth part of the key and the output of the last step
# 9.	Concat the output of the last four steps and this gives us the first RoundKey.
# 10.	Use this Roundkey as a key to iterate the steps again till we get 5 RoundKeys.
# 11.	Xor between state message and the first roundkey
# 12.	In each round we make:
#     •	Substitution
#     •	Shift-Rows
#     •	Mix-Columns
#     •	Add RoundKey
# 13.	In the final step we make all the steps but the mix columns, then we concat the message and this is our encrypted message. 
# 
# 
# <h4>Functions Developed for AES: </h4>
# 1.	lettersToHex(message): <i>Translate strings into hexadecimals.</i>
# 2.	split_string(message): <i>split strings into arrays of 128bits.</i>
# 3.	format_arr_hex(arr_message): <i>format the array.</i>
# 4.	RoundKeys(key): <i>produces the roundkeys needed.</i>
# 5.	Xor_hex(arr_str1, arr_str2): <i>xor operations between two arrays of strings.</i>
# 6.	Sbox_number(stringx): <i>produces the place of the value needed from the sbox array.</i>
# 7.	AddRoundKey(message,key): <i>Adds Roundkey to message.</i>
# 8.	shiftRows(single_state): <i>Shifts rows of a state.</i>
# 9.	galois_mult(a, b): <i>Copied function that makes galois multiplication.</i>
# 10.	MixColumns(state): <i>Mixes columns of a state.</i>
# 11.	Aes_encrypt(message,key): <i>The main aes algorithm utilizing the previous functions.</i>
# 
# <h4>Ciphers Algorithms: </h4>
# 1.	AES
# 2.	Ceasar
# 3.	Playfair
# 4.	Vigenere
# 5.  Autokey
# 6.  Railfence
# 
# 
# <h4>Technologies: </h4>
# 1.	Python.
# 2.  pycipher.
# 
# <h4>Install: </h4>
# 1.	Python3.
# 2.  Anaconda.
# 3.  pycipher (pip install pycipher)

# In[1]:


Sbox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            )


# In[2]:


def letterstohex(message):
    hex_coded = message.encode('utf-8')
    hex_coded = hex_coded.hex()
    n = 2
    hex_coded=[hex_coded[i:i+n] for i in range(0, len(hex_coded), n)]
    return hex_coded


# In[3]:


#A function to divide the message into 128 bits, and fill the last part
#with zero paddings.
def split_string(message):
    
    arr_message = []
    
    while message:
        
        if len(message)<16:
            message = format(message, '16')
            arr_message.append(message)
            break
        else:
            arr_message.append(message[:16])
            if len(message)>16:
                message = message[16:]  
            elif len(message)==16:
                break
              
    return arr_message


# In[4]:


def format_arr_hex(arr_message):
    
    arr_hex = []
    
    for i in range(0, len(arr_message)):
        
        arr_hex.append(letterstohex(arr_message[i]))
        
    return arr_hex


# In[5]:


import copy

def RoundKeys(key):
    
    RoundKeys = []
    rc= ['1', '2', '4', '8', '10', '20', '40', '80', '1b', '36']
    RoundKeys.append(key)
    
    for i in range(0, 10):
        
        k_1st = key[:4]
        k_2nd = key[4:8]
        k_3rd = key[8:12]
        k_4th = key[12:16]
        
        g_k_4th = copy.deepcopy(k_4th)

        g_k_4th = [g_k_4th[1], g_k_4th[2], g_k_4th[3], g_k_4th[0]]
        
        for m in range(0, 4):
            g_k_4th[m][0] = format(Sbox[sbox_number(g_k_4th[m][0])], '02x')
           
        
        result = hex(int(g_k_4th[0][0], 16) ^ int(rc[i], 16))
        #rc *= 2
        test = str(result[2:])
        if len(test) < 2:
            test = '0' + test
        g_k_4th[0][0] = test
        k_5th = xor_hex(k_1st, g_k_4th)
        k_6th = xor_hex(k_5th, k_2nd)
        k_7th = xor_hex(k_6th, k_3rd)
        k_8th = xor_hex(k_7th, k_4th)
        rk = [k_5th[0], k_5th[1], k_5th[2], k_5th[3], k_6th[0], k_6th[1], k_6th[2], k_6th[3], k_7th[0], k_7th[1], k_7th[2], k_7th[3], k_8th[0], k_8th[1], k_8th[2], k_8th[3]] 
        
        for ra in range(0, len(rk)):
            if len(rk[ra][0])<2:
                rk[ra][0] = '0' + rk[ra][0]  
        
        RoundKeys.append(rk)
        key = copy.deepcopy(rk)
        
    return RoundKeys


# In[6]:


def xor_hex(arr_str1, arr_str2):
    
    result0 = hex(int(arr_str1[0][0], 16) ^ int(arr_str2[0][0], 16))
    result1 = hex(int(arr_str1[1][0], 16) ^ int(arr_str2[1][0], 16))
    result2 = hex(int(arr_str1[2][0], 16) ^ int(arr_str2[2][0], 16))
    result3 = hex(int(arr_str1[3][0], 16) ^ int(arr_str2[3][0], 16))
    
    ret = [[str(result0[2:])], [str(result1[2:])], [str(result2[2:])], [str(result3[2:])]]
    return ret


# In[7]:


def sbox_number(stringx):
    
    if len(stringx) < 2:
        
         stringx = '0' + stringx
            
    sp = list(stringx)
    
    sbox_number_1 = 0
    sbox_number_2 = 0
    
    if sp[0]=='0' or sp[0]=='1' or sp[0]=='2' or sp[0]=='3' or sp[0]=='4' or sp[0]=='5' or sp[0]=='6' or sp[0]=='7' or sp[0]=='8' or sp[0]=='9':
        sbox_number_1 = int(sp[0])
        
    elif sp[0] == 'a':
        sbox_number_1 = 10
        
    elif sp[0] == 'b':
        sbox_number_1 = 11
        
    elif sp[0] == 'c':
        sbox_number_1 = 12
        
    elif sp[0] == 'd':
        sbox_number_1 = 13
        
    elif sp[0] == 'e':
        sbox_number_1 = 14
        
    elif sp[0] == 'f':
        sbox_number_1 = 15
        
    if sp[1]=='0' or sp[1]=='1' or sp[1]=='2' or sp[1]=='3' or sp[1]=='4' or sp[1]=='5' or sp[1]=='6' or sp[1]=='7' or sp[1]=='8' or sp[1]=='9':
        sbox_number_2 = int(sp[1])
        
    elif sp[1] == 'a':
        sbox_number_2 = 10
        
    elif sp[1] == 'b':
        sbox_number_2 = 11
        
    elif sp[1] == 'c':
        sbox_number_2 = 12
        
    elif sp[1] == 'd':
        sbox_number_2 = 13
        
    elif sp[1] == 'e':
        sbox_number_2 = 14
        
    elif sp[1] == 'f':
        sbox_number_2 = 15
    
    return sbox_number_1 * 16 + sbox_number_2


# In[8]:


def AddRoundKey(message,key):
    
    result0 = hex(int(message[0][0], 16) ^ int(key[0][0], 16))
    result1 = hex(int(message[1][0], 16) ^ int(key[1][0], 16))
    result2 = hex(int(message[2][0], 16) ^ int(key[2][0], 16))
    result3 = hex(int(message[3][0], 16) ^ int(key[3][0], 16))
    result4 = hex(int(message[4][0], 16) ^ int(key[4][0], 16))
    result5 = hex(int(message[5][0], 16) ^ int(key[5][0], 16))
    result6 = hex(int(message[6][0], 16) ^ int(key[6][0], 16))
    result7 = hex(int(message[7][0], 16) ^ int(key[7][0], 16))
    result8 = hex(int(message[8][0], 16) ^ int(key[8][0], 16))
    result9 = hex(int(message[9][0], 16) ^ int(key[9][0], 16))
    result1m = hex(int(message[10][0], 16) ^ int(key[10][0], 16))
    result2m = hex(int(message[11][0], 16) ^ int(key[11][0], 16))
    result3m = hex(int(message[12][0], 16) ^ int(key[12][0], 16))
    result4m = hex(int(message[13][0], 16) ^ int(key[13][0], 16))
    result5m = hex(int(message[14][0], 16) ^ int(key[14][0], 16))
    result6m = hex(int(message[15][0], 16) ^ int(key[15][0], 16))
    ret = [[str(result0[2:])], [str(result1[2:])], [str(result2[2:])], 
           [str(result3[2:])], [str(result4[2:])], [str(result5[2:])], 
           [str(result6[2:])], [str(result7[2:])], [str(result8[2:])], 
           [str(result9[2:])], [str(result1m[2:])], [str(result2m[2:])], 
           [str(result3m[2:])], [str(result4m[2:])], [str(result5m[2:])], 
           [str(result6m[2:])]]
           
           
    return ret


# In[9]:


def shiftRows(single_state):
    
    rows = []
    for i in range(0, 4):
        for j in range(i, 16, 4):
            rows.append(single_state[j][0])
    
    r0 = rows[0:4]
    r1 = rows[4:8]
    r2 = rows[8:12]
    r3 = rows[12:16]
    
    r0 = [[r0[0]], [r0[1]], [r0[2]], [r0[3]]]
    r1 = [[r1[1]], [r1[2]], [r1[3]], [r1[0]]]
    r2 = [[r2[2]], [r2[3]], [r2[0]], [r2[1]]]
    r3 = [[r3[3]], [r3[0]], [r3[1]], [r3[2]]]
    
    
    shifted_rows = r0 + r1 + r2 + r3
    
    rows_back = []
    
    for i in range(0, 4):
        for j in range(i, 16, 4):
            rows_back.append(shifted_rows[j][0])
            
    r0_back = rows_back[0:4]
    r1_back = rows_back[4:8]
    r2_back = rows_back[8:12]
    r3_back = rows_back[12:16]
    
    r0_back = [[r0_back[0]], [r0_back[1]], [r0_back[2]], [r0_back[3]]]
    r1_back = [[r1_back[0]], [r1_back[1]], [r1_back[2]], [r1_back[3]]]
    r2_back = [[r2_back[0]], [r2_back[1]], [r2_back[2]], [r2_back[3]]]
    r3_back = [[r3_back[0]], [r3_back[1]], [r3_back[2]], [r3_back[3]]]
    
    shifted_rows_back = r0_back + r1_back + r2_back + r3_back
            
    return shifted_rows_back


# In[10]:


def galois_mult(a, b):
   
    p = 0
    hi_bit_set = 0
    for i in range(8):
        if b & 1 == 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set == 0x80: a ^= 0x1b
        b >>= 1
    return p % 256


# In[11]:


def MixColumns(state):
    
    mixed = []
    
    fixed = [['02'], ['03'], ['01'], 
             ['01'], ['01'], ['02'], 
             ['03'], ['01'], ['01'], 
             ['01'], ['02'], ['03'], 
             ['03'], ['01'], ['01'], 
             ['02']]
    
    final0 = hex(galois_mult(int(fixed[0][0],16), int(state[0][0],16))
                 ^galois_mult(int(fixed[1][0],16), int(state[1][0],16))
                 ^galois_mult(int(fixed[2][0],16), int(state[2][0],16))
                 ^galois_mult(int(fixed[3][0],16), int(state[3][0],16)))

    final1 = hex(galois_mult(int(fixed[4][0],16), int(state[0][0],16))
                 ^galois_mult(int(fixed[5][0],16), int(state[1][0],16))
                 ^galois_mult(int(fixed[6][0],16), int(state[2][0],16))
                 ^galois_mult(int(fixed[7][0],16), int(state[3][0],16)))
    
    final2 = hex(galois_mult(int(fixed[8][0],16), int(state[0][0],16))
                 ^galois_mult(int(fixed[9][0],16), int(state[1][0],16))
                 ^galois_mult(int(fixed[10][0],16), int(state[2][0],16))
                 ^galois_mult(int(fixed[11][0],16), int(state[3][0],16)))
    
    final3 = hex(galois_mult(int(fixed[12][0],16), int(state[0][0],16))
                 ^galois_mult(int(fixed[13][0],16), int(state[1][0],16))
                 ^galois_mult(int(fixed[14][0],16), int(state[2][0],16))
                 ^galois_mult(int(fixed[15][0],16), int(state[3][0],16)))
    
    final4 = hex(galois_mult(int(fixed[0][0],16), int(state[4][0],16))
                 ^galois_mult(int(fixed[1][0],16), int(state[5][0],16))
                 ^galois_mult(int(fixed[2][0],16), int(state[6][0],16))
                 ^galois_mult(int(fixed[3][0],16), int(state[7][0],16)))
    
    final5 = hex(galois_mult(int(fixed[4][0],16), int(state[4][0],16))
                 ^galois_mult(int(fixed[5][0],16), int(state[5][0],16))
                 ^galois_mult(int(fixed[6][0],16), int(state[6][0],16))
                 ^galois_mult(int(fixed[7][0],16), int(state[7][0],16)))
    
    final6 = hex(galois_mult(int(fixed[8][0],16), int(state[4][0],16))
                 ^galois_mult(int(fixed[9][0],16), int(state[5][0],16))
                 ^galois_mult(int(fixed[10][0],16), int(state[6][0],16))
                 ^galois_mult(int(fixed[11][0],16), int(state[7][0],16)))
    
    final7 = hex(galois_mult(int(fixed[12][0],16), int(state[4][0],16))
                 ^galois_mult(int(fixed[13][0],16), int(state[5][0],16))
                 ^galois_mult(int(fixed[14][0],16), int(state[6][0],16))
                 ^galois_mult(int(fixed[15][0],16), int(state[7][0],16)))
    
    final8 = hex(galois_mult(int(fixed[0][0],16), int(state[8][0],16))
                 ^galois_mult(int(fixed[1][0],16), int(state[9][0],16))
                 ^galois_mult(int(fixed[2][0],16), int(state[10][0],16))
                 ^galois_mult(int(fixed[3][0],16), int(state[11][0],16)))
    
    final9 = hex(galois_mult(int(fixed[4][0],16), int(state[8][0],16))
                 ^galois_mult(int(fixed[5][0],16), int(state[9][0],16))
                 ^galois_mult(int(fixed[6][0],16), int(state[10][0],16))
                 ^galois_mult(int(fixed[7][0],16), int(state[11][0],16)))
    
    final10 = hex(galois_mult(int(fixed[8][0],16), int(state[8][0],16))
                  ^galois_mult(int(fixed[9][0],16), int(state[9][0],16))
                  ^galois_mult(int(fixed[10][0],16), int(state[10][0],16))
                  ^galois_mult(int(fixed[11][0],16), int(state[11][0],16)))
    
    final11 = hex(galois_mult(int(fixed[12][0],16), int(state[8][0],16))
                  ^galois_mult(int(fixed[13][0],16), int(state[9][0],16))
                  ^galois_mult(int(fixed[14][0],16), int(state[10][0],16))
                  ^galois_mult(int(fixed[15][0],16), int(state[11][0],16)))
    
    final12 = hex(galois_mult(int(fixed[0][0],16), int(state[12][0],16))
                  ^galois_mult(int(fixed[1][0],16), int(state[13][0],16))
                  ^galois_mult(int(fixed[2][0],16), int(state[14][0],16))
                  ^galois_mult(int(fixed[3][0],16), int(state[15][0],16)))
    
    final13 = hex(galois_mult(int(fixed[4][0],16), int(state[12][0],16))
                  ^galois_mult(int(fixed[5][0],16), int(state[13][0],16))
                  ^galois_mult(int(fixed[6][0],16), int(state[14][0],16))
                  ^galois_mult(int(fixed[7][0],16), int(state[15][0],16)))
    
    final14 = hex(galois_mult(int(fixed[8][0],16), int(state[12][0],16))
                  ^galois_mult(int(fixed[9][0],16), int(state[13][0],16))
                  ^galois_mult(int(fixed[10][0],16), int(state[14][0],16))
                  ^galois_mult(int(fixed[11][0],16), int(state[15][0],16)))
    
    final15 = hex(galois_mult(int(fixed[12][0],16), int(state[12][0],16))
                  ^galois_mult(int(fixed[13][0],16), int(state[13][0],16))
                  ^galois_mult(int(fixed[14][0],16), int(state[14][0],16))
                  ^galois_mult(int(fixed[15][0],16), int(state[15][0],16)))
    
    mixed = [[final0[2:]], [final1[2:]], [final2[2:]], [final3[2:]], [final4[2:]],
             [final5[2:]], [final6[2:]], [final7[2:]], [final8[2:]], [final9[2:]], 
             [final10[2:]], [final11[2:]], [final12[2:]], [final13[2:]], [final14[2:]], 
             [final15[2:]]]
    
    return mixed


# In[12]:


def aes_encrypt(message, key):
    arr_message = split_string(message)
    arr_hex_message = []
    for i in range(0, len(arr_message)):
        arr_hex_message.append(format_arr_hex(arr_message[i]))
    
    print("")
    print("")
    print("SHOWING VARIABLES: ")
    print("")
    print("")
    arr_hex_key = format_arr_hex(key)
    print('The key in the hexadecimal is: ', arr_hex_key)
    print("")
    
    for i in range(0, len(arr_hex_message)):
        
        print('The message in the hexadecimal of the word',str(i+1),' is: ', arr_hex_message[i])
        print("")
        
    RK = RoundKeys(arr_hex_key)
    
    print("")
    print("")
    print("ROUNDKEYS: ")
    print("")
    print("")
    for i in range(0, len(RK)):
        print('RoundKey number ',str((i)),': ',RK[i])
        print("")
            
    
    #initialRound
    
    print("")
    print("")
    print("##### START OF ROUND 0: ######")
    print("")
    print("")
    
    #Add_Round_Key
    
    add_rk_init = []
    print("")
    print("")
    print("ADDING Initial ROUNDKEY: ")
    print("")
    print("")
    for i in range(0, len(arr_hex_message)):
        
        add_single_rk = AddRoundKey(arr_hex_message[i],RK[0])   
        print('The state of message',str(i+1),' after adding roundkey number ',str(0),' is: ', add_single_rk)
        print("")
        add_rk_init.append(add_single_rk)
    
    
    print("")
    print("")
    print("##### END OF ROUND 0: ######")
    print("")
    print("")
      
    
    final_iter = []
    final_iter.append(add_rk_init)
    
    for iterfinal in range(0, len(RK)-2):
        
        print("")
        print("")
        print("##### START OF ROUND ",str(iterfinal+1),": ######")
        print("")
        print("")

        #Substitution_Bytes
        subs_bytes = []

        for i in range(0, len(final_iter[iterfinal])):

            for j in range(0, len(final_iter[iterfinal][i])):

                final_iter[iterfinal][i][j][0] = format(Sbox[sbox_number(final_iter[iterfinal][i][j][0])], '02x')

            subs_bytes.append(final_iter[iterfinal][i])

        print("")
        print("")
        print("SUBSTITUTION: ")
        print("")
        print("")

        for i in range(0, len(subs_bytes)):

            print('The state of message',str(i+1),' after substitution is: ', subs_bytes[i])
            print("")

        #ShiftRows
        shifted_rows = []
        for i in range(0, len(subs_bytes)):
            shifted_rows.append(shiftRows(subs_bytes[i]))

        print("")
        print("")
        print("SHIFT ROWS: ")
        print("")
        print("")

        for i in range(0, len(shifted_rows)):

            print('The state of message',str(i+1),' after shifting rows is: ', shifted_rows[i])
            print("")

        print("")
        print("")
        print("MIX COLUMNS: ")
        print("")
        print("")    

        mixed_columns = []
        for i in range(0, len(shifted_rows)):
            mixed_columns.append(MixColumns(shifted_rows[i]))

        for i in range(0, len(mixed_columns)):

            print('The state of message',str(i+1),' after mixing columns is: ', mixed_columns[i])
            print("")


        print("")
        print("")
        print("Add Round Keys: ")
        print("")
        print("") 

        add_rk = []

        for i in range(0, len(arr_hex_message)):

            add_single_rk = AddRoundKey(mixed_columns[i],RK[iterfinal+1])   
            print('The state of message',str(i+1),' after adding roundkey is: ', add_single_rk)
            print("")
            add_rk.append(add_single_rk)

        final_iter.append(add_rk)
        
        print("")
        print("")
        print("##### END OF ROUND ",str(iterfinal+1),": ######")
        print("")
        print("")
        
    print("")
    print("")
    print("##### START OF FINAL ROUND : ######")
    print("")
    print("")

    #Substitution_Bytes
    subs_bytes = []

    for i in range(0, len(final_iter[-1])):

        for j in range(0, len(final_iter[-1][i])):

            final_iter[-1][i][j][0] = format(Sbox[sbox_number(final_iter[-1][i][j][0])], '02x')

        subs_bytes.append(final_iter[-1][i])

    print("")
    print("")
    print("SUBSTITUTION: ")
    print("")
    print("")

    for i in range(0, len(subs_bytes)):

        print('The state of message',str(i+1),' after substitution is: ', subs_bytes[i])
        print("")

    #ShiftRows
    shifted_rows = []
    for i in range(0, len(subs_bytes)):
        shifted_rows.append(shiftRows(subs_bytes[i]))

    print("")
    print("")
    print("SHIFT ROWS: ")
    print("")
    print("")

    for i in range(0, len(shifted_rows)):

        print('The state of message',str(i+1),' after shifting rows is: ', shifted_rows[i])
        print("")


    print("")
    print("")
    print("Add Round Keys: ")
    print("")
    print("") 

    add_rk = []

    for i in range(0, len(arr_hex_message)):

        add_single_rk = AddRoundKey(shifted_rows[i],RK[-1])   
        print('The state of message',str(i+1),' after adding roundkey is: ', add_single_rk)
        print("")
        add_rk.append(add_single_rk)
    
    final = ''
    for i in range(0, len(add_rk)):
        for j in range(0, len(add_rk[i])):
            final += add_rk[i][j][0]
    print('The ENCRYPTION is:', final)     
    return final
    print("")
    print("")
    
    print("")
    print("")
    print("##### END OF FINAL ROUND ######")
    print("")
    print("")


# In[13]:


from tkinter import *
from tkinter import messagebox
from pycipher import Caesar
from pycipher import Playfair
from pycipher import Vigenere
from pycipher import Autokey
from pycipher import Railfence

#put encryption code inside here:
def Encrypt_AES():
    
    inputMessage = inputBox.get()
    Key = inputKeyBox.get()
    
    inputMessage = ""
    key = ""
    finalMessage=""
    output.delete('1.0', END)
    inputMessage = inputBox.get()
    Key = inputKeyBox.get()
    
    if inputMessage == "" or Key == "":
        messagebox.showinfo('Input Error','You must enter both key and message')
    elif len(Key) != 16:
        messagebox.showinfo('Input Error','In AES Key must be 16 characters')
    else:
        finalMessage = aes_encrypt(inputMessage, Key)
        
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")

    
def Encrypt_Ceasar():
    
    inputMessage = inputBox.get()
    Key = inputKeyBox.get()
    finalMessage=""
    output.delete('1.0', END)
    try:
           finalMessage = Caesar(key=int(Key)).encipher(inputMessage)
    except ValueError:
            messagebox.showinfo('Enter an integer','In ceasar cipher you must enter an integer')
    
    
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")    
    

def Encrypt_Playfair():
    
    inputMessage = ""
    key = ""
    finalMessage=""
    output.delete('1.0', END) 
    inputMessage = inputBox.get()
    Key = inputKeyBox.get()
    
    
    if inputMessage == "" or Key == "":
        messagebox.showinfo('Input Error','You must enter both key and message')
    else:
        if len(set(Key)) == len(Key) and len(Key)==25:
            finalMessage = Playfair(Key).encipher(inputMessage)
        else:
            messagebox.showinfo('Input Error','For playcipher, the key must be 25 different letters')
        
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  
    
    
def Encrypt_Vingenere():
    
    inputMessage = ""
    key = ""
    finalMessage=""
    output.delete('1.0', END)
    inputMessage = inputBox.get()
    Key = inputKeyBox.get()
    
    
    if inputMessage == "" or Key == "":
        messagebox.showinfo('Input Error','You must enter both key and message')
    else:
        finalMessage = Vigenere(Key).encipher(inputMessage)
        
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  
    
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  

def Encrypt_AutoKey():
    inputMessage = ""
    key = ""
    finalMessage=""
    output.delete('1.0', END)
    inputMessage = inputBox.get()
    Key = inputKeyBox.get()
    
    
    if inputMessage == "" or Key == "":
        messagebox.showinfo('Input Error','You must enter both key and message')
    else:
        finalMessage = Autokey(Key).encipher(inputMessage)
        
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  
    
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  
 

def Encrypt_RealFence():
    
    inputMessage = inputBox.get()
    Key = inputKeyBox.get()
    finalMessage=""
    output.delete('1.0', END)
    try:
           finalMessage = Railfence(key=int(Key)).encipher(inputMessage)
    except ValueError:
            messagebox.showinfo('Enter an integer','In ceasar cipher you must enter an integer')
    
    
    output.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")

     
def Decrypt_Ceasar():
    
    inputMessage = output.get("1.0",END)
    Key = inputKeyBox.get()
    finalMessage=""
    output_2.delete('1.0', END)
    try:
           finalMessage = Caesar(key=int(Key)).decipher(inputMessage)
    except ValueError:
            messagebox.showinfo('Enter an integer','In ceasar cipher you must enter an integer')
    
    
    output_2.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")    
    

def Decrypt_Playfair():
    
    inputMessage = ""
    key = ""
    finalMessage=""
    output_2.delete('1.0', END) 
    inputMessage = output.get("1.0",END)
    Key = inputKeyBox.get()
    
    
    if inputMessage == "" or Key == "":
        messagebox.showinfo('Input Error','You must enter both key and message')
    else:
        if len(set(Key)) == len(Key) and len(Key)==25:
            finalMessage = Playfair(Key).decipher(inputMessage)
        else:
            messagebox.showinfo('Input Error','For playcipher, the key must be 25 different letters')
        
    output_2.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  
    
    
def Decrypt_Vingenere():
    
    inputMessage = ""
    key = ""
    finalMessage=""
    output_2.delete('1.0', END)
    inputMessage = output.get("1.0",END)
    Key = inputKeyBox.get()
    
    
    if inputMessage == "" or Key == "":
        messagebox.showinfo('Input Error','You must enter both key and message')
    else:
        finalMessage = Vigenere(Key).decipher(inputMessage)
        
    output_2.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")   

def Decrypt_AutoKey():
    inputMessage = ""
    key = ""
    finalMessage=""
    output_2.delete('1.0', END)
    inputMessage = output.get("1.0",END)
    Key = inputKeyBox.get()
    
    
    if inputMessage == "" or Key == "":
        messagebox.showinfo('Input Error','You must enter both key and message')
    else:
        finalMessage = Autokey(Key).decipher(inputMessage)
        
    output_2.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")  
 

def Decrypt_RealFence():
    
    inputMessage = output.get("1.0",END)
    Key = inputKeyBox.get()
    finalMessage=""
    output_2.delete('1.0', END)
    try:
           finalMessage = Railfence(key=int(Key)).decipher(inputMessage)
    except ValueError:
            messagebox.showinfo('Enter an integer','In ceasar cipher you must enter an integer')
    
    
    output_2.insert(END, finalMessage) #replace inputMessage with final result
    print("Done")    
    
    
#Initiating GUI
rootframe=Tk()

#title and size of frame
rootframe.title("Security Project")
rootframe.geometry("800x700")
rootframe.configure(background='#a3e6c6')

#items in the frame

#Message input in row 0
a = Label(rootframe, text="Message ", font=16)
a.config(font=("Courier", 16))
a.grid(row=0,column=0,sticky=W)

inputBox = Entry(rootframe, width=50, bg="white")
inputBox.grid(row=0, column=1, sticky=W)

#Key input in row 1
b = Label(rootframe, text="Key", font=16)
b.config(font=("Courier", 16))
b.grid(row=1,column=0,sticky=W)
inputKeyBox = Entry(rootframe, width=50, bg="white")
inputKeyBox.grid(row=1, column=1, sticky=W)


#button in row 2
AES_button = Button(rootframe, text="AES Encryption", width=16, command=Encrypt_AES, bg='#abeaa7', fg='black')
AES_button.grid(row=2,column=0,sticky=W, padx=0, pady=10)

Ceasar_button = Button(rootframe, text="Ceasar Encryption", width=16, command=Encrypt_Ceasar, bg='#abeaa7', fg='black')
Ceasar_button.grid(row=2,column=1,sticky=W, padx=5, pady=10)

Playfair_button = Button(rootframe, text="Playfair Encryption", width=16, command=Encrypt_Playfair, bg='#abeaa7', fg='black')
Playfair_button.grid(row=3,column=0,sticky=W, padx=0, pady=10)

vingenere_button = Button(rootframe, text="Vingenere Encryption", width=16, command=Encrypt_Vingenere, bg='#abeaa7', fg='black')
vingenere_button.grid(row=3,column=1,sticky=W, padx=5, pady=10)

autokey_button = Button(rootframe, text="AutoKey Encryption", width=16, command=Encrypt_AutoKey, bg='#abeaa7', fg='black')
autokey_button.grid(row=4,column=0,sticky=W, padx=0, pady=10)

realfence_button = Button(rootframe, text="RealFence Encryption", width=16, command=Encrypt_RealFence, bg='#abeaa7', fg='black')
realfence_button.grid(row=4,column=1,sticky=W, padx=5, pady=10)


#output in row 3
label = Label(rootframe, text="Cipher Text")
label.config(font=("Courier", 25))
label.grid(row=5,column=0, sticky=W, pady=30)
output = Text(rootframe, width=50, height=5, background="#f5c1b3")
output.grid(row=5, column=1, sticky=W, padx = 10, pady=50)


Ceasar_button_dec = Button(rootframe, text="Ceasar Decryption", width=16, command=Decrypt_Ceasar, bg='#abeaa7', fg='black')
Ceasar_button_dec.grid(row=6,column=0,sticky=W, padx=5, pady=10)

Playfair_button_dec = Button(rootframe, text="Playfair Decryption", width=16, command=Decrypt_Playfair, bg='#abeaa7', fg='black')
Playfair_button_dec.grid(row=6,column=1,sticky=W, padx=0, pady=10)

vingenere_button_dec = Button(rootframe, text="Vingenere Decryption", width=16, command=Decrypt_Vingenere, bg='#abeaa7', fg='black')
vingenere_button_dec.grid(row=7,column=0,sticky=W, padx=5, pady=10)

autokey_button_dec = Button(rootframe, text="AutoKey Decryption", width=16, command=Decrypt_AutoKey, bg='#abeaa7', fg='black')
autokey_button_dec.grid(row=7,column=1,sticky=W, padx=0, pady=10)

realfence_button_dec = Button(rootframe, text="RealFence Decryption", width=16, command=Decrypt_RealFence, bg='#abeaa7', fg='black')
realfence_button_dec.grid(row=8,column=0,sticky=W, padx=5, pady=10)

label_2 = Label(rootframe, text="Plain Text")
label_2.config(font=("Courier", 25))
label_2.grid(row=9,column=0, sticky=W, pady=30)
output_2 = Text(rootframe, width=50, height=5, background="#f5c1b3")
output_2.grid(row=9, column=1, sticky=W, padx = 10, pady=50)

#this keeps the frame running, any part of the frame should be added before it
rootframe.mainloop()


# In[14]:


#Pycipher Unit Tests:
#website https://pycipher.readthedocs.io 

#AES Unit Tests:
#key = 'Thats my Kung Fu'
#message = 'Two One Nine Two Thats my Kung Fu but we cant know for sure we will hope'

#Outputs in the pdf file

