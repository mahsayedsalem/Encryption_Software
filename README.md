# Encryption_Software
# Security Project

This notebook is an implementation for the AES algorithm written in vanilla python3 and some ciphers using pycipher library

<h3> Problem Statement: </h3>

An encryption ready-to-production software which uses encryption algorithms to encrypt plain texts using multiple encryption algorithms, one of which is written from scratch while the other encryptions are produced using an encryption library. 


<h4>Steps: </h4>
1.	Take a plain message and a key
2.	Divide the plain message into 128bits and pad the final remaining. .
3.	Translate them into Hex
4.	Get the first RoundKey:
    •	Divide the key into 4 parts
    •	Left-shift to the last part
    •	Byte Substitution to the output of the last step
    •	Add Round constant to the output of the last step
5.	Xor between the first part of the key and the output of the last step
6.	Xor between the second part of the key and the output of the last step
7.	Xor between the third part of the key and the output of the last step
8.	Xor between the fourth part of the key and the output of the last step
9.	Concat the output of the last four steps and this gives us the first RoundKey.
10.	Use this Roundkey as a key to iterate the steps again till we get 5 RoundKeys.
11.	Xor between state message and the first roundkey
12.	In each round we make:
    •	Substitution
    •	Shift-Rows
    •	Mix-Columns
    •	Add RoundKey
13.	In the final step we make all the steps but the mix columns, then we concat the message and this is our encrypted message. 


<h4>Functions Developed for AES: </h4>
1.	lettersToHex(message): <i>Translate strings into hexadecimals.</i>
2.	split_string(message): <i>split strings into arrays of 128bits.</i>
3.	format_arr_hex(arr_message): <i>format the array.</i>
4.	RoundKeys(key): <i>produces the roundkeys needed.</i>
5.	Xor_hex(arr_str1, arr_str2): <i>xor operations between two arrays of strings.</i>
6.	Sbox_number(stringx): <i>produces the place of the value needed from the sbox array.</i>
7.	AddRoundKey(message,key): <i>Adds Roundkey to message.</i>
8.	shiftRows(single_state): <i>Shifts rows of a state.</i>
9.	galois_mult(a, b): <i>Copied function that makes galois multiplication.</i>
10.	MixColumns(state): <i>Mixes columns of a state.</i>
11.	Aes_encrypt(message,key): <i>The main aes algorithm utilizing the previous functions.</i>

<h4>Ciphers Algorithms: </h4>
1.	AES
2.	Ceasar
3.	Playfair
4.	Vigenere
5.  Autokey
6.  Railfence


<h4>Technologies: </h4>
1.	Python.
2.  pycipher.

<h4>Install: </h4>
1.	Python3.
2.  Anaconda.
3.  pycipher (pip install pycipher)
