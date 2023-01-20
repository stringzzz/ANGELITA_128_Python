""" 
    
    This is the ANGELITA 128-bit encryption system, Python version
    Copyright (C) 2023 stringzzz, Ghostwarez Co.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY# without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. """

""" 	

ANGELITA128: Algorithm of Number Generation and Encryption Lightweight Intersperse Transform Automator 128-Bit (Python Version)

#Project Start Date: Tue 17 Jan 2023 01∶55 PM
#Initial Untested Complete: Wed 18 Jan 2023 17:25 PM

#Working Version (Kind of): Thu 19 Jan 2023 13:21 PM

#Encrypts and decrypts in both modes, but doesn't do so the same way as the original C++ version.
#Extra steps are needed to track down why it is doing things differently


#Found the problem and fixed it: Thu 19 Jan 2023 14:43 PM

#Problem originated from the xorBytes function, it was ignoring the skipped byte instead of adding
# it to the new list.
#Now the program is completely compatible with the C++ version.
#Something can be encrypted with the C++ version in either mode and successfully decrypted in the Python
# version, or vice-versa. 
# The next step is adding the code for exception handling, adding comments for each section,
# and probably a little bit of clean-up as well.


#Finished testing the exception handling and added the comments:
# Thu Jan 19 16:12 PM
# 
# Will call this the final version, but of course there's probably some extra cleaning up to do...


!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!!
Also to note, this system hasn't gone through any kind of proper peer review process yet, so it should not be used
for any real secure purposes. You have been warned!
!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!! 

"""

#####################################################
# Key Schedule	Bytes	% Key	Key Bytes	Key Bits
#
# S-Box		1216	59.375	9.5		76
# P-Box		320	15.625	2.5		20
# XOR1		256	12.5	2		16
# XOR2		256	12.5	2		16
# Total		2048	100	16		128
#####################################################

#####################################################
################# ANGELITA128 Algorithm ###################
# 1. Choose e/d (encryption/decryption)
# 2. Choose the key option
# 3. Input or generated key is expanded 128 times by
#	the key schedule (KISS)
# 4. The Key Schedule is split, some bytes used
#	to initialize the S-Box and P-Box. The rest is
#	used in the encryption/decryption loop
# 5. The encryption/decryption loop works on 128-Bit
#	blocks, for 16 cycles. Cycle below (Encryption):
#
#	b. XOR with KS 1
#	c. S-Box
#	d. XOR with KS 2
#	e. If cycles is multiple of 2, P-Box the pairs of bits of the block
#
#	Decryption is simply the reverse of this
#####################################################

import random
import os

class ANGELITA_128:

    #Various variables for setup 
    __initialKey0 = []
    __initialKey1 = []
    __keySchedule = []
    __Sbox = []
    __Pbox = []
    __revSbox = []
    __revPbox = []
    __KS_SBOX = []
    __KS_SBOX_BITS = []
    __KS_PBOX = []
    __KS_PBOX_BITS = []
    __KS_XOR1 = []
    __KS_XOR2 = []
    __keySet = False
    __reverseSet = False

    def __init__(self):
        pass

    def __sp1_8(byte_list):
        #Split a list of bytes into a list of its corresponding bits
        bit_list = []
        for byte in byte_list:
            for n in range(7, -1, -1):
                bit_list.append((byte >> n) & 1)

        return bit_list
    
    def __sp1_2bits(byte_list):
        #Split a list of bytes into a list of its corresponding 2-bit pairs (Lyks)
        lyk_list = []
        for byte in byte_list:
            for n in range(6, -1, -2):
                lyk_list.append((byte >> n) & 3)

        return lyk_list

    def __jn2bits_1(lyk_list):
        #Join a list of 2-bit pairs (Lyks) into their corresponding bytes
        byte_list = []
        lyk_index = 0
        for n in range(0, int(len(lyk_list) / 4)):
            byte_list.append(0)
            for n2 in range(lyk_index, lyk_index + 4):
                byte_list[n] = (byte_list[n] << 2) ^ lyk_list[n2]
            lyk_index += 4
        return byte_list
    
    def __rotateBytes(byte_list):
        #Take a list of bytes and move their leftmost bit to the right side of the byte
        byte_list2 = []
        for byte in byte_list:
            byte_list2.append(((byte >> 7) ^ (byte << 1)) & 255)
        
        return byte_list2
    
    def __xorBytes(byte_list, byte, skippedIndex):
        #XOR all bytes in byte_list by byte, except for the one at skippedIndex
        byte_list2 = []
        for n in range(0, len(byte_list)):
            if n == skippedIndex:
                byte_list2.append(byte_list[n])
                continue
            byte_list2.append(byte_list[n] ^ byte)

        return byte_list2
    
    def __TeaParty2_SBOX(sbox):
        #Generate the S-Box by repeated key-dependent shuffles
        #Shuffles are recreatable by using the same key
        #Total 38 shuffles
        KS_Counter = 0
        ANGELITA_128.__KS_SBOX_BITS = list(ANGELITA_128.__sp1_8(ANGELITA_128.__KS_SBOX))
        for shuffles in range(1, 39):
            TeaCup1 = []
            TeaCup2 = []
            for boxBytes in range(0, 256):
                if ANGELITA_128.__KS_SBOX_BITS[KS_Counter] == 1:
                    TeaCup1.append(sbox[boxBytes])
                else:
                    TeaCup2.append(sbox[boxBytes])
                KS_Counter += 1

            sbox = list(TeaCup2 + TeaCup1)

        return sbox
    
    def __TeaParty2_PBOX(pbox):
        #Generate the P-Box by repeated key-dependent shuffles
        #Shuffles are recreatable by using the same key
        #Total 40 shuffles
        KS_Counter = 0
        ANGELITA_128.__KS_PBOX_BITS = list(ANGELITA_128.__sp1_8(ANGELITA_128.__KS_PBOX))
        for shuffles in range(1, 41):
            TeaCup1 = []
            TeaCup2 = []
            for boxBytes in range(0, 64):
                if ANGELITA_128.__KS_PBOX_BITS[KS_Counter] == 1:
                    TeaCup1.append(pbox[boxBytes])
                else:
                    TeaCup2.append(pbox[boxBytes])
                KS_Counter += 1

            pbox = list(TeaCup2 + TeaCup1)

        return pbox
    
    def __genSBox():
        #Generate the initial S-Box and run it through TeaParty2
        sbox = []
        for n in range(0, 256):
            sbox.append(n)
        ANGELITA_128.__Sbox = list(ANGELITA_128.__TeaParty2_SBOX(sbox))

    def __genPBox():
        #Generate the initial P-Box and run it through TeaParty2
        pbox = []
        for n in range(0, 64):
            pbox.append(n)
        ANGELITA_128.__Pbox = list(ANGELITA_128.__TeaParty2_PBOX(pbox))

    def __genRevSBox():
        #Flip around the S-Box for its inverse (For decryption)
        rsbox = list(ANGELITA_128.__Sbox)
        for n in range(0, 256):
            rsbox[ANGELITA_128.__Sbox[n]] = n
        ANGELITA_128.__revSbox = list(rsbox)

    def __genRevPBox():
        #Flip around the P-Box for its inverse (For decryption)
        rpbox = list(ANGELITA_128.__Pbox)
        for n in range(0, 64):
            rpbox[ANGELITA_128.__Pbox[n]] = n
        ANGELITA_128.__revPbox = list(rpbox)

    def __useSBox(blockByte):
        #Substitute input byte according to the S-Box
        return ANGELITA_128.__Sbox[blockByte]
    
    def __usePBox(lyks):
        #Permute all the input 2-bit pairs (Lyks) according to the P-Box
        pLyks = list(lyks)
        for n in range(0, 64):
            pLyks[ANGELITA_128.__Pbox[n]] = lyks[n]
        return pLyks
    
    def __useRevSBox(blockByte):
        #Substitute input byte according to the inverse S-Box
        return ANGELITA_128.__revSbox[blockByte]

    def __useRevPBox(lyks):
        #Permute all the input 2-bit pairs (Lyks) according to the inverse P-Box
        pLyks = list(lyks)
        for n in range(0, 64):
            pLyks[ANGELITA_128.__revPbox[n]] = lyks[n]
        return pLyks

    def __ANGELITA128_KISS():
        #KISS: Key Initializing Scheduling Subroutine
        #Expand the key, used inside ANGELITA128_KISS2
        KS_ALL = []
        block = list(ANGELITA_128.__initialKey1)
        xorBlock = []
        rotateBlock = []

        #Create 256 bytes from the 16 by repeated XORS of the initial key by each key byte
        for xors in range(0, 16):
            xorBlock = list(ANGELITA_128.__xorBytes(block, block[xors], xors))
            KS_ALL = list(KS_ALL + xorBlock)

        rotateBlock = list(rotateBlock + KS_ALL)

        #Expand they KS_ALL to 2048 bytes by repeated rotation of the bytes of the previous block
        for rotates in range(1, 8):
            rotateBlock = list(ANGELITA_128.__rotateBytes(rotateBlock))
            KS_ALL = list(KS_ALL + rotateBlock)

        #Generate a temp P-Box and S-Box to mix up the working Key Schedule
        for mixes in range(1, 3):
            ANGELITA_128.__KS_PBOX = list(KS_ALL[0:320])
            ANGELITA_128.__genPBox()
            pBlock = []
            KS_ALL2 = []
            pBlockCounter = 0
            for i in range(1, 129):
                pBlock = list(KS_ALL[pBlockCounter:pBlockCounter + 16])
                pBlockCounter += 16
                pBlock = list(ANGELITA_128.__jn2bits_1(ANGELITA_128.__usePBox(ANGELITA_128.__sp1_2bits(pBlock))))
                KS_ALL2 = list(KS_ALL2 + pBlock)
            
            ANGELITA_128.__KS_SBOX = list(KS_ALL2[0:1216])
            ANGELITA_128.__genSBox()
            for n in range(0, 2048):
                KS_ALL2[n] = ANGELITA_128.__useSBox(KS_ALL2[n])

            if mixes != 2:
                KS_ALL = list(KS_ALL2)

        return KS_ALL2
    
    def __ANGELITA128_KISS2():
        #KISS2: Key Initializing Scheduling Subroutine 2
        #Repeats same steps as KISS, but with an additional important step near the end
        KS_ALL = []
        block = list(ANGELITA_128.__initialKey1)
        xorBlock = []
        rotateBlock = []

        for xors in range(0, 16):
            xorBlock = list(ANGELITA_128.__xorBytes(block, block[xors], xors))
            KS_ALL = list(KS_ALL + xorBlock)

        rotateBlock = list(rotateBlock + KS_ALL)
        for rotates in range(1, 8):
            rotateBlock = list(ANGELITA_128.__rotateBytes(rotateBlock))
            KS_ALL = list(KS_ALL + rotateBlock)

        for mixes in range(1, 3):
            ANGELITA_128.__KS_PBOX = list(KS_ALL[0:320])
            ANGELITA_128.__genPBox()
            pBlock = []
            KS_ALL2 = []
            pBlockCounter = 0
            for i in range(1, 129):
                pBlock = list(KS_ALL[pBlockCounter:pBlockCounter + 16])
                pBlockCounter += 16
                pBlock = list(ANGELITA_128.__jn2bits_1(ANGELITA_128.__usePBox(ANGELITA_128.__sp1_2bits(pBlock))))
                KS_ALL2 = list(KS_ALL2 + pBlock)
            
            ANGELITA_128.__KS_SBOX = list(KS_ALL2[0:1216])
            ANGELITA_128.__genSBox()
            for n in range(0, 2048):
                KS_ALL2[n] = ANGELITA_128.__useSBox(KS_ALL2[n])

            if mixes != 2:
                KS_ALL = list(KS_ALL2)

        #Create a temp key by using a sponge construction with all the temp Key Schedule bytes
        spongeBlock = list(KS_ALL2[0:16])
        KS_INDEX = 16
        for blockCount in range(1, 128):
            for i in range(0, 16):
                spongeBlock[i] ^= KS_ALL2[KS_INDEX]
                KS_INDEX += 1

        tempKS = list(KS_ALL2)
        tempKS2 = []

        #Use KISS with the tmp key and create the temp Key Schedule distribution
        ANGELITA_128.__initialKey1 = list(spongeBlock)
        ANGELITA_128.__keySchedule = ANGELITA_128.__ANGELITA128_KISS()
        ANGELITA_128.__KS_SBOX = list(ANGELITA_128.__keySchedule[0:1216])
        ANGELITA_128.__KS_PBOX = list(ANGELITA_128.__keySchedule[1216:1536])
        ANGELITA_128.__KS_XOR1 = list(ANGELITA_128.__keySchedule[1536:1792])
        ANGELITA_128.__KS_XOR2 = list(ANGELITA_128.__keySchedule[1792:2048])
        ANGELITA_128.__genSBox()
        ANGELITA_128.__genPBox()

        #Encrypt each block of the temp Key Schedule using the previous setup
        plaintextBlock2 = list(tempKS[2032:2048])
        plaintextBlock1 = []
        blockIndex1 = 0
        for blockNumber in range(1, 129):
            plaintextBlock1 = list(tempKS[blockIndex1 : blockIndex1 + 16])
            blockIndex1 += 16
            for n in range(0, 16):
                plaintextBlock1[n] ^= plaintextBlock2[n]
            tempKS2 = list(tempKS2 + plaintextBlock2)
            plaintextBlock2 = list(ANGELITA_128.__encrypt(plaintextBlock1))

        tempKS2 = list(tempKS2 + plaintextBlock2)
        KS_ALL = list(tempKS2[16:2064])
        return KS_ALL
    
    def __genKS():
        #Setup the different portions of the Key Schedule
        ANGELITA_128.__keySchedule = ANGELITA_128.__ANGELITA128_KISS2()
        ANGELITA_128.__KS_SBOX = list(ANGELITA_128.__keySchedule[0:1216])
        ANGELITA_128.__KS_PBOX = list(ANGELITA_128.__keySchedule[1216:1536])
        ANGELITA_128.__KS_XOR1 = list(ANGELITA_128.__keySchedule[1536:1792])
        ANGELITA_128.__KS_XOR2 = list(ANGELITA_128.__keySchedule[1792:2048])

    def __encrypt(plaintextBlock):
        #Encrypt 1 block of plaintext for 16 cycles
        KS_XOR1_Counter = 0
        KS_XOR2_Counter = 0
        for cycles in range(1, 17):
            if cycles % 2 == 0:
                plaintextBlock = list(ANGELITA_128.__jn2bits_1(ANGELITA_128.__usePBox(ANGELITA_128.__sp1_2bits(plaintextBlock))))
            for i in range(0, 16):
                plaintextBlock[i] ^= ANGELITA_128.__KS_XOR1[KS_XOR1_Counter]
                KS_XOR1_Counter += 1
                plaintextBlock[i] = ANGELITA_128.__useSBox(plaintextBlock[i])
                plaintextBlock[i] ^= ANGELITA_128.__KS_XOR2[KS_XOR2_Counter]
                KS_XOR2_Counter += 1
        
        return plaintextBlock
    
    def __decrypt(ciphertextBlock):
        #Decrypt 1 block of ciphertext for 16 cycles in reverse
        KS_XOR1_Counter = 255
        KS_XOR2_Counter = 255
        for cycles in range(16, 0, -1):
            for i in range(15, -1, -1):
                ciphertextBlock[i] ^= ANGELITA_128.__KS_XOR2[KS_XOR2_Counter]
                KS_XOR2_Counter -= 1
                ciphertextBlock[i] = ANGELITA_128.__useRevSBox(ciphertextBlock[i])
                ciphertextBlock[i] ^= ANGELITA_128.__KS_XOR1[KS_XOR1_Counter]
                KS_XOR1_Counter -= 1
            if cycles % 2 == 0:
                ciphertextBlock = list(ANGELITA_128.__jn2bits_1(ANGELITA_128.__useRevPBox(ANGELITA_128.__sp1_2bits(ciphertextBlock))))

        return ciphertextBlock
    
    def __GLORIA():
        #GLORIA: Generator of Lovely Random Intersperse Automator

        #Store away current S-Box and P-Box arrangements
        SboxT = list(ANGELITA_128.__Sbox)
        PboxT = list(ANGELITA_128.__Pbox)

        #Create the RNG pool from PRNG source
        RNG_POOL = []
        for n in range(0, 2048):
            RNG_POOL.append(random.randint(0, 255))

        #The following is almost exactly identical to the KISS function
        for mixes in range(1, 4):
            ANGELITA_128.__KS_PBOX = list(RNG_POOL[0:320])
            ANGELITA_128.__genPBox()
            pBlock = []
            RNG_POOL2 = []
            pBlockCounter = 0
            for i in range(1, 129):
                pBlock = list(RNG_POOL[pBlockCounter:pBlockCounter + 16])
                pBlockCounter += 16
                pBlock = list(ANGELITA_128.__jn2bits_1(ANGELITA_128.__usePBox(ANGELITA_128.__sp1_2bits(pBlock))))
                RNG_POOL2 = list(RNG_POOL2 + pBlock)
            
            ANGELITA_128.__KS_SBOX = list(RNG_POOL2[0:1216])
            ANGELITA_128.__genSBox()
            for n in range(0, 2048):
                RNG_POOL2[n] = ANGELITA_128.__useSBox(RNG_POOL2[n])

            if mixes != 3:
                RNG_POOL = list(RNG_POOL2)

        #Create the generated key by a sponge construction of the RNG_POOL bytes
        spongeBlock = list(RNG_POOL2[0:16])
        RNG_INDEX = 16
        for blockCount in range(1, 128):
            for i in range(0, 16):
                spongeBlock[i] ^= RNG_POOL2[RNG_INDEX]
                RNG_INDEX += 1

        #Restore old S-Box and P-Box arrangements
        ANGELITA_128.__Sbox = list(SboxT)
        ANGELITA_128.__Pbox = list(PboxT)

        return spongeBlock
    
    def __setup():
        #Setup the key schedule portions, S-Box, and P-Box
        ANGELITA_128.__initialKey1 = ANGELITA_128.__initialKey0
        ANGELITA_128.__genKS()
        ANGELITA_128.__genSBox()
        ANGELITA_128.__genPBox()
        ANGELITA_128.__keySet = True
        ANGELITA_128.__reverseSet = False
    
    #########################################
    ### Public interface
    #########################################

    def genKey(self):
        #Generate a PRNG key with GLORIA
        ANGELITA_128.__initialKey0 = list(ANGELITA_128.__GLORIA())
        ANGELITA_128.__setup()

    def setKeyS(self, keyString):
        #Set the key by a string of 16 characters

        #Raise exceptions if not 16 character input
        if len(keyString) > 16:
            raise Exception("KeyStringError: Input key is greater than 16 characters.")
        elif len(keyString) < 16:
            raise Exception("KeyStringError: Input key is less than 16 characters.")

        for n in range(0, 16):
            ANGELITA_128.__initialKey0[n] = ord(keyString)

        ANGELITA_128.__setup()

    def setKeyH(self, hexString):
        #Set the key by a string of 32 hex digits

        if len(hexString) > 32:
            raise Exception("HexKeyError: Input key is greater than 32 hex digits.")
        elif len(hexString) < 32:
            raise Exception("HexKeyError: Input key is less than 32 hex digits.")
        
        dec_digits = {}
        hex_digits = "0123456789ABCDEF"

        #Create dictionary for converting from hex to byte values
        for n in range(0, 16):
            dec_digits[hex_digits[n]] = n

        dec_list = []
        hexString = hexString.upper()

        #Make sure hex key is using valid hex digits
        for digit in hexString:
            match = False
            for n in range(0, len(hex_digits) - 1):
                if hex_digits[n] == digit:
                    match = True
                    break
            if not(match):
                raise Exception("HexKeyError: Invalid character '" + digit + "' not hex digit")

        #Convert the hex key into a list of bytes
        for n in range(0, len(hexString), 2):
            dec_list.append((dec_digits[hexString[n]] << 4) ^ dec_digits[hexString[n + 1]])

        ANGELITA_128.__initialKey0 = list(dec_list)
        ANGELITA_128.__setup()

    def showKey(self):
        #Show the current key in the form of hex string
        digits = "0123456789ABCDEF"
        hex_string = ""
        for decimal in ANGELITA_128.__initialKey0:
            hex_string = hex_string + digits[decimal >> 4] + digits[decimal & 15]

        print("Set key in hexadecimal: " + hex_string)

    def encrypt(self, file, mode):
        #Encrypt file with selected mode

        mode = mode.lower()

        #Detect if key is set and mode is correct, raise Exception if not
        if not(ANGELITA_128.__keySet):
            raise Exception("SetKeyError: Key must be set to encrypt.")
        if mode != "ecb" and mode != "cbc":
            raise Exception("ModeError: Invalid encryption mode, must be 'ecb' or 'cbc'.")

        #Input the file bytes as a bytearray
        IF = open(file, 'rb')
        Bytes = bytearray(IF.read())
        IF.close()

        #Get needed padding size and append that number to the plaintext that many times
        paddingSize = 16 - (len(Bytes) % 16)
        for n in range(0, paddingSize):
            Bytes.append(paddingSize)

        blockCount = int(len(Bytes) / 16)

        #Electronic Code Book mode, just plain encryption
        if mode == "ecb":
            plaintextBlock = []
            blockIndex = 0
            outputBytes = bytearray()
            for blockNumber in range(0, blockCount):
                plaintextBlock = list(Bytes[blockIndex : blockIndex + 16])
                blockIndex += 16
                plaintextBlock = list(ANGELITA_128.__encrypt(plaintextBlock))
                outputBytes = outputBytes + bytearray(plaintextBlock)

        #Cipher Block Chaining mode, XOR previous block with next block before encryption
        #IV is generated using GLORIA PRNG
        elif mode == "cbc":
            plaintextBlock2 = list(ANGELITA_128.__GLORIA())
            plaintextBlock1 = []
            blockIndex = 0
            outputBytes = bytearray()
            for blockNumber in range(1, blockCount + 1):
                plaintextBlock1 = list(Bytes[blockIndex : blockIndex + 16])
                blockIndex += 16
                for n in range(0, 16):
                    plaintextBlock1[n] ^= plaintextBlock2[n]
                outputBytes = outputBytes + bytearray(plaintextBlock2)
                plaintextBlock2 = ANGELITA_128.__encrypt(plaintextBlock1)

            outputBytes = outputBytes + bytearray(plaintextBlock2)

        #Output the ciphertext back into the file
        OF = open(file, 'wb')
        OF.write(bytes(outputBytes))
        OF.close()

        #Add the ".ANGELITA128" extension to the newly encrypted file
        os.system("mv " + file + " " + file + ".ANGELITA128")

    def decrypt(self, file, mode):
        #Decrypt the file in the chosen mode

        mode = mode.lower()

        #Detect if key is set and mode is correct, raise exception if not
        if not(ANGELITA_128.__keySet):
            raise Exception("SetKeyError: Key must be set to decrypt.")
        if mode != "ecb" and mode != "cbc":
            raise Exception("ModeError: Invalid decryption mode, must be 'ecb' or 'cbc'.")

        #Input file bytes as a bytearray
        IF = open(file, 'rb')
        Bytes = bytearray(IF.read())
        IF.close()

        #Generate the inverse S-Box and P-Box for decryption
        if not(ANGELITA_128.__reverseSet):
            ANGELITA_128.__genRevSBox()
            ANGELITA_128.__genRevPBox()
            ANGELITA_128.__reverseSet = True

        blockCount = int(len(Bytes) / 16)

        #Electronic Code Book mode, no need to worry about block order
        if mode == "ecb":
            ciphertextBlock = []
            blockIndex = 0
            outputBytes = bytearray()
            for blockNumber in range(0, blockCount):
                ciphertextBlock = list(Bytes[blockIndex : blockIndex + 16])
                blockIndex += 16
                ciphertextBlock = list(ANGELITA_128.__decrypt(ciphertextBlock))
                outputBytes = outputBytes + bytearray(ciphertextBlock)

        #Cipher Block Chaining Mode, order does matter, must do in reverse
        elif mode == "cbc":
            ciphertextBlock1 = []
            ciphertextBlock2 = []
            blockIndex = len(Bytes)
            outputBytes = bytearray()
            for blockNumber in range(blockCount, 1, -1):
                if blockNumber == blockCount:
                    ciphertextBlock1 = list(Bytes[blockIndex - 16 : blockIndex])
                    blockIndex -= 16
                ciphertextBlock2 = list(ANGELITA_128.__decrypt(ciphertextBlock1))
                ciphertextBlock1 = list(Bytes[blockIndex - 16 : blockIndex])
                blockIndex -= 16
                for n in range(0, 16):
                    ciphertextBlock2[n] ^= ciphertextBlock1[n]
                outputBytes = bytearray(ciphertextBlock2) + outputBytes

        #Get padding size and remove accordingly from end of plaintext bytes
        paddingSize = int(outputBytes[len(outputBytes) - 1])
        del outputBytes[len(outputBytes) - paddingSize : len(outputBytes)]

        #Output the newly decrypted plaintext bytes into file
        OF = open(file, 'wb')
        OF.write(bytes(outputBytes))
        OF.close()

        #Remove the ".ANGELITA128" extension from the decrypted file
        originalFile = file.replace(".ANGELITA128", "")
        os.system("mv " + file + " " + originalFile)