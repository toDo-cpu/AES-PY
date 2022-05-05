WORD_SIZE_BIT = 8

STATE_TABLE = 0
STATE_LINE = 1

#----------------------Substitution Box-----------------------------#
S_BOX_STR = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76'\
        'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0'\
        'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15'\
        '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75'\
        '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84'\
        '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf'\
        'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8'\
        '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2'\
        'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73'\
        '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db'\
        'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79'\
        'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08'\
        'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a'\
        '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e'\
        'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df'\
        '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'.replace(" ","")

S_BOX = bytearray().fromhex(S_BOX_STR)

#---------------------Round Constant----------------------------------#
RCON_LOOKUP_TABLE = bytearray().fromhex("01020408102040801B36")

def doubleArr_to_OneArr(arr:[[int]])->[int]:
    c = []
    for a in arr:
        for b in a:
            c.append(b)

    return b''.join(c)

def shiftRow(state: [[int]] ,row:int ,n:int )->None:
    """
    @brief shift cyclicaly the values in a rows of a state matrix
    @arg1: the state matrix
    @arg2: index of the row to by shifted
    @arg3: shift n times
    @return: None
    """
    state[row] = state[row][n:] + state[row][:n]


def get_nr_from_key(key: bytes)->int:
    """
    @brief calculate the Nr constant using the key size
    @arg1: key
    @return: Nr constant as an integer 
    """ 
    bkey_length = len(key) * WORD_SIZE_BIT

    assert( 
        (bkey_length == 128) or  
        (bkey_length == 192) or 
        (bkey_length == 256))

    if bkey_length == 128:
        return 10
    elif bkey_length == 192:
        return 12
    else:
        return 14

def print_state(state:[[int]], mode:int=STATE_TABLE, content:str="state object")->None:
    """
    @brief print the state structure aka 2d array
    @arg1: state 2d array
    @arg2: mode to print the 2d array, if it is STATE_TABLE interpret this as a table, elif its STATE_LINE interpret this as a line
    @return: nothing 
    """
    #Print the state as a table
    if mode == STATE_TABLE:
        print(content)
        print("+" + "-" * (4*7-1) + "+") 
        for word in state:
            print("|",end="")
            for byte in word:
                print(" 0x{:02X}".format(byte), end =" |")
            print("\n",end="")
            print("+" + "-" * (4*7-1) + "+")
    #Print the state in a line
    elif mode == STATE_LINE:
        buffer = ""
        for word in state:
            for byte in word:
                buffer += "{:02x}".format(byte)
        print(content + buffer)  
    return 

def state_from_bytes(plaintext:bytes)->[[int]]:
    """
    @brief This function convert the plaintext into an 2d matrix (described as a state in the NIST document)
    @arg1: plaintext to be transformed to a state structure 
    @return: state structure
    """
    return [ plaintext[i*4:(i+1)*4] for i in range(len(plaintext) // 4)]

def bytes_from_state(cipher:[[int]])->bytes:
    """
    @brief This function convert the ciphertext represented by the state structure
    @arg1: state to transform to a state structure
    @return: bytearray
    """
    return bytes(cipher[0] + cipher[1] + cipher[2] + cipher[3])

def Rcon(i:int)->bytes:
    """ 
    @brief return rcon(i) where rcon is a constant
    @arg1: i
    @return: rcon(i)
    """
    return bytes([RCON_LOOKUP_TABLE[i-1],0,0,0])

def ShiftRows(state:[[int]])->None:
    """
    @brief Apply the ShiftRows function, shift state[0] by 0, state[1] by 1, state[2] by 2, state[3] by 3
    @arg1: state matrix
    @return: None
    """
    for r in range(len(state)):
        shiftRow(state, r, r)    

def RotWord(word:bytes)->bytes:
    """
    @brief apply a cyclic operations on a word
    @arg1: word to be rotated
    @return: return the rotated word
    """
    return word[1:] + word[:1]

assert(RotWord(b'\x00\x01\x02\x03') == b'\x01\x02\x03\x00')

def XorBytes(a:bytes, b:bytes)->bytes:
    """
    @brief apply a XOR logical operation between a and b, a and b 
    must have the same size
    @arg1: operand a
    @arg2: operand b
    @return: XOR(a,b) 
    """
    assert(len(a) == len(b))

    c = bytearray()
    for i in range(len(a)):
        c.append(a[i] ^ b[i])
    return c

def SubWord(word: bytes)->bytes:
    """ 
    @brief substitue bytes in the given buffer using the S_BOX
    @arg1: word to be substitute
    @return: the substitued buffer
    """
    return bytes(S_BOX[i] for i in word)

def SubBytes(state: [[int]])->None:
    for w in range(len(state)): #for each words in the state matrix
        for b in range(len(state)):#for each bytes in the current word
            state[w][b] = S_BOX[state[w][b]]
    return
def key_expansion(key: bytes, Nb: int = 4)->[[[int]]]:
    """
    @brief implementation of the key expansion algorithms to create the key schedule
    @arg1: the key to extend
    @arg2: Key size as block of 32 bits
    @return: extended key as byte 
    """
    Nk = len(key) // 4
    Nr = get_nr_from_key(key)
    w = state_from_bytes(key)

    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i-1]
        if (i % Nk == 0):
            temp = XorBytes(SubWord(RotWord(temp)), Rcon(i//Nk))
        elif (Nk > 6) and (i%Nk == 4):
            temp = SubWord(temp)
        w.append(XorBytes(w[i-Nk],temp)) 

    return [w[i*4:(i+1)*4] for i in range(len(w) // 4)]

def AddRoundKey(state:[[int]], key_schedule:[[[int]]], round:int=0, Nb:int = 4)->None:
    for c in range(Nb):
        current_key = key_schedule[round * Nb + c]
        state[0][c] = state[0][c] ^ current_key[0][c]
        state[1][c] = state[1][c] ^ current_key[1][c]
        state[2][c] = state[2][c] ^ current_key[2][c]
        state[3][c] = state[3][c] ^ current_key[3][c]
    return
def aes_encryption(plaintext: bytes, key: bytes)->bytes:
    """
    @brief encrypt plaintext using the AES algorithms
    @arg1: plaintext to be encrypted
    @arg2: key used to encrypt the plaitext
    @return: the ciphertext 
    """
    #Guessing Nr by using the key length
    Nr = get_nr_from_key(key)

    #State is a buffer used to handle the modified plaintext
    #State is a 2d array with for rows, each containing Nb bytes where Nb is the block cipher size divided by 32
    state = state_from_bytes(plaintext)
    
    #key_schedule is the equivalent of w in the pseudo code
    #key_schedule is a list of matrix 4 * Nb 
    key_schedule = key_expansion(key)

    #Simple Xor between a key in the key_schedule and the state structure, the key picked is determined by round
    AddRoundKey(state, key_schedule, round=0)

    #Starting cyclic operations ...
    for round in range(0, Nr):

        #Apply the substitution table on each byte of the state matrix
        SubBytes(state)

        #Apply the ShiftRows Transformation
        ShiftRows(state)

        #Apply the MixColumns transformation
        MixColumns(state)

        #Apply the Addroundkey transformation
        AddRoundKey(state, key_schedule, round=round)
    
    SubBytes(state)
    ShiftRows(state)
    AddRoundKey(state, key_schedule[Nr * Nb, (Nr+1)*Nb-1])
    
    return state
