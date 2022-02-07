
import time

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
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


#encrypt

def encrypt(input,word): 
    state = []
    for r in range(4):
        temp=[]
        for c in range(Nb):
            temp.append(input[r+4*c])
        state.append(temp)
    state=AddRoundKey(state, word[0: Nb])
    for round in range(1,Nr):
            state=SubBytes(state)
            state=ShiftRows(state)
            state=MixColumns(state)
            state=AddRoundKey(state,word[round*Nb : (round+1)*Nb])
    state=SubBytes(state)
    state=ShiftRows(state)
    state=AddRoundKey(state, word[Nr*Nb: (Nr+1)*Nb])

    output = []
    for j in range(Nb):
        for i in range(4):
            output.append(state[i][j])

    return output


    

def rotWord(w):
    w[0],w[1],w[2],w[3] = w[1],w[2],w[3],w[0]
    return w

def subWord(w):
    for i in range(4):
        w[i] = Sbox[w[i]]
    return w

def KeyExpansion(key,Nk):
    word=[]
    i=0
    while(i<Nk):
        word.append([int(key[4*i],16),int(key[4*i+1],16),int(key[4*i+2],16),int(key[4*i+3],16)])
        i=i+1
    i=Nk
    while(i< Nb*(Nr+1)):
        temp=word[i-1][:]
        if(i%Nk == 0):
            temp=subWord(rotWord(temp))
            temp[0]=temp[0] ^ Rcon[int(i/Nk)]
        elif(Nk>6 and i%Nk==4):
            temp=subWord(temp)
            
        line=[]
        for k in range(4):
            line.append(word[i-Nk][k]^temp[k])
        word.append(line)
        i=i+1
    return word

def AddRoundKey(state,word):
    for r in range(4):
        for c in range(Nb):
            state[r][c]=state[r][c] ^ word[c][r]
    return state

def SubBytes(state):
    for r in range(4):
        for c in range(Nb):
            state[r][c]=Sbox[state[r][c]]
    return state

def ShiftRows(state):
    newstate=[]
    for i in range(4):
        newstate.append(state[i])
    newstate[1][0], newstate[1][1], newstate[1][2], newstate[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    newstate[2][0], newstate[2][1], newstate[2][2], newstate[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    newstate[3][0], newstate[3][1], newstate[3][2], newstate[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    return newstate

def xtime(a,n=1):
    for i in range(n):
        if a & 0x80:   
            a = a << 1
            a ^= 0x1B
        else:
            a = a << 1
    return a & 0xFF

def MixColumns(state):
    for i in range(Nb):
        state=MixOneColumn(state,i)
    return state

def MixOneColumn(state,c):
    state0, state1, state2, state3 =state[0][c],state[1][c],state[2][c],state[3][c]
    state[0][c]=xtime(state0) ^ (xtime(state1) ^ state1) ^ state2 ^ state3
    state[1][c]=state0 ^ xtime(state1) ^ (xtime(state2)^ state2) ^ state3
    state[2][c]= state0 ^ state1 ^ xtime(state2) ^ (xtime(state3) ^ state3)
    state[3][c]= (xtime(state0) ^ state0) ^ state1 ^ state2 ^ xtime(state3)
    return state

#decrypt

def decrypt(input,word): 
    state = []
    for r in range(4):
        temp=[]
        for c in range(Nb):
            temp.append(input[r+4*c])
        state.append(temp)
    state=AddRoundKey(state, word[Nr*Nb: (Nr+1)*Nb])
    round=Nr-1
    while(round>=1):
            state=InvShiftRows(state)
            state=InvSubBytes(state)
            state=AddRoundKey(state,word[round*Nb : (round+1)*Nb])
            state=InvMixColumns(state)
            round=round-1
    state=InvShiftRows(state)
    state=InvSubBytes(state)
    state=AddRoundKey(state, word[0: Nb])

    output = []
    for j in range(Nb):
        for i in range(4):
            output.append(state[i][j])
    
    return output



def InvShiftRows(state):
    newstate=[]
    for i in range(4):
        newstate.append(state[i])
    newstate[1][0], newstate[1][1], newstate[1][2], newstate[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    newstate[2][0], newstate[2][1], newstate[2][2], newstate[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    newstate[3][0], newstate[3][1], newstate[3][2], newstate[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    return newstate

def InvSubBytes(state):
    for r in range(4):
        for c in range(Nb):
            state[r][c]=InvSbox[state[r][c]]
    return state

def InvMixColumns(state):
    for i in range(Nb):
        state=InvMixOneColumn(state,i)
    return state

def InvMixOneColumn(state,c):
    state0, state1, state2, state3 =state[0][c],state[1][c],state[2][c],state[3][c]
    '''
    s0 = 0e*so + 0b*s1 + 0d*s2 + 09*s3
    s1 = 09*so + 0e*s1 + 0b*s2 + 0d*s3
    s2 = 0d*s0 + 09*s1 + 0e*s2 + 0b*s3
    s3 = 0b*s0 + 0d*s1 + 09*s2 + 0e*s3
    '''
    #precalculate the x_time i'll need
    xtime1_s0, xtime1_s1, xtime1_s2, xtime1_s3 = xtime(state0), xtime(state1), xtime(state2), xtime(state3)
    xtime2_s0, xtime2_s1, xtime2_s2, xtime2_s3 =xtime(xtime1_s0), xtime(xtime1_s1), xtime(xtime1_s2), xtime(xtime1_s3)
    xtime3_s0, xtime3_s1, xtime3_s2, xtime3_s3=xtime(xtime2_s0), xtime(xtime2_s1), xtime(xtime2_s2), xtime(xtime2_s3)
    
    state[0][c]=(xtime3_s0 ^ xtime2_s0 ^ xtime1_s0) ^ (xtime3_s1 ^ xtime1_s1 ^ state1) ^ (xtime3_s2 ^ xtime2_s2 ^ state2) ^ (xtime3_s3 ^ state3)
    state[1][c]=(xtime3_s0 ^ state0) ^ (xtime3_s1 ^ xtime2_s1 ^ xtime1_s1 ) ^ (xtime3_s2 ^ xtime1_s2 ^ state2) ^ (xtime3_s3 ^ xtime2_s3 ^ state3)
    state[2][c]=(xtime3_s0 ^ xtime2_s0 ^ state0) ^ (xtime3_s1 ^ state1) ^ (xtime3_s2 ^ xtime2_s2 ^ xtime1_s2) ^ (xtime3_s3 ^ xtime1_s3 ^ state3)
    state[3][c]=(xtime3_s0 ^ xtime1_s0 ^ state0) ^ (xtime3_s1 ^ xtime2_s1 ^ state1) ^ (xtime3_s2 ^ state2) ^ (xtime3_s3 ^ xtime2_s3^ xtime1_s3)

    return state


#---------------------------------ECB-----------------------------
def ecb(text,key):
    
    word=key
    
    l=len(text)
    output=[]
    for c in range(int(l/16)):
        input=[]
        for i in range(4*Nb):
            cell=hex(ord(text[4*Nb*c + i]))
            input.append(int(cell,16))
        out=encrypt(input,word)
        for n in out:
            output.append(hex(n))
    c=int(l/16)
    input=[]
    for i in range(l%16):
        cell=hex(ord(text[4*Nb*c + i]))
        input.append(int(cell,16))
    #add padding
    numpad=16- l%16
    for i in range(numpad):
        input.append(numpad)
    out=encrypt(input,word)
    for n in out:
        output.append(hex(n))
    return output

def inv_ecb(cipher,key):

    word=key
    
    plaintext=""
    l=len(cipher)
    for c in range(int(l/16)):
        input=[]
        for i in range(4*Nb):
            input.append(int(cipher[4*Nb*c +i],16))
        out=decrypt(input,word)
        for x in out:
            plaintext=plaintext + chr(x)
    #removepadding
    lastchar=plaintext[-1]
    idx=plaintext.find(lastchar,l-16)
    newidx=idx
    for i in range(idx,l):
        if(plaintext[i]!=lastchar):
            newidx=plaintext.find(lastchar,newidx)
            i=newidx

    plaintext=plaintext[0:newidx]
    return plaintext


#---------------------------------CBC-------------------------------

def cbc(text,key,iv):
    word=key
    
    l=len(text)
    numpad=16- l%16
    char=chr(numpad)
    for i in range(numpad):
        text=text+char
    output=[]
    l=len(text)
    for c in range(int(l/16)):
        input=[]
        for i in range(4*Nb):
            cell=hex(ord(text[4*Nb*c + i]))
            xored = int(cell,16) ^ iv[i]
            input.append(xored)
        iv=encrypt(input,word)
        out=iv
        for n in out:
            output.append(hex(n))
    return output

def inv_cbc(cipher,key,iv):

    word=key
    
    plaintext=""
    l=len(cipher)
    for c in range(int(l/16)):
        input=[]
        out=[]
        for i in range(4*Nb):
            input.append(int(cipher[4*Nb*c +i],16))
        text= decrypt(input,word)
        for i in range(4*Nb):
            out.append(text[i] ^ iv[i])
        iv=input
        for x in out:
            plaintext=plaintext + chr(x)
    #removepadding
    lastchar=plaintext[-1]
    idx=plaintext.find(lastchar,l-16)
    newidx=idx
    for i in range(idx,l):
        if(plaintext[i]!=lastchar):
            newidx=plaintext.find(lastchar,newidx)
            i=newidx

    plaintext=plaintext[0:newidx]
    return plaintext


#---------------------------------CFB-------------------------------

def cfb(text,key,IV):

    word=key
    
    l=len(text)
    output=[]
    iv=IV
    for c in range(int(l/16)):
        input=[]
        crypt=encrypt(iv,word)
        for i in range(4*Nb):
            cell=hex(ord(text[4*Nb*c + i]))
            xored = int(crypt[i]) ^ int(cell,16) 
            input.append(xored)
        iv=input
        for n in iv:
            output.append(hex(n))
    c=int(l/16)
    input=[]
    out=[]
    crypt=encrypt(iv,word)
    for i in range(l%16):
        cell=hex(ord(text[4*Nb*c + i]))
        xored = int(crypt[i]) ^ int(cell,16) 
        input.append(xored)
    iv=input
    for n in iv:
        output.append(hex(n))
    return output

def inv_cfb(cipher,key,iv):

    word=key
    
    plaintext=""
    l=len(cipher)
    for c in range(int(l/16)):
        input=[]
        out=[]
        crypt=encrypt(iv,word)
        for i in range(4*Nb):
            input.append(int(cipher[4*Nb*c +i],16))
            out.append(int(cipher[4*Nb*c +i],16) ^ crypt[i])
        iv=input
        for x in out:
            plaintext=plaintext + chr(x)
    c=int(l/16)
    input=[]
    out=[]
    crypt=encrypt(iv,word)
    for i in range(l%16):
        input.append(int(cipher[4*Nb*c +i],16))
        out.append(int(cipher[4*Nb*c +i],16) ^ crypt[i])
    iv=input
    for x in out:
        plaintext=plaintext + chr(x)
        
    return plaintext

#---------------------------------OFB-------------------------------


def ofb(text,key,IV):

    word=key
    
    l=len(text)
    output=[]
    iv=IV
    for c in range(int(l/16)):
        out=[]
        crypt=encrypt(iv,word)
        for i in range(4*Nb):
            cell=hex(ord(text[4*Nb*c + i]))
            xored = int(crypt[i]) ^ int(cell,16) 
            out.append(xored)
        iv=crypt
        for n in out:
            output.append(hex(n))
    c=int(l/16)
    out=[]
    crypt=encrypt(iv,word)
    for i in range(l%16):
        cell=hex(ord(text[4*Nb*c + i]))
        xored = int(crypt[i]) ^ int(cell,16) 
        out.append(xored)
    for n in out:
        output.append(hex(n))
    return output

def inv_ofb(cipher,key,iv):

    word=key
    
    plaintext=""
    l=len(cipher)
    for c in range(int(l/16)):
        out=[]
        crypt=encrypt(iv,word)
        for i in range(4*Nb):
            out.append(int(cipher[4*Nb*c +i],16) ^ crypt[i])
        iv=crypt
        for x in out:
            plaintext=plaintext + chr(x)
    c=int(l/16)
    out=[]
    crypt=encrypt(iv,word)
    for i in range(l%16):
        out.append(int(cipher[4*Nb*c +i],16) ^ crypt[i])
    for x in out:
        plaintext=plaintext + chr(x)
        
    return plaintext

#---------------------------------CTR-----------------------------

def incr_counter(counter):
    i=15
    while(i>7):
        if(counter[i]==255):
            counter[i]=0
        else:
            counter[i]=counter[i]+1
            break
        i=i-1
    return counter

def ctr(text,key,nonce):

    word=key
    
    l=len(text)
    output=[]

    counter=[]
    for i in range(16):
        if(i<8):
            counter.append(nonce[i])
        else:
            counter.append(0)
    
    for c in range(int(l/16)):
        input=[]
        out=encrypt(counter,word)
        for i in range(4*Nb):
            cell=hex(ord(text[4*Nb*c + i]))
            xored=int(cell,16) ^ int(out[i])
            output.append(hex(xored))
        counter=incr_counter(counter)

    c=int(l/16)
    input=[]
    out=encrypt(counter,word)
    for i in range(l%16):
        cell=hex(ord(text[4*Nb*c + i]))
        xored=int(cell,16) ^ int(out[i])
        output.append(hex(xored))

    return output

def inv_ctr(cipher,key,nonce):

    word=key
    
    plaintext=""
    l=len(cipher)

    counter=[]
    for i in range(16):
        if(i<8):
            counter.append(nonce[i])
        else:
            counter.append(0)
    
    for c in range(int(l/16)):
        output=[]
        out=encrypt(counter,word)
        for i in range(4*Nb):
            xored= int(cipher[4*Nb*c +i],16) ^ int(out[i])
            plaintext = plaintext + chr(xored)
        counter=incr_counter(counter)
        
    c=int(l/16)
    input=[]
    out=encrypt(counter,word)
    for i in range(l%16):
        xored= int(cipher[4*Nb*c +i],16) ^ int(out[i])
        plaintext = plaintext + chr(xored)
            
    return plaintext


#------------------------------MAIN---------------------------------

#aux functions to call the mode of operation
def do_ECB(string,word):
    print("\n -----ECB----")
    en_start=time.time()
    output=ecb(string,word)
    en_rtime=time.time() - en_start

    print("encryption running time: "+str(en_rtime)+" sec")

    de_start=time.time()
    plaintext=inv_ecb(output,word)
    de_rtime=time.time() - de_start
    
    
    print("decryption running time: "+str(de_rtime)+" sec")

    return output,plaintext

def do_CBC(string,word):
    print("\n -----CBC----")
    iv=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    
    en_start=time.time()
    output=cbc(string,word,iv)
    en_rtime=time.time() - en_start

    print("encryption running time: "+str(en_rtime)+" sec")

    de_start=time.time()
    plaintext=inv_cbc(output,word,iv)
    de_rtime=time.time() - de_start
    
    print("decryption running time: "+str(de_rtime)+" sec")

    return output,plaintext

def do_CFB(string,word):
    print("\n -----CFB----")
    iv=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]

    en_start=time.time()
    output=cfb(string,word,iv)
    en_rtime=time.time() - en_start

    print("encryption running time: "+str(en_rtime)+" sec")

    de_start=time.time()
    plaintext=inv_cfb(output,word,iv)
    de_rtime=time.time() - de_start

    print("decryption running time: "+str(de_rtime)+" sec")

    return output,plaintext

def do_OFB(string,word):
    print("\n -----OFB----")
    iv=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]

    en_start=time.time()
    output=ofb(string,word,iv)
    en_rtime=time.time() - en_start
    
    print("encryption running time: "+str(en_rtime)+" sec")

    de_start=time.time()
    plaintext=inv_ofb(output,word,iv)
    de_rtime=time.time() - de_start

    print("decryption running time: "+str(de_rtime)+" sec")

    return output,plaintext

def do_CTR(string,word):
    print("\n -----CTR----")
    nonce=[0,1,2,3,4,5,6,7]

    en_start=time.time()
    output=ctr(string,word,nonce)
    en_rtime=time.time() - en_start

    print("encryption running time: "+str(en_rtime)+" sec")

    de_start=time.time()
    plaintext=inv_ctr(output,word,nonce)
    de_rtime=time.time() - de_start
    
    print("decryption running time: "+str(de_rtime)+" sec")

    return output,plaintext


def how_to_print(printed):
    if(printed=="t"):
        print("\n ciphertext \n")
        print(output)
        print("\n plaintext \n")
        print(plaintext)
    elif(printed=="n"):
        return
    else:
        file=open("results.txt","w")
        file.write("\n ciphertext \n"+str(output)+"\n plaintext \n"+str(plaintext))
        file.close
        print("\n printed on 'results.txt' \n")
    
#-----------------------------------------
    
Nk=0
Nk=0
Nb=4
textkey="myflaaagismyflag"
textkey192="myflaaagismyflag4g5hjlrr"
textkey256="myflaaagismyflag4g5hjl9uf4gti8st"
string="ciao mamma guarda come mi diverto"
lenkey=len(textkey)
if(lenkey==16):
    Nk=4
    Nr=10
elif(lenkey==24):
    Nk=6
    Nr=12
elif(lenkey==32):
    Nk=8
    Nr=14

input_string=raw_input("Do you want to encrypt a string or a file? (s/f) \n")
if(input_string=="s"):
    string=raw_input("Insert the string you want to encrypt \n")
else:
    name=raw_input("Insert the name of the file \n")
    file=open(name,"r")
    string=file.read()
    file.close()

keytx=""
len_key=raw_input("Choose the lenght of the key (128/192/256) \n")
if(len_key=="128"):
    keytx=textkey
elif(len_key=="192"):
    keytx=textkey192
else:
    keytx=textkey256

#key expansion
key=[]
for i in range(4*Nk):
    cell=hex(ord(textkey[i]))
    key.append(cell)
word=KeyExpansion(key,Nk)

    
mode_of_op=raw_input("Choose a mode of operation (ECB/CBC/CFB/OFB/CTR) \n")
if(mode_of_op=="ECB"):
    output, plaintext = do_ECB(string,word)
    printed=raw_input("Do you want to see the ciphertext and plaintex on a terminal or a file or nowhere? (t/f/n) \n")
    how_to_print(printed)
        
elif(mode_of_op=="CBC"):
    output, plaintext = do_CBC(string,word)
    printed=raw_input("Do you want to see the ciphertext and plaintex on a terminal or a file or nowhere? (t/f/n) \n")
    how_to_print(printed)
elif(mode_of_op=="CFB"):
    output, plaintext = do_CFB(string,word)
    printed=raw_input("Do you want to see the ciphertext and plaintex on a terminal or a file or nowhere? (t/f/n) \n")
    how_to_print(printed)
elif(mode_of_op=="OFB"):
    output, plaintext = do_OFB(string,word)
    printed=raw_input("Do you want to see the ciphertext and plaintex on a terminal or a file or nowhere? (t/f/n) \n")
    how_to_print(printed)
else:
    output, plaintext = do_CTR(string,word)
    printed=raw_input("Do you want to see the ciphertext and plaintex on a terminal or a file or nowhere? (t/f/n) \n")
    how_to_print(printed)
    
    

