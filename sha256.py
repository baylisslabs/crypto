import sys, struct, hashlib
 
# constants [4.2.2]
K =  [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ]
		

#
# compression functions [4.1.2]
#

def rotr(n,x):
    return (x >> n) | (x << (32-n))
     
def E0(x):
    return rotr(2,  x) ^ rotr(13, x) ^ rotr(22, x);

def E1(x):
    return rotr(6,  x) ^ rotr(11, x) ^ rotr(25, x)

def o0(x):
    return rotr(7,  x) ^ rotr(18, x) ^ (x>>3)

def o1(x):
    return rotr(17, x) ^ rotr(19, x) ^ (x>>10)

def Ch(x,y,z):
    return (x & y) ^ (~x & z)

def Maj(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)


# RETURN THE SHA-256 HASH    
def hash(msg):

    ## PREPROCESSING 
        
    # calculate number of blocks allowing for padding(byte) and 64-bit length
    bz = 64
    N = (len(msg)+72)/64
    M = [[]]*N
    msg_len_bits = len(msg)*8

    # add trailing '1' bit (+ 0's padding) to string [5.1.1]
    msg += '\x80'    

    for n in range(0,N):
        blk = struct.pack('64s',msg[bz*n:min(bz*n+bz,len(msg))])
        m = [0x0] * (bz/4)
        for i in range(0,bz/4):
            m[i] = struct.unpack('>L',blk[i*4:i*4+4])[0]
        M[n] = m
    
    # add length (in bits) into final pair of 32-bit integers (big-endian) [5.1.1]       
    M[-1][14] = (msg_len_bits >> 32) & 0xffffffff
    M[-1][15] = msg_len_bits & 0xffffffff

    # HASH COMPUTATION [6.1.2]
    # initial hash value [5.3.1]		

    H = [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ]
    W = [0]*64  
    
    for i in range(0,N):
        # 1 - prepare message schedule 'W'
        for t in range(0,16):
            W[t] = M[i][t]
            
        for t in range(16,64):
            W[t] = (o1(W[t-2]) + W[t-7] + o0(W[t-15]) + W[t-16]) & 0xffffffff

        # 2 - initialise working variables a, b, c, d, e, f, g, h with previous hash value
        a,b,c,d,e,f,g,h = H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]

        # 3 - main loop (note 'addition modulo 2^32')
        for t in range(0,64):
            T1 = h + E1(e) + Ch(e, f, g) + K[t] + W[t]
            T2 =     E0(a) + Maj(a, b, c)
            h = g
            g = f
            f = e
            e = (d + T1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xffffffff
        
        # 4 - compute the new intermediate hash value (note 'addition modulo 2^32')
        H[0] = (H[0]+a) & 0xffffffff
        H[1] = (H[1]+b) & 0xffffffff
        H[2] = (H[2]+c) & 0xffffffff 
        H[3] = (H[3]+d) & 0xffffffff
        H[4] = (H[4]+e) & 0xffffffff
        H[5] = (H[5]+f) & 0xffffffff
        H[6] = (H[6]+g) & 0xffffffff
        H[7] = (H[7]+h) & 0xffffffff
    
    return struct.pack(">LLLLLLLL",*H)
		
               
# COMMAND LINE CHECKER
if __name__=="__main__":
    msg = sys.argv[1]
    print msg, hash(msg).encode('hex'), hashlib.sha256(msg).digest().encode('hex')
