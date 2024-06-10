from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes 
AES_MODE = AES.MODE_ECB

def AES_hash( m ): # m is the input message in bytes 
    H0 = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' # initial vector 2 ** 128 - 1 
    m_size = len( m ) # in bytes 
    
    ### padding ### 
    append = m_size * 8 # number of bits in the original file; it's going to be appended to m 
    mul = int( m_size / 16 ) # multiple of the block size of the message
    
    if mul % 2 == 0 : # the last block is the odd block ->> pad the last block 
        m = m.ljust( 16 * ( mul + 1 ) , b'\0' )
    else: # the last block is the even block ->> pad the last block and append a block of 0's to it 
        m = m.ljust( 16 * ( mul + 2 ) , b'\0' ) 
    
    append = append.to_bytes( 16 , 'big') # convert the appended number into a 128-bit byte number 
    m = m + append # append the appended number 
    m_size = len( m ) # update the size of m after padding 
    print('padded m: ' + str( m ) + ' size: ' + str( m_size ) + ' (bytes)') 
    
    ### Encryption ### 
    P = H0 # plaintext 
    C = '' # ciphertext 
    n = int( m_size / 16 ) # multiple of the block size 
    for i in range( 0 , n ): # 16 bytes per block ->> total n blocks(rounds)
        print('\nget H' + str( i + 1 ) )
        K = m[ i * 16 : i * 16 + 16 ] # key; use mi as the key  
        E = AES.new( K , AES_MODE ) 
        print('K: ' + str( K ) )
        print('P: ' + str( P ) ) 
        C = E.encrypt( P ) 
        print('C: ' + str( C ) )  
        P = ( XOR_bytes( P , C ) ) # now P is Hi+1
        print('H' + str( i + 1 ) + ' = P XOR C: ' + str( P ) )
     
    # get Hn+1
    E = AES.new( P , AES_MODE ) 
    C = E.encrypt( P ) # P is Hn 
    print('\nto get H = Hn + 1') 
    print('Hn: ' + str( P ) ) 
    print('EHn( Hn ): ' + str( C ) ) 
    H = XOR_bytes( C , P ) 
    print('H = Hn+1 = EHn( Hn ) xor Hn: ' + str( H ) + '\n' )  
    return H 

def XOR_bytes( b1 , b2 ): # 128 bits 
    res = b''
    for i in range( 0 , len( b1 ) ): # XOR byte by byte 
        res = res + ( b1[ i ] ^ b2[ i ] ).to_bytes( 1 , 'big' ) # b1[i] is in type int 
    return res 

### main function ###
message = 'NDHUCSIE東華資工' 
m = message.encode('utf-8') 
print('\ninput message(m): ' + message + ' => ' + str( m ) + ' size of m: ' + str( len( m ) ) + ' bytes / ' + str( len( m ) * 8 ) + ' bits' ) 
H = AES_hash( m ) 
print('AES_Hash( m ): ' + str( H ) ) 

#######################################################################################################################################################
### utf-8 ### 
# 1 letter: 8 bits => 2 hex => 1 byte 
# 1 word: 24 bits => 6 hex => 3 bytes  

### 
# 128 bits = 16 bytes = 32 Hex 