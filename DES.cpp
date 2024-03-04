#include<iostream>
using namespace std ; 
#define debug  
//#define debug_f
//#define debug_sub
//#define testKey

int Key[ 64 ] =   { //0001 0011 0011 0100 0101 0111 0111 1001 1001 1011 1011 1100 1101 1111 1111 0001
                            0 , 0 , 0 , 1 , 0 , 0 , 1 , 1 , 
                            0 , 0 , 1 , 1 , 0 , 1 , 0 , 0 , 
                            0 , 1 , 0 , 1 , 0 , 1 , 1 , 1 , 
                            0 , 1 , 1 , 1 , 1 , 0 , 0 , 1 ,
                            1 , 0 , 0 , 1 , 1 , 0 , 1 , 1 , 
                            1 , 0 , 1 , 1 , 1 , 1 , 0 , 0 ,
                            1 , 1 , 0 , 1 , 1 , 1 , 1 , 1 ,
                            1 , 1 , 1 , 1 , 0 , 0 , 0 , 1 
                        };

void print( int *arr , int len )
{
    for( int i = 0 ; i < len ; i++ )
    {
        cout << arr[ i ] ;
    }cout << endl ; 
}

class DES
{
public:
    DES(){}
    int *encrypt( int *in )
    {//64-bit input 
        //IP 
        in = initial_Permutation( in ) ; // 64-bit
        //divide into 2 parts 
        int *L = new int[ 32 ] , *R = new int[ 32 ] , *tmp , *out ; 
        for( int i = 0 ; i < 32 ; i++ )
        {
            L[ i ] = in[ i ] ; 
            R[ i ] = in[ 32 + i ] ; 
        } 
        #ifdef debug 
        cout << "IP:" ; 
        print( in , 64 ) ;  
        #endif 
        int *k = permutation_Choice1( Key ) ;//56-bit
        int *curKey = NULL ; 
        for( int i = 1 ; i <= 16 ; i++ )
        {//16 rounds 
            /**** L , R ****/
            #ifdef debug 
            cout << "L" << i - 1 << ":" ; 
            print( L , 32 ) ; 
            cout << "R" << i - 1 << ":" ; 
            print( R , 32 ) ; 
            #endif 
            //gernerate the next key
            left_Shift( k , i ) ; 
            curKey = permutation_Choice2( k ) ; //48-bit

            //encrypt the right part
            out = f( R , curKey ) ;//32-bit  
            /**** tmp , R ****/
            tmp = R ; 
            R = XOR( L , out , 32 ) ;//32-bit 

            #ifdef debug  
            cout << "Key " << i << ":" ; 
            print( curKey , 48 ) ; 
            cout << "out:" ; 
            print( out , 32 ) ; 
            cout << endl ; 
            #endif  
            
            delete L ; /********** L = in ; delete L ;  Cannot delete the memoey that is NOT allocated by new ********/
            /**** L , R ****/
            L = tmp ; 
            delete out ; 
            delete curKey ;
        }

        #ifdef debug
        cout << "L16:" ; 
        print( L , 32 ) ; 
        cout << "R16:" ; 
        print( R , 32 ) ; 
        #endif

        //combine the 2 parts 
        tmp = new int[ 64 ] ; 
        for( int i = 0 ; i < 32 ; i++ )
            tmp[ i ] = R[ i ] ; 
        for( int i = 0 ; i < 32 ; i++ )
            tmp[ i + 32 ] = L[ i ] ; 
        
        delete L ; 
        delete R ; 
        //FP(IP^(-1))
        int *ciphertext = final_Permutaion( tmp ) ; 
        delete tmp ; 
        return ciphertext ; 
    }
    #ifdef testKey
    void test_Key( int *key )
    {
        int *dropped = permutation_Choice1( key ) ; //56-bit 
        cout << "dropped:" ; 
        print( dropped , 56 ) ;//dropped will be (C0, D1) to (C16, D16)
        for( int i = 1 ; i <= 16 ; i++ )
        {
            left_Shift( dropped , i ) ; //56-bit 
            cout << "Shifted round " << i << ":\n" ; 
            print( dropped , 56 ) ; //56-bit
            
            int *curKey = permutation_Choice2( dropped ) ; //48-bit 
            cout << "Key " << i << ":\n" ; 
            print( curKey , 48 ) ; 
            delete curKey ; 
        } 
        delete dropped ; 
    }
    #endif 
private:
    int IP[ 64 ] =  { 
                        58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 , 
                        60 , 52 , 44 , 36 , 28 , 20 , 12 , 4 ,
                        62 , 54 , 46 , 38 , 30 , 22 , 14 , 6 ,
                        64 , 56 , 48 , 40 , 32 , 24 , 16 , 8 ,
                        57 , 49 , 41 , 33 , 25 , 17 , 9  , 1 ,
                        59 , 51 , 43 , 35 , 27 , 19 , 11 , 3 ,
                        61 , 53 , 45 , 37 , 29 , 21 , 13 , 5 ,
                        63 , 55 , 47 , 39 , 31 , 23 , 15 , 7 
                    }; 
    int E_box[ 48 ] =   {
                            32 , 1 , 2 , 3 , 4 , 5 ,
                            4 , 5 , 6 , 7 , 8 , 9 ,
                            8 , 9 , 10 , 11 , 12 , 13 ,
                            12 , 13 , 14 , 15 , 16 , 17 ,
                            16 , 17 , 18 , 19 , 20 , 21 ,
                            20 , 21 , 22 , 23 , 24 , 25 ,
                            24 , 25 , 26 , 27 , 28 , 29 ,
                            28 , 29 , 30 , 31 , 32 , 1 
                        };
                
    int S_box[ 8 ][ 4 ][ 16 ] = {
                                    {
                                        { 14 , 4 , 13 , 1 , 2 , 15 , 11 , 8 , 3 , 10 , 6 , 12 , 5 , 9 , 0 , 7 },
                                        { 0 , 15 , 7 , 4 , 14 , 2 , 13 , 1 , 10 , 6 , 12 , 11 , 9 , 5 , 3 , 8 },
                                        { 4 , 1 , 14 , 8 , 13 , 6 , 2 , 11 , 15 , 12 , 9 , 7 , 3 , 10 , 5 , 0 },
                                        { 15 , 12 , 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11 , 3 , 14 , 10 , 0 , 6 , 13 }
                                    },
                                    {
                                        { 15 , 1 , 8 , 14 , 6 , 11 , 3 , 4 , 9 , 7 , 2 , 13 , 12 , 0 , 5 , 10 }, 
                                        { 3 , 13 , 4 , 7 , 15 , 2 , 8 , 14 , 12 , 0 , 1 , 10 , 6 , 9 , 11 , 5 }, 
                                        { 0 , 14 , 7 , 11 , 10 , 4 , 13 , 1 , 5 , 8 , 12 , 6 , 9 , 3 , 2 , 15 }, 
                                        { 13 , 8 , 10 , 1 , 3 , 15 , 4 , 2 , 11 , 6 , 7 , 12 , 0 , 5 , 14 , 9 } 
                                    },
                                    {
                                        { 10 , 0 , 9 , 14 , 6 , 3 , 15 , 5 , 1 , 13 , 12 , 7 , 11 , 4 , 2 ,8 }, 
                                        { 13 , 7 , 0 , 9 , 3 , 4 , 6, 10 , 2 , 8 , 5 , 14 , 12 , 11 , 15 , 1 }, 
                                        { 13 , 6 , 4 , 9 , 8 , 15 , 3 , 0 , 11 , 1 , 2 , 12 , 5 , 10 , 14 , 7 }, 
                                        { 1 , 10 , 13 , 0 , 6 , 9 , 8 , 7 , 4 , 15 , 14 , 3 , 11 , 5 , 2 , 12 } 
                                    },
                                    {
                                        { 7 , 13 , 14 , 3 , 0 , 6 , 9 , 10 , 1 , 2 , 8 , 5 , 11 , 12 , 4 , 15 }, 
                                        { 13 , 8 , 11 , 5 , 6 , 15 , 0 , 3 , 4 , 7 , 2 , 12 , 1 , 10 , 14 , 9 }, 
                                        { 10 , 6 , 9 , 0 , 12 , 11 , 7 , 13 , 15 , 1 , 3 , 14 , 5 , 2 , 8 , 4 }, 
                                        { 3 , 15 , 0 , 6 , 10 , 1 , 13 , 8 , 9 , 4 , 5 , 11 , 12 , 7 , 2 , 14 } 
                                    },
                                    {
                                        { 2 , 12 , 4 , 1 , 7 , 10 , 11 , 6 , 8 , 5 , 3 , 15 , 13 , 0 , 14 , 9 }, 
                                        { 14 , 11 , 2 ,12 , 4 , 7 , 13 , 1 , 5 , 0 , 15 , 10 , 3 , 9 , 8 , 6 }, 
                                        { 4 , 2 , 1 , 11 , 10 , 13 , 7 , 8 , 15 , 9 , 12 , 5 , 6 , 3 , 0 , 14 }, 
                                        { 11 , 8 , 12 , 7 , 1 , 14 , 2 , 13 , 6 , 15 , 0 , 9 , 10 , 4 , 5 , 3 } 
                                    },
                                    {
                                        { 12 , 1 , 10 , 15 , 9 , 2 , 6 , 8 , 0 , 13 , 3 , 4 , 14 , 7 , 5 , 11 }, 
                                        { 10 , 15 , 4 , 2 , 7 , 12 , 9 , 5 , 6 , 1 , 13 , 14 , 0 , 11 , 3 , 8 }, 
                                        { 9 , 14 , 15 , 5 , 2 , 8 , 12 , 3 , 7 , 0 , 4 , 10 , 1 , 13 , 11 , 6 }, 
                                        { 4 , 3 , 2 , 12 , 9 , 5 , 15 , 10 , 11 , 14 , 1 , 7 , 6 , 0 ,  8 , 13 } 
                                    },
                                    {
                                        { 4 , 11 , 2 , 14 , 15 , 0 , 8 , 13 , 3 , 12 , 9 , 7 , 5 , 10 , 6 , 1 }, 
                                        { 13 , 0 , 11 , 7 , 4 , 9 , 1 , 10 , 14 , 3 , 5 , 12 , 2 , 15 , 8 , 6 }, 
                                        { 1 , 4 , 11 , 13 , 12 , 3 , 7 , 14 , 10 , 15 , 6 , 8 , 0 , 5 , 9 , 2 }, 
                                        { 6 , 11 , 13 , 8 , 1 , 4 , 10 , 7 , 9 , 5 , 0 , 15 , 14 , 2 , 3 , 12 } 
                                    },
                                    {
                                        { 13 , 2 , 8 , 4 , 6 , 15 , 11 , 1 , 10 , 9 , 3 , 14 , 5 , 0 , 12 , 7 }, 
                                        { 1 , 15 , 13 , 8, 10 , 3 , 7 , 4 , 12 , 5 , 6 , 11 , 0 , 14 , 9 , 2 }, 
                                        { 7 , 11 , 4 , 1 , 9 , 12 , 14 , 2 , 0 , 6 , 10 , 13 , 15 , 3 , 5 , 8 }, 
                                        { 2 , 1 , 14 , 7 , 4 , 10 , 8 , 13 , 15 , 12 , 9 , 0 , 3 , 5 , 6 , 11 } 
                                    }
                                };
    int P[ 32 ] =   {
                        16 , 7 , 20 , 21 , 29 , 12 , 28 , 17 ,
                        1 , 15 , 23 , 26 , 5 , 18 , 31 , 10 ,
                        2 , 8 , 24 , 14 , 32 , 27 , 3 , 9 ,
                        19 , 13 , 30 , 6 , 22 , 11 , 4 , 25 
                    }; 
    int FP[ 64 ] =  { 	
                        40 , 8 , 48 , 16 , 56 , 24 , 64 , 32 ,
                        39 , 7 , 47 , 15 , 55 , 23 , 63 , 31 ,
                        38 , 6 , 46 , 14 , 54 , 22 , 62 , 30 ,
                        37 , 5 , 45 , 13 , 53 , 21 , 61 , 29 ,
                        36 , 4 , 44 , 12 , 52 , 20 , 60 , 28 ,
                        35 , 3 , 43 , 11 , 51 , 19 , 59 , 27 ,
                        34 , 2 , 42 , 10 , 50 , 18 , 58 , 26 ,
                        33 , 1 , 41 , 9 , 49 , 17 , 57 , 25 
                    };
    int PC1[ 56 ] = {
                        57 , 49 , 41 , 33 , 25 , 17 , 9 , 1 , 
                        58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 , 
                        59 , 51 , 43 , 35 , 27 , 19 , 11 , 3 , 
                        60 , 52 , 44 , 36 , 63 , 55 , 47 , 39 , 
                        31 , 23 , 15 , 7 , 62 , 54 , 46 , 38 , 
                        30 , 22 , 14 , 6 , 61 , 53 , 45 , 37 , 
                        29 , 21 , 13 , 5 , 28 , 20 , 12 , 4 
                    };
    int PC2[ 48 ] = {  
                        14 , 17 , 11 , 24 , 1 , 5 ,
                        3 , 28 , 15 , 6 , 21 , 10 ,
                        23 , 19 , 12 , 4 , 26 , 8 ,
                        16 , 7 , 27 , 20 , 13 , 2 ,
                        41 , 52 , 31 , 37 , 47 , 55 ,
                        30 , 40 , 51 , 45 , 33 , 48 ,
                        44 , 49 , 39 , 56 , 34 , 53 ,
                        46 , 42 , 50 , 36 , 29 , 32 
                   };
    int *Expansion( int *R ) 
    {//32-bit right part 
        int *tmp = new int[ 48 ] ; 
        for( int i = 0 ; i < 48 ; i++ )
        {
            tmp[ i ] = R[ E_box[ i ] - 1 ] ;  
        }
        return tmp ; 
    }
    int *XOR( int *c1 , int *c2 , int len )
    {
        int *tmp = new int[ len ] ; 
        for( int i = 0 ; i < len ; i++ )
        {
            tmp[ i ] = c1[ i ] - c2[ i ] == 0 ? 0 : 1 ; 
        }
        return tmp ; 
    }
    int *Substitution( int *in )
    {//48-bit input 
        int *tmp = new int[ 32 ] ; 
        for( int i = 0 ; i < 8 ; i++ )
        {//there are 8 S-boxes 
            int *temp = in + i * 6 ;//each box maps 6 bits to 4 bits  
            int row_idx = temp[ 0 ] * 2 + temp[ 5 ] * 1 ; 
            int col_idx = temp[ 1 ] * 8 + temp[ 2 ] * 4 + temp[ 3 ] * 2 + temp[ 4 ] * 1 ; 
            int mapped_res = S_box[ i ][ row_idx ][ col_idx ] ; 

            #ifdef debug_sub
            cout << "cur 6 bits:" << temp[ 0 ] << temp[ 1 ] << temp[ 2 ] << temp[ 3 ] << temp[ 4 ] << temp[ 5 ] << endl ; 
            cout << "row_idx:" << row_idx << " col_idx:" << col_idx << " mapped result:" << mapped_res << endl ; 
            #endif
            
            //convert the decimal to a 4-bit binary number 
            for( int j = 3 ; j >= 0 ; j-- ) 
            {
                tmp[ i * 4 + j ] = mapped_res % 2 ; 
                mapped_res = mapped_res >> 1 ; 
            }
            
            #ifdef debug_sub
            print( tmp + i * 4 , 4 ) ;  
            #endif
        }
        return tmp ; 
    }
    int *Permutation( int *in )
    {//32-bit input 
        int *tmp = new int[ 32 ] ; 
        for( int i = 0 ; i < 32 ; i++ )
        {
            tmp[ i ] = in[ P[ i ] - 1 ] ; 
        }
        return tmp ; 
    }
    int *f( int *in , int *K )
    {//32-bit input 
        cout << "f BEGIN\n" ; 
        int *cur1 = Expansion( in ) ; //48-bit
        int *cur2 = XOR( K , cur1 , 48 ) ;//48-bit  

        #ifdef debug_f
        cout << "Expansion:" ; 
        print( cur1 , 48 ) ; 
        cout << "E(R) XOR K:" ; 
        print( cur2 , 48 ) ; 
        #endif 

        delete cur1 ; 
        cur1 = Substitution( cur2 ) ;//32-bit 
        delete cur2 ; 
        cur2 = Permutation( cur1 ) ;//32-bit 

        #ifdef debug_f
        cout << "After Substitution:" ; 
        print( cur1 ,32 ) ;
        cout << "After Permutation:" ; 
        print( cur2 , 32 ) ;  
        cout << "f END\n" ; 
        #endif
        
        delete cur1 ; 
        return cur2 ; 
        
    }
    int *initial_Permutation( int *in )
    {//64-bit input 
        int *tmp = new int[ 64 ] ; 
        for( int i = 0 ; i < 64 ; i++ )
        {
            tmp[ i ] = in[ IP[ i ] - 1 ] ; 
        }
        return tmp ; 
    }
    int *final_Permutaion( int *in )
    {//64-bit input 
        int *tmp = new int[ 64 ] ; 
        for( int i = 0 ; i < 64 ; i++ )
        {
            tmp[ i ] = in[ FP[ i ] - 1 ] ; 
        }
        return tmp ; 
    }
    int *permutation_Choice1( int *K )
    {//64-bit Key 
        int *tmp = new int[ 56 ] ; 
        for( int i = 0 ; i < 56 ; i++ )
        {
            tmp[ i ] = K[ PC1[ i ] - 1 ] ; 
        }
        return tmp ; 
    }
    void left_Shift( int *in , int round )
    {//56-bit input 
        if( round == 1 || round == 2 || round == 9 || round == 16 )
        {//shift 1 position 
            //left part
            int first = in[ 0 ] ; 
            for( int i = 0 ; i < 27 ; i++ )
            {
                in[ i ] = in[ i + 1 ] ; 
            }
            in[ 27 ] = first ; 
            //right part 
            first = in[ 28 ] ; 
            for( int i = 28 ; i < 55 ; i++ )
            {
                in[ i ] = in[ i + 1 ] ; 
            }
            in[ 55 ] = first ; 
        } else {//shift 2 positions 
            //left part
            int first = in[ 0 ] , second = in[ 1 ] ;  
            for( int i = 0 ; i < 26 ; i++ )
            {
                in[ i ] = in[ i + 2 ] ; 
            }
            in[ 26 ] = first ;
            in[ 27 ] = second ;  
            //right part 
            first = in[ 28 ] ; 
            second = in[ 29 ] ; 
            for( int i = 28 ; i < 54 ; i++ )
            {
                in[ i ] = in[ i + 2 ] ; 
            }
            in[ 54 ] = first ; 
            in[ 55 ] = second ; 
        }
    }
    int *permutation_Choice2( int *in )
    {//56-bit input 
        int *tmp = new int[ 48 ] ; 
        for( int i = 0 ; i < 48 ; i++ ) 
        {
            tmp[ i ] = in[ PC2[ i ] - 1 ] ; 
        } 
        return tmp ; 
    }
};

int main()
{
    /*
    int plaintext[ 64 ] =  {
                                0 , 0 , 0 , 0 , 0 , 0 , 0 , 1 , 
                                0 , 0 , 1 , 0 , 0 , 0 , 1 , 1 , 
                                0 , 1 , 0 , 0 , 0 , 1 , 0 , 1 , 
                                0 , 1 , 1 , 0 , 0 , 1 , 1 , 1 , 
                                1 , 0 , 0 , 0 , 1 , 0 , 0 , 1 , 
                                1 , 0 , 1 , 0 , 1 , 0 , 1 , 1 , 
                                1 , 1 , 0 , 0 , 1 , 1 , 0 , 1 , 
                                1 , 1 , 1 , 0 , 1 , 1 , 1 , 1
                            };*/
    int plaintext[ 64 ] =  {
                                0 , 1 , 0 , 1 , 1 , 0 , 1 , 0 , 
                                1 , 0 , 0 , 1 , 1 , 0 , 1 , 1 ,
                                0 , 1 , 1 , 1 , 0 , 1 , 0 , 1 ,
                                0 , 1 , 1 , 0 , 1 , 0 , 0 , 0 ,
                                0 , 0 , 0 , 0 , 0 , 1 , 1 , 1 ,
                                0 , 1 , 1 , 1 , 0 , 0 , 1 , 1 ,
                                1 , 1 , 0 , 1 , 1 , 0 , 0 , 0 ,
                                0 , 1 , 0 , 0 , 1 , 1 , 0 , 1 
                            };
    cout << "plaintext: " ; 
    print( plaintext , 64 ) ;
    cout << "Key: " ; 
    print( Key , 64 ) ;  
    DES des ; 
    int *ciphertext = des.encrypt( plaintext ) ; 
    cout << "ciphertext: " ; 
    print( ciphertext , 64 ) ; 

    #ifdef testKey
    des.test_Key( Key ) ;
    #endif 
}


/*
test1
Key:
0001001100110100010101110111100110011011101111001101111111110001
133457799BBCDFF1
Dropped + Permutation:
1111000 0110011 0010101 0101111 0101010 1011001 1001111 0001111
Left Shift( round 1 ):
11100001100110010101010111111010101011001100111100011110
Left Shift( round 2 ):
11000011001100101010101111110101010110011001111000111101
Left Shift( round 3 ):
00001100110010101010111111110101011001100111100011110101
Left Shift( round 16 ):
11110000110011001010101011110101010101100110011110001111

Key1:
000110110000001011101111111111000111000001110010
Key16:
110010110011110110001011000011100001011111110101

plaintext:
0000000100100011010001010110011110001001101010111100110111101111
123456789ABCDEF
intitail permutation:
1100110000000000110011001111111111110000101010101111000010101010
Expansion of R0:
011110100001010101010101011110100001010101010101
XOR in f:
011000010001011110111010100001100110010100100111
After Substitution:
01011100100000101011010110010111
After Permutation( output of f ):
00100011010010101010100110111011

L1 = R0:
11110000101010101111000010101010
R1:
11101111010010100110010101000100

L16:
01000011010000100011001000110100
R16:
00001010010011001101100110010101

ciphertext:
1000010111101000000100110101010000001111000010101011010000000101
*/

/*
test2
Key:
0001001100110100010101110111100110011011101111001101111111110001
133457799BBCDFF1
plaintext:
0101101010011011011101010110100000000111011100111101100001001101
5A9B75680773D84D
ciphertext:
0011101010001001111100111101100111110110110011010011110000110111
3a89f3d9f6cd3c37 
*/

/*
references:
https://www.rapidtables.com/convert/number/hex-to-binary.html
http://des.online-domain-tools.com/
https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
*/

/******************************************************
Remarks:
L16 and R16 should be switched before final permutation 
*******************************************************/
