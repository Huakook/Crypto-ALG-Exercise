#include<iostream>
using namespace std ; 
//#define debug  

int Key[ 64 ] =   { 
                            0 , 0 , 1 , 1 , 0 , 1 , 0 , 1 , 
                            0 , 1 , 0 , 1 , 0 , 1 , 0 , 1 , 
                            1 , 0 , 1 , 0 , 1 , 0 , 0 , 1 , 
                            0 , 0 , 0 , 0 , 0 , 1 , 0 , 0 ,
                            0 , 1 , 1 , 1 , 0 , 1 , 1 , 1 , 
                            1 , 1 , 0 , 0 , 1 , 1 , 1 , 0 ,
                            0 , 1 , 1 , 0 , 1 , 1 , 0 , 0 ,
                            0 , 1 , 1 , 0 , 0 , 1 , 1 , 1 
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
        #ifdef debug 
        cout << "encrypt Begin\n" ;
        #endif 
        int *L = new int[ 32 ] , *R = new int[ 32 ] , *tmp , *out ; 
        for( int i = 0 ; i < 32 ; i++ )
        {
            L[ i ] = in[ i ] ; 
            R[ i ] = in[ 32 + i ] ; 
        }
        int *k = permutation_Choice1( Key ) ;//56-bit
        int *curKey = NULL ; 
        for( int i = 1 ; i <= 16 ; i++ )
        {//16 rounds 
            //gernerate the next key
            #ifdef debug
            cout << "round " << i << " END" << endl ;  
            cout << "Left Shift\n" ; 
            #endif 
            left_Shift( k , i ) ; 
            #ifdef debug
            cout << "PC2\n" ; 
            #endif
            curKey = permutation_Choice2( k ) ; 
            #ifdef debug
            cout << "f\n" ; 
            #endif 
            //encrypt the right part
            out = f( R , curKey ) ;//32-bit 
            tmp = R ;  
            #ifdef debug 
            cout << "XOR\n" ;
            #endif  
            R = XOR( L , out , 32 ) ;//32-bit 
            delete L ; 
            /********** L = in ; delete L ;  Cannot delete the memoey that is NOT allocated by new ********/
            L = tmp ; 
            delete out ; 
            delete curKey ;
            #ifdef debug  
            cout << "round " << i << " END" << endl ; 
            #endif 
        }
        int *ciphertext = new int[ 64 ] ; 
        for( int i = 0 ; i < 32 ; i++ )
        {
            ciphertext[ i ] = L[ i ] ; 
        }
        for( int i = 0 ; i < 32 ; i++ )
        {
            ciphertext[ i + 32 ] = L[ i ] ; 
        }
        delete L ; 
        delete R ; 
        return ciphertext ; 
    }
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
                
    int S_box[ 4 ][ 16 ] =  {
                                { 14 , 4 , 13 , 1 , 2 , 15 , 11 , 8 , 3 , 10 , 6 , 12 , 5 , 9 , 0 , 7 },
                                { 0 , 15 , 7 , 4 , 14 , 2 , 13 , 1 , 10 , 6 , 12 , 11 , 9 , 5 , 3 , 8 },
                                { 4 , 1 , 14 , 8 , 13 , 6 , 2 , 11 , 15 , 12 , 9 , 7 , 3 , 10 , 5 , 0 },
                                { 15 , 12 , 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11 , 3 , 14 , 10 , 0 , 6 , 13 }
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
            //cout << row_idx << " :: " << col_idx << endl ; 
            int mapped_res = S_box[ row_idx ][ col_idx ] ; 
            //convert the decimal to a 4-bit binary number 
            for( int j = 3 ; j >= 0 ; j-- ) 
            {
                tmp[ i * 4 + j ] = mapped_res % 2 ; 
                mapped_res = mapped_res >> 1 ; 
            }
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
        int *cur1 = Expansion( in ) ; //48-bit
        int *cur2 = XOR( K , cur1 , 48 ) ;//48-bit  
        delete cur1 ; 
        cur1 = Substitution( cur2 ) ;//32-bit 
        delete cur2 ; 
        cur2 = Permutation( cur1 ) ;//32-bit 
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
                in[ i ] = in[ i + 1 ] ; 
            }
            in[ 26 ] = first ;
            in[ 27 ] = second ;  
            //right part 
            first = in[ 28 ] ; 
            second = in[ 29 ] ; 
            for( int i = 28 ; i < 55 ; i++ )
            {
                in[ i ] = in[ i + 1 ] ; 
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
}

