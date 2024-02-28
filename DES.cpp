#include<iostream>
using namespace std ; 
const int Key[ 48 ] =   { 
                            0 , 0 , 1 , 1 , 0 , 1 , 0 , 1 , 
                            0 , 1 , 0 , 1 , 0 , 1 , 0 , 1 , 
                            1 , 0 , 1 , 0 , 1 , 0 , 0 , 1 , 
                            0 , 0 , 0 , 0 , 0 , 1 , 0 , 0 ,
                            0 , 1 , 1 , 1 , 0 , 1 , 1 , 1 , 
                            1 , 1 , 0 , 0 , 1 , 1 , 1 , 0 
                        };

template <typename T>
T *dynamic_allocate( T R , T C , T **ptr )
{
    T *tmp = new T[ R * C ] ; 
    ptr = new T*[ R ] ; 
    for( int i = 0 ; i < R ; i++ ) IP[ i ] = tmp + C * i ; 
    return tmp ;     
} 

class DES
{
public:
    DES(){}
    int *encrypt( int *in )
    {//64-bit input 
        
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
    int *Expansion( int *R ) 
    {//32-bit right part 
        int *tmp = new int[ 48 ] ; 
        for( int i = 0 ; i < 48 ; i++ )
        {
            tmp[ i ] = R[ E_box[ i ] - 1 ] ;  
        }
        return tmp ; 
    }
    int *XOR( int *K , int *in )
    {//48-bit key and input 
        int *tmp = new int[ 48 ] ; 
        for( int i = 0 ; i < 48 ; i++ )
        {
            tmp[ i ] = K[ i ] - in[ i ] == 0 ? 0 : 1 ; 
        }
        return tmp ; 
    }
    int *Substitution( int *in )
    {//48-bit input 
        int *tmp = new int[ 32 ] ; 
        for( int i = 0 ; i < 8 ; i++ )
        {//there are 8 S-boxes 
            int *temp = tmp + i * 6 ;//each box maps 6 bits to 4 bits  
            int row_idx = temp[ 0 ] * 2 + temp[ 5 ] * 1 ; 
            int col_idx = temp[ 1 ] * 8 + temp[ 2 ] * 4 + temp[ 1 ] * 2 + temp[ 0 ] * 1 ; 
            int mapped_res = S_box[ row_idx ][ col_idx ] ; 
            //convert the decimal to a 4-bit binary number 
            for( int j = 3 ; j >= 0 ; j-- ) 
            {
                tmp[ i * 4 + j ] = mapped_res % 2 ; 
                mapped_res /= 2 ; 
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
};

int main()
{

}