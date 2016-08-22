// g++ -Wall -c -std=c++0x s11nsha.cpp
// implementation of s11nsha.hpp

#include "s11nsha.hpp"

// fopen, fread, fclose
#include <cstdio>

// size_t, std::memset, std::memcpy
#include <cstring>

// std::stringstream
#include <sstream>

// boost archive and serialization
#include <boost/archive/text_oarchive.hpp> 
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp> 
#include <boost/archive/binary_iarchive.hpp>

void s11nSHA::SHA1::init()
{
    total[0] = 0;
    total[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
    std::memset( buffer, 0, BLOCK_BYTES );
}

// 32-bit integer manipulation macros (big endian)
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

void s11nSHA::SHA1::process( const unsigned char data[BLOCK_BYTES] )
{
    uint32_t temp, W[16], A, B, C, D, E;

    GET_UINT32_BE( W[ 0], data,  0 ); GET_UINT32_BE( W[ 1], data,  4 );
    GET_UINT32_BE( W[ 2], data,  8 ); GET_UINT32_BE( W[ 3], data, 12 );
    GET_UINT32_BE( W[ 4], data, 16 ); GET_UINT32_BE( W[ 5], data, 20 );
    GET_UINT32_BE( W[ 6], data, 24 ); GET_UINT32_BE( W[ 7], data, 28 );
    GET_UINT32_BE( W[ 8], data, 32 ); GET_UINT32_BE( W[ 9], data, 36 );
    GET_UINT32_BE( W[10], data, 40 ); GET_UINT32_BE( W[11], data, 44 );
    GET_UINT32_BE( W[12], data, 48 ); GET_UINT32_BE( W[13], data, 52 );
    GET_UINT32_BE( W[14], data, 56 ); GET_UINT32_BE( W[15], data, 60 );

    #define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

    #define R(t)                                         \
    (                                                    \
     temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
            W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
     ( W[t & 0x0F] = S(temp,1) )                         \
    )

    #define P(a,b,c,d,e,x)                               \
    {                                                    \
     e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
    }

    A = state[0]; B = state[1]; C = state[2]; D = state[3]; E = state[4];

    #define F(x,y,z) (z ^ (x & (y ^ z)))
    #define K 0x5A827999

    P( A, B, C, D, E, W[0]  ); P( E, A, B, C, D, W[1]  );
    P( D, E, A, B, C, W[2]  ); P( C, D, E, A, B, W[3]  );
    P( B, C, D, E, A, W[4]  ); P( A, B, C, D, E, W[5]  );
    P( E, A, B, C, D, W[6]  ); P( D, E, A, B, C, W[7]  );
    P( C, D, E, A, B, W[8]  ); P( B, C, D, E, A, W[9]  );
    P( A, B, C, D, E, W[10] ); P( E, A, B, C, D, W[11] );
    P( D, E, A, B, C, W[12] ); P( C, D, E, A, B, W[13] );
    P( B, C, D, E, A, W[14] ); P( A, B, C, D, E, W[15] );
    P( E, A, B, C, D, R(16) ); P( D, E, A, B, C, R(17) );
    P( C, D, E, A, B, R(18) ); P( B, C, D, E, A, R(19) );

    #undef K
    #undef F

    #define F(x,y,z) (x ^ y ^ z)
    #define K 0x6ED9EBA1

    P( A, B, C, D, E, R(20) ); P( E, A, B, C, D, R(21) );
    P( D, E, A, B, C, R(22) ); P( C, D, E, A, B, R(23) );
    P( B, C, D, E, A, R(24) ); P( A, B, C, D, E, R(25) );
    P( E, A, B, C, D, R(26) ); P( D, E, A, B, C, R(27) );
    P( C, D, E, A, B, R(28) ); P( B, C, D, E, A, R(29) );
    P( A, B, C, D, E, R(30) ); P( E, A, B, C, D, R(31) );
    P( D, E, A, B, C, R(32) ); P( C, D, E, A, B, R(33) );
    P( B, C, D, E, A, R(34) ); P( A, B, C, D, E, R(35) );
    P( E, A, B, C, D, R(36) ); P( D, E, A, B, C, R(37) );
    P( C, D, E, A, B, R(38) ); P( B, C, D, E, A, R(39) );

    #undef K
    #undef F

    #define F(x,y,z) ((x & y) | (z & (x | y)))
    #define K 0x8F1BBCDC

    P( A, B, C, D, E, R(40) ); P( E, A, B, C, D, R(41) );
    P( D, E, A, B, C, R(42) ); P( C, D, E, A, B, R(43) );
    P( B, C, D, E, A, R(44) ); P( A, B, C, D, E, R(45) );
    P( E, A, B, C, D, R(46) ); P( D, E, A, B, C, R(47) );
    P( C, D, E, A, B, R(48) ); P( B, C, D, E, A, R(49) );
    P( A, B, C, D, E, R(50) ); P( E, A, B, C, D, R(51) );
    P( D, E, A, B, C, R(52) ); P( C, D, E, A, B, R(53) );
    P( B, C, D, E, A, R(54) ); P( A, B, C, D, E, R(55) );
    P( E, A, B, C, D, R(56) ); P( D, E, A, B, C, R(57) );
    P( C, D, E, A, B, R(58) ); P( B, C, D, E, A, R(59) );

    #undef K
    #undef F

    #define F(x,y,z) (x ^ y ^ z)
    #define K 0xCA62C1D6

    P( A, B, C, D, E, R(60) ); P( E, A, B, C, D, R(61) );
    P( D, E, A, B, C, R(62) ); P( C, D, E, A, B, R(63) );
    P( B, C, D, E, A, R(64) ); P( A, B, C, D, E, R(65) );
    P( E, A, B, C, D, R(66) ); P( D, E, A, B, C, R(67) );
    P( C, D, E, A, B, R(68) ); P( B, C, D, E, A, R(69) );
    P( A, B, C, D, E, R(70) ); P( E, A, B, C, D, R(71) );
    P( D, E, A, B, C, R(72) ); P( C, D, E, A, B, R(73) );
    P( B, C, D, E, A, R(74) ); P( A, B, C, D, E, R(75) );
    P( E, A, B, C, D, R(76) ); P( D, E, A, B, C, R(77) );
    P( C, D, E, A, B, R(78) ); P( B, C, D, E, A, R(79) );

    #undef K
    #undef F

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
}

s11nSHA::SHA1::SHA1()
{
    init();
}

void s11nSHA::SHA1::update( const unsigned char *input, size_t length )
{
    size_t fill;
    uint32_t left;

    if( length <= 0 )
        return;

    left = total[0] & 0x3F;
    fill = BLOCK_BYTES - left;

    total[0] += static_cast<uint32_t>(length);
    total[0] &= 0xFFFFFFFF;

    if( total[0] < static_cast<uint32_t>(length) )
        total[1]++;

    if( left && length >= fill )
    {
        std::memcpy( (buffer + left), input, fill );
        process( buffer );
        input += fill;
        length  -= fill;
        left = 0;
    }

    while( length >= BLOCK_BYTES )
    {
        process( input );
        input += BLOCK_BYTES;
        length  -= BLOCK_BYTES;
    }

    if( length > 0 )
        std::memcpy( (buffer + left), input, length );
}

void s11nSHA::SHA1::final( unsigned char digest[DIGEST_SIZE] )
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];

    high = ( total[0] >> 29 ) | ( total[1] <<  3 );
    low  = ( total[0] <<  3 );

    PUT_UINT32_BE( high, msglen, 0 );
    PUT_UINT32_BE( low,  msglen, 4 );

    last = total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    update( SHA1_PADDING, padn );
    update( msglen, 8 );

    PUT_UINT32_BE( state[0], digest,  0 );
    PUT_UINT32_BE( state[1], digest,  4 );
    PUT_UINT32_BE( state[2], digest,  8 );
    PUT_UINT32_BE( state[3], digest, 12 );
    PUT_UINT32_BE( state[4], digest, 16 );

    init(); // reset for future use
}

void s11nSHA::SHA1::calculate( const unsigned char *input, size_t length,
                               unsigned char digest[DIGEST_SIZE] )
{
    init();
    update( input, length );
    final( digest );
    init(); // reset for future use
}

bool s11nSHA::SHA1::calculate( const char *path,
                               unsigned char digest[DIGEST_SIZE] )
{
    FILE *f;
    size_t n;
    unsigned char buf[1024*4];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return false;

    this->init();

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        this->update( buf, n );

    this->final( digest );
    this->init();

    if( ferror(f) != 0 )
    {
        fclose(f);
        return false;
    }

    fclose(f);
    return true;
}

void s11nSHA::marshall( std::string& s11n_sha1_object,
                        const SHA1& sha1_object, bool to_binary )
{
    std::stringstream ss;
    if (to_binary)
    {
        boost::archive::binary_oarchive oa(ss);
        oa << sha1_object;
    }
    else
    {
        boost::archive::text_oarchive oa(ss);
        oa << sha1_object;
    }

    s11n_sha1_object.clear();
    s11n_sha1_object = ss.str();
}

void s11nSHA::unmarshall( const std::string& s11n_sha1_object,
                          SHA1& sha1_object, bool from_binary )
{
    std::stringstream ss(s11n_sha1_object);

    if (from_binary)
    {
        boost::archive::binary_iarchive ia(ss);
        ia >> sha1_object;
    }
    else
    {
        boost::archive::text_iarchive ia(ss);
        ia >> sha1_object;
    }
}

void s11nSHA::SHA1::dump()
{
    printf( "total[0, 1] = [%u, %u]\n", total[0], total[1] );

    for (unsigned int i = 0; i < DIGEST_INTS; ++i )
        printf( "state[%u] = %u\n", i, state[i] );

    for (unsigned int i = 0; i < BLOCK_BYTES; ++i )
        printf( "%c ", buffer[i] );

    printf("\n");
}
