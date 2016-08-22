/*

 BUILD AND EXECUTE
 =================
 $ g++ -Wall -std=c++0x -O3 -I../src -o utest utest.cpp ../src/pushoversha1.cpp ../src/s11nsha.cpp -lcryptopp -lboost_serialization -lgtest
 $ ./utest

 USEFUL FLAGS
 ============
 $ ./utest --help
 $ ./utest --gtest_list_tests [List the names of all tests instead of running them]
 $ ./utest --gtest_print_time=0 [Don't print the elapsed time of each test]

*/

// classes to be tested
#include "s11nsha.hpp"

//std::cout, std::endl
#include <iostream>

// std::string
#include <string>

// std::rand, std::srand
#include <cstdlib>

// std::time
#include <ctime>

// CryptoPP::SHA1
#include <cryptopp/sha.h>

// CryptoPP::HexEncoder
#include <cryptopp/hex.h>

// CryptoPP::StringSink, CryptoPP::StringSource
#include <cryptopp/filters.h>


// TEST, RUN_ALL_TESTS, InitGoogleTest()
#include <gtest/gtest.h>

// generate random alphanumeric[0-9A-Za-z] string
std::string generate_random_string( size_t len) {
    static const std::string alphanum("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    std::string str;
    for (size_t i = 1; i <= len; ++i) {
        str.push_back( alphanum[rand() % alphanum.size()] );
    }
    return str;
}

// hex encode a byte* and return a encoded string
void encodeHex ( std::string& encoded_message, const byte* message,
                     const unsigned int& size )
{        
    CryptoPP::StringSource( message, size, true,
                            new CryptoPP::HexEncoder(
                             new CryptoPP::StringSink(encoded_message)
                            ) 
                          ); 
}

// unit test - s11nsha class

// sha1 of empty string
TEST(s11nsha, calculateWithEmptyStringArg)
{
    std::string plain("");
    std::string hexencoded;

    s11nSHA::SHA1 s11n_sha1;
    unsigned char s11n_digest[ s11nSHA::DIGEST_SIZE ];
    s11n_sha1.calculate((byte*)plain.data(), plain.size(), s11n_digest );
    ::encodeHex(hexencoded, s11n_digest, sizeof(s11n_digest));
    EXPECT_EQ(0,hexencoded.compare("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"));
}

// sha1 of string "librados"
TEST(s11nsha, calculateWithStringArg)
{
    std::string plain("librados");
    std::string hexencoded;

    s11nSHA::SHA1 s11n_sha1;
    unsigned char s11n_digest[ s11nSHA::DIGEST_SIZE ];
    s11n_sha1.calculate((byte*)plain.data(), plain.size(), s11n_digest );
    ::encodeHex(hexencoded, s11n_digest, sizeof(s11n_digest));
    EXPECT_EQ(0,hexencoded.compare("8A5DBDE5A76A1431F092FA7DDE144F846DE3B219"));
}

// sha1 of random sized strings (size <= 4MB)
TEST(s11nsha, calculateWithRandomStringArg)
{
    s11nSHA::SHA1 s11n_sha1; 
    unsigned char s11n_digest[ s11nSHA::DIGEST_SIZE ];
    byte crypto_digest[ CryptoPP::SHA1::DIGESTSIZE ];
    std::string crypto_hexencoded, s11n_hexencoded;

    std::srand(std::time(0));

    for(int count = 1; count <= 50; ++count)
    {
        uint64_t r = (std::rand() % (1024*1024*4)) + 1;
        std::string plain = generate_random_string(r);
        s11n_sha1.calculate((byte*)plain.data(), plain.size(), s11n_digest );
        ::encodeHex(s11n_hexencoded, s11n_digest, sizeof(s11n_digest));
        CryptoPP::SHA1().CalculateDigest(crypto_digest, (byte*)plain.data(), plain.size());
        ::encodeHex(crypto_hexencoded, crypto_digest, sizeof(crypto_digest));
        EXPECT_TRUE( s11n_hexencoded == crypto_hexencoded );
        s11n_hexencoded.clear();
        crypto_hexencoded.clear();
    }
}

// sha1 of large data (size <= 1GB)
TEST(s11nsha, updateAndfinalWithRandomStringArg)
{
    s11nSHA::SHA1 s11n_sha1;
    CryptoPP::SHA1 crypto_sha1; 
    unsigned char s11n_digest[ s11nSHA::DIGEST_SIZE ];
    byte crypto_digest[ CryptoPP::SHA1::DIGESTSIZE ];
    std::string crypto_hexencoded, s11n_hexencoded;

    std::srand(std::time(0));
    // test for very large string (size <= 1GB)
    for( int count = 1; count <= 1024; ++count)
    {
        uint64_t r = (std::rand() % (1024*1024) ) + 1;
        std::string plain = generate_random_string(r);
        s11n_sha1.update((byte*)plain.data(), plain.size());
        crypto_sha1.Update((byte*)plain.data(), plain.size());   
    }
    crypto_sha1.Final(crypto_digest);
    s11n_sha1.final( s11n_digest ); s11n_sha1.dump();
    ::encodeHex(s11n_hexencoded, s11n_digest, sizeof(s11n_digest));
    ::encodeHex(crypto_hexencoded, crypto_digest, sizeof(crypto_digest));
    EXPECT_TRUE( s11n_hexencoded == crypto_hexencoded ); 
}

// marshall and unmarshall SHA1 state
TEST(s11nsha, marshallAndUnmarshallRandomStringArg)
{
    s11nSHA::SHA1 s11n_sha1, s11n_sha1_new;
    unsigned char s11n_digest[ s11nSHA::DIGEST_SIZE ];
    unsigned char s11n_digest_new[ s11nSHA::DIGEST_SIZE ];   
    std::string s11n_hexencoded, s11n_hexencoded_new;

    std::srand(std::time(0));

    uint64_t r = (std::rand() % (1024*1024*4)) + 1;
    std::string plain = generate_random_string(r);
    s11n_sha1.update((byte*)plain.data(), plain.size());
    r = (std::rand() % (1024*1024*4)) + 1;
    plain = generate_random_string(r);
    s11n_sha1.update((byte*)plain.data(), plain.size());

    std::string s11n_sha1_object;
    s11nSHA::marshall(s11n_sha1_object, s11n_sha1); // serialize
    s11nSHA::unmarshall(s11n_sha1_object, s11n_sha1_new); // deserialize

    r = (std::rand() % (1024*1024*4)) + 1;
    plain = generate_random_string(r);
    // update original as well as unmarshalled sha1 object
    s11n_sha1.update((byte*)plain.data(), plain.size());
    s11n_sha1_new.update((byte*)plain.data(), plain.size());

    s11n_sha1.final( s11n_digest );
    s11n_sha1_new.final( s11n_digest_new );
    ::encodeHex(s11n_hexencoded, s11n_digest, sizeof(s11n_digest));
    ::encodeHex(s11n_hexencoded_new, s11n_digest_new, sizeof(s11n_digest));

    EXPECT_TRUE( s11n_hexencoded == s11n_hexencoded_new ); 
}

// sha1 of large data (size <= 1GB)
TEST(s11nsha, updateAndfinalWithRandomStringArgDump)
{
    s11nSHA::SHA1 s11n_sha1; s11n_sha1.dump();
    unsigned char s11n_digest[ s11nSHA::DIGEST_SIZE ];

    std::srand(std::time(0));
    // test for very large string (size <= 1GB)
    for( int count = 1; count <= 25; ++count)
    {
        uint64_t r = std::rand() % 29 + 1;
        std::string plain = generate_random_string(r);
        s11n_sha1.update((byte*)plain.data(), plain.size());
        std::cout << '[' << plain.size() << "] " << plain << '\n';
        s11n_sha1.dump();  
    }
    s11n_sha1.final( s11n_digest ); s11n_sha1.dump();
}

int main (int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);

    return  RUN_ALL_TESTS(); 
}
