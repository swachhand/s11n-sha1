// g++ -Wall -std=c++0x -I../src -O3 benchmark_sha1.cpp ../src/pushoversha1.cpp ../src/s11nsha.cpp -lcryptopp -lboost_serialization

#include <iostream>
#include <fstream>
#include <iomanip> 
#include <string>
#include <ctime>
#include <cstdlib>
#include <sstream>

// CryptoPP::SHA1
#include <cryptopp/sha.h>

// CryptoPP::HexEncoder
#include <cryptopp/hex.h>

// CryptoPP::StringSink, CryptoPP::StringSource
#include <cryptopp/filters.h>

// Pushover SHA1
#include "pushoversha1.hpp"

// Polar SSL SHA1
#include "s11nsha.hpp"

#include "simplebenchmark.hpp"

// display header
void print_header()
{
    std::cout << std::setw(8)  << "SIZE(MB)"     << "   "
              << std::setw(13) << "CRYPTO++(ms)" << "   "
              << std::setw(13) << "PUSHOVER(ms)" << "   "
              << std::setw(13) << "POLARSSL(ms)" << "   "
              << std::setw(8)  << "SHA1SUM"
              << std::endl; 
}

// display stats
void print_stats(uint64_t size, long int t1, long int t2, long int t3, bool status)
{
    std::cout << std::setw(8)  << std::setprecision(2)
              << std::fixed    << size/(1024*1024) << " | "
              << std::setw(13) << t1 << " | "
              << std::setw(13) << t2 << " | "
              << std::setw(13) << t3 << " | "
              << std::setw(8)  << (status ? "==" : "!=")
              << std::endl;  
}

// generates a random alphanumeric[0-9A-Za-z] string of specified size
std::string generate_random_string( size_t len) {
    static const std::string alphanum("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    std::string str;
    std::srand(std::time(0));
    for (size_t i = 1; i <= len; ++i) {
        str.push_back( alphanum[std::rand() % alphanum.size()] );
    }
    return str;
}

// hex encode a byte* and return a encoded string
void encode_hex ( std::string& encoded_message, const byte* message,
                     const unsigned int& size )
{        
    CryptoPP::StringSource( message, size, true,
                            new CryptoPP::HexEncoder(
                             new CryptoPP::StringSink(encoded_message)
                            ) 
                          ); 
}

void benchmark_sha1()
{
    unsigned int fourMB = 1024*1024*4;

    // generate random size >= 4MB
    std::srand(std::time(0));
    uint64_t data_size;
    do
    {
        data_size = std::rand();
    } while (data_size < fourMB );

    simplebenchmark sb;
    long int cryptoppsha1_time = 0, pushoversha1_time = 0, polarsha1_time = 0;

    // measure ctor time
    sb.start();
    CryptoPP::SHA1 cryptopp_sha1;
    sb.stop();
    cryptoppsha1_time += sb.getResult();

    sb.start();
    PUSHOVERSHA1 pushover_sha1;
    sb.stop();
    pushoversha1_time += sb.getResult();

    sb.start();
    s11nSHA::SHA1 polar_sha1;
    sb.stop();
    polarsha1_time += sb.getResult();

    uint64_t temp_data_size = data_size;
    while ( temp_data_size > 0 )
    {
        // write 4MB in each iteration except last
        uint64_t buffer_size = (temp_data_size >= fourMB) ? fourMB : temp_data_size;
        std::string buffer = ::generate_random_string(buffer_size);
        
        // measure update time
        sb.start();
        cryptopp_sha1.Update((byte*)buffer.c_str(), buffer_size);
        sb.stop();
        cryptoppsha1_time += sb.getResult(); 

        sb.start();
        pushover_sha1.update(buffer);
        sb.stop();
        pushoversha1_time += sb.getResult();

        sb.start(); 
        polar_sha1.update( (unsigned char*)buffer.c_str(), buffer.size() );
        sb.stop();
        polarsha1_time += sb.getResult();

        temp_data_size -= buffer_size;
    }
    // measure final time
    std::string cryptopp_encoded_digest;
    byte cryptopp_digest[ CryptoPP::SHA1::DIGESTSIZE ];
    sb.start(); cryptopp_sha1.Final(cryptopp_digest);
    ::encode_hex(cryptopp_encoded_digest, cryptopp_digest, CryptoPP::SHA1::DIGESTSIZE);
    sb.stop();
    cryptoppsha1_time += sb.getResult();

    sb.start();
    std::string pushover_digest = pushover_sha1.final();
    sb.stop();
    pushoversha1_time += sb.getResult();

    unsigned char polar_digest[s11nSHA::DIGEST_SIZE];
    std::string polar_encoded_digest;
    sb.start(); 
    polar_sha1.final( polar_digest );
    ::encode_hex(polar_encoded_digest, polar_digest, s11nSHA::DIGEST_SIZE);
    sb.stop();
    polarsha1_time += sb.getResult();
    
    // display stats
    ::print_stats(data_size, cryptoppsha1_time, pushoversha1_time, polarsha1_time,
                (cryptopp_encoded_digest == pushover_digest) &&
                (pushover_digest == polar_encoded_digest) );
}

int main(int argc, char* argv[])
{
    ::print_header();

    for( int count=1; count <= 50; ++count)
        ::benchmark_sha1();

    return 0;
}

