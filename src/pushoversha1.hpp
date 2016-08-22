/*
    http://pushover.sourceforge.net/

    ============
    SHA-1 in C++
    ============

    100% Public Domain.

    Original C Code
        -- Steve Reid <steve@edmweb.com>
    Small changes to fit into bglibs
        -- Bruce Guenter <bruce@untroubled.org>
    Translation to simpler C++ Code
        -- Volker Grabsch <vog@notjusthosting.com>
    Cosmetic changes
        -- Amit Tiwary <amitt@one.com>
*/

#ifndef PUSHOVERSHA1_HPP
#define PUSHOVERSHA1_HPP

#include <iostream>
#include <sstream> 
#include <string>
#include <fstream>

class PUSHOVERSHA1
{
public:
    PUSHOVERSHA1()
    {
        reset();
    }

    void update(const std::string &s)
    {
        std::istringstream is(s);
        update(is);
    }

    void update(std::istream &is);

    std::string final();

    static std::string from_file(const std::string &filename)
    {
        std::ifstream stream(filename.c_str(), std::ios::binary);
        PUSHOVERSHA1 checksum;
        checksum.update(stream);
        return checksum.final();
    }

private:
    typedef unsigned long int uint32;   /* just needs to be at least 32bit */
    typedef unsigned long long uint64;  /* just needs to be at least 64bit */

    static const unsigned int DIGEST_INTS = 5;  /* number of 32bit integers per SHA1 digest */
    static const unsigned int BLOCK_INTS = 16;  /* number of 32bit integers per SHA1 block */
    static const unsigned int BLOCK_BYTES = BLOCK_INTS * 4;

    uint64 transforms;
    uint32 digest[DIGEST_INTS];
    std::string buffer;


    void reset()
    {
        /* SHA1 initialization constants */
        digest[0] = 0x67452301;
        digest[1] = 0xefcdab89;
        digest[2] = 0x98badcfe;
        digest[3] = 0x10325476;
        digest[4] = 0xc3d2e1f0;

        /* Reset counters */
        transforms = 0;
        buffer.clear();
    }

    void transform(uint32 block[BLOCK_BYTES]);

    static void buffer_to_block(const std::string &buffer, uint32 block[BLOCK_BYTES]);

    static void read(std::istream &is, std::string &s, int max)
    {
        char sbuf[max];
        is.read(sbuf, max);
        s.assign(sbuf, is.gcount());
    }
};

#endif
