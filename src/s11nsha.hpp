/**
 *  SHA-1 cryptographic hash function
 *
 *  Original C Code
 *      -- Copyright (C) 2006-2013, Brainspark B.V.
 *      -- is part of PolarSSL (http://www.polarssl.org)
 *      -- Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  Translation to C++ Code and boost s11n support
 *      -- Amit Tiwary <amitt@one.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef S11NSHA_HPP
#define S11NSHA_HPP

// uint32_t
#include <cstdint>

// size_t
#include <cstring>

// std::string
#include <string>

// boost archive and serialization
#include <boost/serialization/serialization.hpp>

namespace s11nSHA
{
    const unsigned int DIGEST_SIZE = 20;
    const unsigned int DIGEST_INTS = 5;  // 32bit integers per SHA1 digest
    const unsigned int BLOCK_INTS = 16;  // 32bit integers per SHA1 block
    const unsigned int BLOCK_BYTES = BLOCK_INTS * 4;

    const unsigned char SHA1_PADDING[BLOCK_BYTES] =
        { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

    class SHA1
    {
    public:
        SHA1();

        void init();

        // process more input
        void update( const unsigned char *input, size_t length );

        // compute hash for current message, then restart for a new message
        void final( unsigned char digest[DIGEST_SIZE] );

        // calculate hash of input. use this if your input is in one piece
        // and you don't want to call update() and final() separately
        void calculate( const unsigned char *input, size_t length,
                        unsigned char digest[DIGEST_SIZE] );

        // calculate hash of file contents
        bool calculate( const char *path, unsigned char digest[DIGEST_SIZE] );

        // dump the contents
        void dump();

    private:
        // helper methods 
        void process( const unsigned char data[BLOCK_BYTES] );

        uint32_t total[2];                 // number of bytes processed
        uint32_t state[DIGEST_INTS];       // intermediate digest state
        unsigned char buffer[BLOCK_BYTES]; // data block being processed

        friend class boost::serialization::access;

        template <typename Archive>
        void serialize( Archive &ar, const unsigned int version ) 
        { 
            ar & total & state & buffer; 
        }
    }; // end of class SHA1

    // serialize SHA1 object into std::string; set last argument to true for
    // non-portable binay format
    void marshall( std::string& s11n_sha1_object, const SHA1& sha1_object,
                                                  bool to_binary = false );

    // deserialize SHA1 object from std::string; set last argument to true if
    // non-portable binay format was used while serializing 
    void unmarshall( const std::string& s11n_sha1_object, SHA1& sha1_object,
                                                  bool from_binary = false );

} // end of namespace s11nSHA

#endif
