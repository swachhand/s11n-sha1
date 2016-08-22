# s11n-sha1
Persist and serialize SHA1 state

Dependencies
============

You need the following dependencies installed
 - libcrypto++-dev (crypto++)
 - libgtest-dev    (google test)
 - libboost-serialization-dev (boost serialization) 

Directory layout
================

  |-- src/       - implementation of s11nSHA1 code  
  |-- t/         - unit tests  
  |-- benchmark/ - benchmark scripts and results

Code layout
===========
  |-- benchmark  
  |---|-- benchmark_sha1.cpp  [benchmarks different SHA1 implementations                         ]  
  |---|-- results.txt         [sample result                                                     ]  
  |---|-- simplebenchmark.hpp [simplebenchmark class with start(), stop() and getResult() methods]  
  |-- src  
  |---|-- pushoversha1.cpp    [implements below class - http://pushover.sourceforge.net/         ]  
  |---|-- pushoversha1.hpp    [SHA1 algorithm picked from Pushover                               ]  
  |---|-- s11nsha.cpp         [implements below class                                            ]  
  |---`-- s11nsha.hpp         [SHA1 class with archive/(de)serialization support for SHA1 object ]  
  |-- t  
  |---`-- utest.cpp           [unit tests                                                        ]
