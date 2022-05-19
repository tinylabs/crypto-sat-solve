### Mifare Crypto1 algebraic attack using SAT solver
Python module to solve for Mifare classic 48bit key using a single successful sniffed transaction.  
This attack requires no dependencies on implementation and typically completes in less than a minute  
on a modern PC.  
#### Inputs - Single sniffed authentication
- UID, Nt (plaintext UID and card nonce)
- enc_nr, enc_ar, enc_at
#### Compiling
    sudo apt-get install libboost-all-dev cmake zlib1g-dev
    sudo python3 -m pip install numpy matplotlib pylfsr pycryptosat
    git clone git@github.com:tinylabs/crypto-sat-solve.git
    cd crypto-sat-solve
    git submodule update
    cd grainofsalt/build
    cmake ../
    make -j
    cd ../..
#### Sample usage
    time ./Crypto1.py 
    key=0x4fd7605e1ce5
    uid=0x7a39c16f nt=0x35ecd241 nr=0x4317ee49
    0x7c 0x7f 0x52 0xf3 0x68 0x7 0x96 0x75 
    0x5b 0xda 0xa 0x41 
    ===================
    Recovering key with algebraic attack...
    Key=0x4fd7605e1ce5
    
    real    0m10.304s
    user    0m20.684s
    sys     0m0.796s
#### Papers
- Built on research from Karsten Nohl and Mate Soos
- https://eprint.iacr.org/2008/166.pdf
- https://www.msoos.org/wordpress/wp-content/uploads/2011/03/Extending_SAT_2009.pdf
