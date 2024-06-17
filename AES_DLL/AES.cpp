#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>

#include "pch.h"

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cin;
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/xts.h"
#include "cryptopp/ccm.h"
#include "cryptopp/gcm.h"
#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;


#include "cryptopp/secblock.h"
#include "cryptopp/xts.h"
using CryptoPP::SecByteBlock;

#ifndef DLL_EXPORT
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif
#endif

extern "C"
{
    DLL_EXPORT void KeyGen(const char* key_length, const char* file_name);
    DLL_EXPORT void IVGen(const char* iv_length, const char* file_name);
    DLL_EXPORT void Encrypt(const char* mode, const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file);
    DLL_EXPORT void Decrypt(const char* mode, const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file);
}

void Usage() {
    cout << "Usage: ./AES_CL1 <command> [options]" << endl;
    cout << "Commands:" << endl;
    cout << "   keygen <key_length> <file_name>" << endl;
    cout << "   ivgen <iv_length> <file_name>" << endl;
    cout << "   encrypt <mode> <key_file> <iv_file> <plaintext_file> <ciphertext_file>" << endl;
    cout << "   decrypt <mode> <key_file> <iv_file> <ciphertext_file> <recovered_file>" << endl;
    cout << " ------------------------------------------------------------------------ " << endl;
}

void KeyGen(const char* key_length, const char* file_name) {
    string key_length_str(key_length);
    float keyLength = std::stoi(key_length_str) / 8;
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        cout << "Invalid key length, please re-insert the correct one!" << endl;
        return;
    }
    AutoSeededRandomPool prng;
    SecByteBlock key(keyLength);
    prng.GenerateBlock(key, key.size());

    string encoded;
    encoded.clear();
    string file_name_str(file_name);
    StringSource(key, key.size(), true, new HexEncoder(new FileSink(file_name_str.c_str())));

    cout << "Key generation completed!" << endl;
}

void IVGen(const char* iv_length, const char* file_name) {
    string iv_length_str(iv_length);
    float ivLength = std::stoi(iv_length_str) / 8;
    if (ivLength != 16 && ivLength != 7 && ivLength != 8 && ivLength != 9 && ivLength != 10 && ivLength != 11 && ivLength != 12 && ivLength != 13) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }
    AutoSeededRandomPool prng;
    SecByteBlock iv(ivLength);
    prng.GenerateBlock(iv, iv.size());

    string encoded;
    encoded.clear();
    string file_name_str(file_name);
    StringSource(iv, iv.size(), true, new HexEncoder(new FileSink(file_name_str.c_str())));

    cout << "IV generation completed!" << endl;
}

void EncryptCBC(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, iv, plain;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string cipher;
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(plaintext_file_str.c_str(), true, new StreamTransformationFilter(encryptor, new StringSink(cipher)));

    StringSource(cipher, true, new HexEncoder(new FileSink(ciphertext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptCBC(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, iv, cipher;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string recovered;
    string recovered_file_str(recovered_file);
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(ciphertext_file_str.c_str(), true, new HexDecoder(new StreamTransformationFilter(decryptor, new StringSink(recovered))));

    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

void EncryptCFB(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, iv, plain;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string cipher;
    CFB_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(plaintext_file_str.c_str(), true, new StreamTransformationFilter(encryptor, new StringSink(cipher)));

    StringSource(cipher, true, new HexEncoder(new FileSink(ciphertext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptCFB(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, iv, cipher;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string recovered;
    string recovered_file_str(recovered_file);
    CFB_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(ciphertext_file_str.c_str(), true, new HexDecoder(new StreamTransformationFilter(decryptor, new StringSink(recovered))));

    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

void EncryptOFB(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, iv, plain;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string cipher;
    OFB_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(plaintext_file_str.c_str(), true, new StreamTransformationFilter(encryptor, new StringSink(cipher)));

    StringSource(cipher, true, new HexEncoder(new FileSink(plaintext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptOFB(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, iv, cipher;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string recovered;
    string recovered_file_str(recovered_file);
    OFB_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(ciphertext_file_str.c_str(), true, new HexDecoder(new StreamTransformationFilter(decryptor, new StringSink(recovered))));

    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

void EncryptCTR(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, iv, plain;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string cipher;
    CTR_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(plaintext_file_str.c_str(), true, new StreamTransformationFilter(encryptor, new StringSink(cipher)));

    StringSource(cipher, true, new HexEncoder(new FileSink(ciphertext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptCTR(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, iv, cipher;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    if (iv.size() != 16) {
        cout << "Invalid IV length, please re-insert the correct one!" << endl;
        return;
    }

    string recovered;
    string recovered_file_str(recovered_file);
    CTR_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(ciphertext_file_str.c_str(), true, new HexDecoder(new StreamTransformationFilter(decryptor, new StringSink(recovered))));

    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

void EncryptECB(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, plain;
    string key_file_str(key_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());

    string cipher;
    ECB_Mode<AES>::Encryption encryptor;
    encryptor.SetKey(key_byte, key_byte.size());

    FileSource(plaintext_file_str.c_str(), true, new StreamTransformationFilter(encryptor, new StringSink(cipher)));

    StringSource(cipher, true, new HexEncoder(new FileSink(ciphertext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptECB(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, cipher;
    string key_file_str(key_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));
    FileSource(key_file_str.c_str(), true, new HexEncoder(new  StringSink(key)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());

    string recovered;
    string recovered_file_str(recovered_file);
    ECB_Mode<AES>::Decryption decryptor;
    decryptor.SetKey(key_byte, key_byte.size());

    FileSource(ciphertext_file_str.c_str(), true, new HexDecoder(new StreamTransformationFilter(decryptor, new StringSink(recovered))));

    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

void EncryptXTS(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, iv, plain;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    string cipher;
    XTS_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    FileSource(plaintext_file_str.c_str(), true, new StreamTransformationFilter(encryptor, new StringSink(cipher)));

    StringSource(cipher, true, new HexEncoder(new FileSink(ciphertext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptXTS(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, iv, cipher;
    string key_file_str(key_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));
    FileSource(key_file_str.c_str(), true, new HexEncoder(new  StringSink(key)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    string recovered;
    string recovered_file_str(recovered_file);
    XTS_Mode< AES >::Decryption decryptor;
    decryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte);

    StringSource(cipher, true, new HexDecoder(new StreamTransformationFilter(decryptor, new StringSink(recovered), StreamTransformationFilter::NO_PADDING)));

    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

int SetUpCCM() {
    int tagSize;
    cin >> tagSize;
    if (tagSize != 4 && tagSize != 6 && tagSize != 8 && tagSize != 10 && tagSize != 12 && tagSize != 14 && tagSize != 16) {
        cout << "Invalid tag size, please re-insert the correct one!" << endl;
        SetUpCCM();
    }
    else {
        cout << "Tag size inserted correctly!" << endl;
    }
    return tagSize;
}

void EncryptCCM(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, iv, plain;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    //#include <cryptopp/filters.h> 
    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    const int tagSize = 8;

    string cipher;
    CryptoPP::CCM<AES, tagSize>::Encryption encryptor;
    encryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte, iv_byte.size());
    encryptor.SpecifyDataLengths(0, plain.size(), 0);

    FileSource(plaintext_file_str.c_str(), true, new CryptoPP::AuthenticatedEncryptionFilter(encryptor, new StringSink(cipher)));
    StringSource(cipher, true, new HexEncoder(new FileSink(ciphertext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptCCM(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, iv, cipher;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(ciphertext_file_str.c_str(), true, new StringSink(cipher));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    const int tagSize = 8;

    string recovered;
    string recovered_file_str(recovered_file);
    CryptoPP::CCM<AES, tagSize>::Decryption decryptor;
    decryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte, iv_byte.size());
    decryptor.SpecifyDataLengths(0, cipher.size() - tagSize, 0);

    CryptoPP::AuthenticatedDecryptionFilter df(decryptor,
        new StringSink(recovered)
    );
    StringSource ss(cipher, true,
        new CryptoPP::Redirector(df)
    );
    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

void EncryptGCM(const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    string key, iv, plain;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string plaintext_file_str(plaintext_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(plaintext_file_str.c_str(), true, new StringSink(plain));

    //#include <cryptopp/filters.h> 
    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    string cipher;
    CryptoPP::GCM<AES, CryptoPP::GCM_64K_Tables >::Encryption encryptor;
    encryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte, iv_byte.size());

    const int tagSize = 12;

    StringSource ss1(plain, true, new CryptoPP::AuthenticatedEncryptionFilter(encryptor, new StringSink(cipher), false, tagSize));

    StringSource(cipher, true, new HexEncoder(new FileSink(ciphertext_file_str.c_str())));

    cout << "Encryption completed!" << endl;
}

void DecryptGCM(const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    string key, iv, cipher;
    string key_file_str(key_file);
    string iv_file_str(iv_file);
    string ciphertext_file_str(ciphertext_file);
    FileSource(key_file_str.c_str(), true, new HexDecoder(new  StringSink(key)));
    FileSource(iv_file_str.c_str(), true, new HexDecoder(new  StringSink(iv)));
    FileSource(ciphertext_file_str.c_str(), true, new HexDecoder(new StringSink(cipher)));

    const CryptoPP::SecByteBlock key_byte((const unsigned char*)key.data(), key.size());
    const CryptoPP::SecByteBlock iv_byte((const unsigned char*)iv.data(), iv.size());

    const int tagSize = 12;

    string recovered;
    string recovered_file_str(recovered_file);
    CryptoPP::GCM<AES, CryptoPP::GCM_64K_Tables >::Decryption decryptor;
    decryptor.SetKeyWithIV(key_byte, key_byte.size(), iv_byte, iv_byte.size());

    CryptoPP::AuthenticatedDecryptionFilter df(decryptor,
        new StringSink(recovered), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, tagSize
    );
    StringSource ss2(cipher, true,
        new CryptoPP::Redirector(df)
    );
    StringSource(recovered, true, new FileSink(recovered_file_str.c_str()));

    cout << "Decryption completed!" << endl;
}

void Encrypt(const char* mode, const char* key_file, const char* iv_file, const char* plaintext_file, const char* ciphertext_file) {
    if (strcmp(mode, "CBC") == 0) {
        EncryptCBC(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else if (strcmp(mode, "CFB") == 0) {
        EncryptCFB(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else if (strcmp(mode, "OFB") == 0) {
        EncryptOFB(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else if (strcmp(mode, "CTR") == 0) {
        EncryptCTR(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else if (strcmp(mode, "ECB") == 0) {
        EncryptECB(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else if (strcmp(mode, "XTS") == 0) {
        EncryptXTS(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else if (strcmp(mode, "CCM") == 0) {
        EncryptCCM(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else if (strcmp(mode, "GCM") == 0) {
        EncryptGCM(key_file, iv_file, plaintext_file, ciphertext_file);
    }
    else {
        cout << "Invalid mode, please re-check the usage!" << endl;
        return;
    }
}

void Decrypt(const char* mode, const char* key_file, const char* iv_file, const char* ciphertext_file, const char* recovered_file) {
    if (strcmp(mode, "CBC") == 0) {
        DecryptCBC(key_file, iv_file, ciphertext_file,recovered_file);
    }
    else if (strcmp(mode, "CFB") == 0) {
        DecryptCFB(key_file, iv_file, ciphertext_file, recovered_file);
    }
    else if (strcmp(mode, "OFB") == 0) {
        DecryptOFB(key_file, iv_file, ciphertext_file, recovered_file);
    }
    else if (strcmp(mode, "CTR") == 0) {
        DecryptCTR(key_file, iv_file, ciphertext_file, recovered_file);
    }
    else if (strcmp(mode, "ECB") == 0) {
        DecryptECB(key_file, iv_file, ciphertext_file, recovered_file);
    }
    else if (strcmp(mode, "XTS") == 0) {
        DecryptXTS(key_file, iv_file, ciphertext_file, recovered_file);
    }
    else if (strcmp(mode, "CCM") == 0) {
        DecryptCCM(key_file, iv_file, ciphertext_file, recovered_file);
    }
    else if (strcmp(mode, "GCM") == 0) {
        DecryptGCM(key_file, iv_file, ciphertext_file, recovered_file);
    }
    else {
        cout << "Invalid mode, please re-check the usage!" << endl;
        return;
    }
}

int main(int argc, char* argv[]) {
#ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
#endif

#ifdef _WIN32
    // Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc < 2) {
        cout << "Please read the usage!" << endl;
        Usage();
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (argc != 4) {
            cout << "Wrong number of arguments for keygen, please re-check the usage!" << endl;
            return 1;
        }
        KeyGen(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "ivgen") == 0) {
        if (argc != 4) {
            cout << "Wrong number of arguments for ivgen, please re-check the usage!" << endl;
            return 1;
        }
        IVGen(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "encrypt") == 0) {
        if (argc != 7) {
            cout << "Wrong number of arguments for encrypt, please re-check the usage!" << endl;
            return 1;
        }
        Encrypt(argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc != 8) {
            cout << "Wrong number of arguments for decrypt, please re-check the usage!" << endl;
            return 1;
        }
        Decrypt(argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    else {
        cout << "Invalid command, please re-check the usage!" << endl;
        return 1;
    }
    return 0;
}