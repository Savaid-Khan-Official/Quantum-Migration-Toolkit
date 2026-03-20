#ifndef AES_HPP
#define AES_HPP

#include <vector>
#include <cstdint>

class AES {
public:
    // Encrypt data using AES-256-CBC with OpenSSL
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, 
                                   const std::vector<uint8_t>& key, 
                                   const std::vector<uint8_t>& iv);
    
    // Decrypt data using AES-256-CBC with OpenSSL
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, 
                                   const std::vector<uint8_t>& key, 
                                   const std::vector<uint8_t>& iv);
};

#endif // AES_HPP
