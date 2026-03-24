#include "dns_packet.hpp"
#include <arpa/inet.h>
#include <cstring>

namespace dns {

bool DNSPacket::parse(const uint8_t* data, size_t len) {
    if (len < 12) return false;

    // Parse header (network byte order -> host byte order)
    std::memcpy(&header.id, data, 2);
    header.id = ntohs(header.id);
    
    std::memcpy(&header.flags, data + 2, 2);
    header.flags = ntohs(header.flags);
    
    std::memcpy(&header.qdcount, data + 4, 2);
    header.qdcount = ntohs(header.qdcount);
    
    std::memcpy(&header.ancount, data + 6, 2);
    header.ancount = ntohs(header.ancount);
    
    std::memcpy(&header.nscount, data + 8, 2);
    header.nscount = ntohs(header.nscount);
    
    std::memcpy(&header.arcount, data + 10, 2);
    header.arcount = ntohs(header.arcount);

    // TODO: parse questions
    return true;
}

std::vector<uint8_t> DNSPacket::serialize() const {
    std::vector<uint8_t> result;
    
    // Header
    uint16_t id = htons(header.id);
    uint16_t flags = htons(header.flags);
    uint16_t qdcount = htons(header.qdcount);
    uint16_t ancount = htons(header.ancount);
    uint16_t nscount = htons(header.nscount);
    uint16_t arcount = htons(header.arcount);
    
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&id), reinterpret_cast<const uint8_t*>(&id) + 2);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&flags), reinterpret_cast<const uint8_t*>(&flags) + 2);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&qdcount), reinterpret_cast<const uint8_t*>(&qdcount) + 2);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&ancount), reinterpret_cast<const uint8_t*>(&ancount) + 2);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&nscount), reinterpret_cast<const uint8_t*>(&nscount) + 2);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&arcount), reinterpret_cast<const uint8_t*>(&arcount) + 2);
    
    // TODO: serialize questions
    
    return result;
}

} // namespace dns

int main() {
    dns::DNSPacket packet;
    
    // Test DNS header parsing
    uint8_t data[] = {
        0x00, 0x01,  // ID: 1
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // QDCOUNT: 1
        0x00, 0x00,  // ANCOUNT: 0
        0x00, 0x00,  // NSCOUNT: 0
        0x00, 0x00   // ARCOUNT: 0
    };
    
    packet.parse(data, sizeof(data));
    
    return 0;
}
