#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dns {

// DNS packet structure
class DNSPacket {
  public:
    struct Header {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
    };

    struct Question {
        std::string qname;
        uint16_t qtype;
        uint16_t qclass;
    };

    struct ResourceRecord {
        std::string name;
        uint16_t type;
        uint16_t rclass;
        uint32_t ttl;
        std::vector<uint8_t> rdata;
    };

    Header header;
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;

    bool parse(const uint8_t *data, size_t len);
    std::vector<uint8_t> serialize() const;
};

} // namespace dns
