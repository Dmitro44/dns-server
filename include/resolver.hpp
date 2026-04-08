#pragma once

#include "dns_packet.hpp"
#include "zone_loader.hpp"

namespace dns {

// DNS resolver - queries zone data and constructs DNS responses
class Resolver {
  public:
    // Constructor: takes reference to zone loader
    explicit Resolver(ZoneLoader &zone_loader);

    // Resolve a DNS query packet and return response packet
    DNSPacket resolve(const DNSPacket &query);

  private:
    ZoneLoader &zone_loader_;

    // Maximum CNAME chain depth to prevent infinite loops
    static constexpr int MAX_CNAME_DEPTH = 10;

    // Helper: follow CNAME chain and collect all records
    bool
    follow_cname_chain(const std::string &start_name, RecordType target_type,
                       std::vector<DNSPacket::ResourceRecord> &answer_records,
                       int depth = 0);

    // Helper: set DNS response flags
    static void set_response_flags(DNSPacket::Header &header,
                                   bool authoritative, uint8_t rcode);
};

} // namespace dns
