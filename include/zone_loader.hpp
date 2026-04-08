#pragma once

#include "dns_packet.hpp"
#include "dns_record.hpp"
#include <string>
#include <unordered_map>
#include <vector>

namespace dns {

// Zone file loader - parses BIND-format zone files
class ZoneLoader {
  public:
    // Load and parse a zone file
    bool load(const std::string &zone_file_path);

    // Get all records for a specific name and type
    std::vector<DNSPacket::ResourceRecord> get_records(const std::string &name,
                                                       RecordType type) const;

    // Get all records for a specific name (any type)
    std::vector<DNSPacket::ResourceRecord>
    get_records(const std::string &name) const;

    // Get all loaded records (for debugging)
    const std::unordered_map<std::string,
                             std::vector<DNSPacket::ResourceRecord>> &
    get_all_records() const {
        return records_;
    }

  private:
    // Storage: map from FQDN to list of resource records
    std::unordered_map<std::string, std::vector<DNSPacket::ResourceRecord>>
        records_;

    // Zone file parsing state
    std::string current_origin_;
    uint32_t current_ttl_;

    // Helper methods
    std::string make_fqdn(const std::string &name) const;
    bool parse_line(const std::string &line);
    bool parse_soa_record(std::ifstream &file, const std::string &name,
                          uint32_t ttl, uint16_t rclass);
    std::vector<uint8_t> encode_domain_name(const std::string &domain) const;
    std::vector<uint8_t> encode_ipv4(const std::string &ip) const;
    std::vector<uint8_t> encode_ipv6(const std::string &ip) const;
};

} // namespace dns
