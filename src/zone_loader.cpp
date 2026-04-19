#include "zone_loader.hpp"
#include "logger.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <sstream>

namespace dns {

bool ZoneLoader::load(const std::string &zone_file_path) {
    std::ifstream file(zone_file_path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open zone file: " << zone_file_path);
        return false;
    }

    current_origin_ = "";
    current_ttl_ = 3600;
    records_.clear();

    std::string line;
    while (std::getline(file, line)) {
        size_t comment_pos = line.find(';');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }

        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) {
            continue;
        }

        if (!parse_line(line)) {
            if (line.find('(') != std::string::npos) {
                std::istringstream iss(line);
                std::string name, in_class, type;
                uint32_t ttl = current_ttl_;

                iss >> name;
                std::string token;
                iss >> token;

                if (std::isdigit(token[0])) {
                    ttl = std::stoul(token);
                    iss >> in_class >> type;
                } else {
                    in_class = token;
                    iss >> type;
                }

                if (type == "SOA") {
                    uint16_t rclass = static_cast<uint16_t>(RecordClass::IN);
                    parse_soa_record(file, name, ttl, rclass);
                }
            }
        }
    }

    return true;
}

std::string ZoneLoader::make_fqdn(const std::string &name) const {
    if (name == "@") {
        return current_origin_;
    }

    if (name.empty() || name.back() == '.') {
        return name;
    }

    return name + "." + current_origin_;
}

bool ZoneLoader::parse_line(const std::string &line) {
    std::istringstream iss(line);
    std::string token;
    iss >> token;

    if (token == "$ORIGIN") {
        iss >> current_origin_;
        if (!current_origin_.empty() && current_origin_.back() != '.') {
            current_origin_ += '.';
        }
        return true;
    }

    if (token == "$TTL") {
        iss >> current_ttl_;
        return true;
    }

    if (token.find('(') != std::string::npos) {
        return false;
    }

    std::string name = token;
    uint32_t ttl = current_ttl_;
    std::string rclass_str;
    std::string type_str;

    iss >> token;
    if (std::isdigit(token[0])) {
        ttl = std::stoul(token);
        iss >> rclass_str >> type_str;
    } else {
        rclass_str = token;
        iss >> type_str;
    }

    if (rclass_str != "IN") {
        return true;
    }

    std::string fqdn = make_fqdn(name);
    uint16_t rclass = static_cast<uint16_t>(RecordClass::IN);
    DNSPacket::ResourceRecord record;
    record.name = fqdn;
    record.rclass = rclass;
    record.ttl = ttl;

    if (type_str == "A") {
        record.type = static_cast<uint16_t>(RecordType::A);
        std::string ip;
        iss >> ip;
        record.rdata = encode_ipv4(ip);
    } else if (type_str == "AAAA") {
        record.type = static_cast<uint16_t>(RecordType::AAAA);
        std::string ip;
        iss >> ip;
        record.rdata = encode_ipv6(ip);
    } else if (type_str == "CNAME") {
        record.type = static_cast<uint16_t>(RecordType::CNAME);
        std::string target;
        iss >> target;
        std::string target_fqdn = make_fqdn(target);
        record.rdata = encode_domain_name(target_fqdn);
    } else if (type_str == "NS") {
        record.type = static_cast<uint16_t>(RecordType::NS);
        std::string ns_name;
        iss >> ns_name;
        std::string ns_fqdn = make_fqdn(ns_name);
        record.rdata = encode_domain_name(ns_fqdn);
    } else {
        return true;
    }

    records_[fqdn].push_back(record);
    return true;
}

bool ZoneLoader::parse_soa_record(std::ifstream &file, const std::string &name,
                                  uint32_t ttl, uint16_t rclass) {
    std::string line;
    std::string accumulated;

    file.seekg(-static_cast<int>(file.gcount()), std::ios::cur);
    std::getline(file, line);

    accumulated = line;
    while (std::getline(file, line)) {
        size_t comment_pos = line.find(';');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        accumulated += " " + line;
        if (line.find(')') != std::string::npos) {
            break;
        }
    }

    size_t open_paren = accumulated.find('(');
    size_t close_paren = accumulated.find(')');

    std::string before_paren = accumulated.substr(0, open_paren);
    std::string inside_paren =
        accumulated.substr(open_paren + 1, close_paren - open_paren - 1);

    std::istringstream before_iss(before_paren);
    std::string rec_name, in_class, type, mname, rname;
    before_iss >> rec_name >> in_class >> type >> mname >> rname;

    std::istringstream inside_iss(inside_paren);
    uint32_t serial, refresh, retry, expire, minimum;
    inside_iss >> serial >> refresh >> retry >> expire >> minimum;

    std::string fqdn = make_fqdn(rec_name);
    std::string mname_fqdn = make_fqdn(mname);
    std::string rname_fqdn = make_fqdn(rname);

    DNSPacket::ResourceRecord record;
    record.name = fqdn;
    record.type = static_cast<uint16_t>(RecordType::SOA);
    record.rclass = rclass;
    record.ttl = ttl;

    std::vector<uint8_t> rdata;
    std::vector<uint8_t> mname_encoded = encode_domain_name(mname_fqdn);
    std::vector<uint8_t> rname_encoded = encode_domain_name(rname_fqdn);

    rdata.insert(rdata.end(), mname_encoded.begin(), mname_encoded.end());
    rdata.insert(rdata.end(), rname_encoded.begin(), rname_encoded.end());

    uint32_t serial_net = htonl(serial);
    uint32_t refresh_net = htonl(refresh);
    uint32_t retry_net = htonl(retry);
    uint32_t expire_net = htonl(expire);
    uint32_t minimum_net = htonl(minimum);

    const uint8_t *serial_bytes =
        reinterpret_cast<const uint8_t *>(&serial_net);
    const uint8_t *refresh_bytes =
        reinterpret_cast<const uint8_t *>(&refresh_net);
    const uint8_t *retry_bytes = reinterpret_cast<const uint8_t *>(&retry_net);
    const uint8_t *expire_bytes =
        reinterpret_cast<const uint8_t *>(&expire_net);
    const uint8_t *minimum_bytes =
        reinterpret_cast<const uint8_t *>(&minimum_net);

    rdata.insert(rdata.end(), serial_bytes, serial_bytes + 4);
    rdata.insert(rdata.end(), refresh_bytes, refresh_bytes + 4);
    rdata.insert(rdata.end(), retry_bytes, retry_bytes + 4);
    rdata.insert(rdata.end(), expire_bytes, expire_bytes + 4);
    rdata.insert(rdata.end(), minimum_bytes, minimum_bytes + 4);

    record.rdata = rdata;
    records_[fqdn].push_back(record);

    return true;
}

std::vector<uint8_t>
ZoneLoader::encode_domain_name(const std::string &domain) const {
    std::vector<uint8_t> result;
    std::istringstream iss(domain);
    std::string label;

    while (std::getline(iss, label, '.')) {
        if (label.empty()) {
            continue;
        }
        result.push_back(static_cast<uint8_t>(label.size()));
        result.insert(result.end(), label.begin(), label.end());
    }

    result.push_back(0);
    return result;
}

std::vector<uint8_t> ZoneLoader::encode_ipv4(const std::string &ip) const {
    std::vector<uint8_t> result(4);
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&addr.s_addr);
        result.assign(bytes, bytes + 4);
    }
    return result;
}

std::vector<uint8_t> ZoneLoader::encode_ipv6(const std::string &ip) const {
    std::vector<uint8_t> result(16);
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ip.c_str(), &addr) == 1) {
        result.assign(addr.s6_addr, addr.s6_addr + 16);
    }
    return result;
}

std::vector<DNSPacket::ResourceRecord>
ZoneLoader::get_records(const std::string &name, RecordType type) const {
    std::vector<DNSPacket::ResourceRecord> result;
    auto it = records_.find(name);
    if (it == records_.end()) {
        return result;
    }

    uint16_t type_value = static_cast<uint16_t>(type);
    for (const auto &record : it->second) {
        if (record.type == type_value) {
            result.push_back(record);
        }
    }
    return result;
}

std::vector<DNSPacket::ResourceRecord>
ZoneLoader::get_records(const std::string &name) const {
    auto it = records_.find(name);
    if (it == records_.end()) {
        return {};
    }
    return it->second;
}

} // namespace dns
