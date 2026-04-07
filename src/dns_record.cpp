#include "dns_record.hpp"
#include <arpa/inet.h>
#include <cstring>

namespace dns {

namespace {

bool write_name(std::vector<uint8_t> &out, const std::string &name) {
    if (name.empty()) {
        out.push_back(0);
        return true;
    }

    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        size_t end = (dot == std::string::npos) ? name.size() : dot;
        size_t label_len = end - start;

        if (label_len == 0)
            return false;
        if (label_len > 63)
            return false;

        out.push_back(static_cast<uint8_t>(label_len));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                   name.begin() + static_cast<std::ptrdiff_t>(end));

        if (dot == std::string::npos)
            break;
        start = dot + 1;
    }

    if (!name.empty() && name.back() == '.') {
        if (name.size() > 1 && name[name.size() - 2] == '.')
            return false;
    }

    out.push_back(0);
    return true;
}

} // namespace

ARecord::ARecord(uint32_t address) : address_(address) {}

ARecord::ARecord(const std::string &ip_string) {
    inet_pton(AF_INET, ip_string.c_str(), reinterpret_cast<void *>(&address_));
}

std::vector<uint8_t> ARecord::serialize() const {
    std::vector<uint8_t> result(4);
    std::memcpy(result.data(), &address_, 4);
    return result;
}

std::string ARecord::to_string() const {
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address_, buffer, sizeof(buffer));
    return std::string(buffer);
}

AAAARecord::AAAARecord(const uint8_t address[16]) {
    std::memcpy(address_, address, 16);
}

AAAARecord::AAAARecord(const std::string &ip_string) {
    inet_pton(AF_INET6, ip_string.c_str(), address_);
}

std::vector<uint8_t> AAAARecord::serialize() const {
    return std::vector<uint8_t>(address_, address_ + 16);
}

std::string AAAARecord::to_string() const {
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, address_, buffer, sizeof(buffer));
    return std::string(buffer);
}

CNAMERecord::CNAMERecord(std::string cname) : cname_(std::move(cname)) {}

std::vector<uint8_t> CNAMERecord::serialize() const {
    std::vector<uint8_t> result;
    write_name(result, cname_);
    return result;
}

std::string CNAMERecord::to_string() const { return cname_; }

std::unique_ptr<DNSRecord> parse_rdata(RecordType type, const uint8_t *rdata,
                                       size_t rdata_len) {
    switch (type) {
    case RecordType::A:
        if (rdata_len == 4) {
            uint32_t address;
            std::memcpy(&address, rdata, 4);
            return std::make_unique<ARecord>(address);
        }
        break;

    case RecordType::AAAA:
        if (rdata_len == 16) {
            return std::make_unique<AAAARecord>(rdata);
        }
        break;

    case RecordType::CNAME: {
        std::string cname(reinterpret_cast<const char *>(rdata), rdata_len);
        return std::make_unique<CNAMERecord>(std::move(cname));
    }

    default:
        break;
    }

    return nullptr;
}

} // namespace dns
