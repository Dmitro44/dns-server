#include "zone_loader.hpp"
#include <iomanip>
#include <iostream>

std::string record_type_to_string(uint16_t type) {
    switch (static_cast<dns::RecordType>(type)) {
    case dns::RecordType::A:
        return "A";
    case dns::RecordType::AAAA:
        return "AAAA";
    case dns::RecordType::CNAME:
        return "CNAME";
    case dns::RecordType::NS:
        return "NS";
    case dns::RecordType::SOA:
        return "SOA";
    default:
        return "UNKNOWN";
    }
}

std::string rdata_to_string(uint16_t type, const std::vector<uint8_t> &rdata) {
    if (type == static_cast<uint16_t>(dns::RecordType::A) &&
        rdata.size() == 4) {
        return std::to_string(rdata[0]) + "." + std::to_string(rdata[1]) + "." +
               std::to_string(rdata[2]) + "." + std::to_string(rdata[3]);
    }

    if (type == static_cast<uint16_t>(dns::RecordType::AAAA) &&
        rdata.size() == 16) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0)
                ss << ":";
            ss << std::setw(2) << static_cast<int>(rdata[i]) << std::setw(2)
               << static_cast<int>(rdata[i + 1]);
        }
        return ss.str();
    }

    if (type == static_cast<uint16_t>(dns::RecordType::CNAME) ||
        type == static_cast<uint16_t>(dns::RecordType::NS)) {
        std::string result;
        size_t pos = 0;
        while (pos < rdata.size()) {
            uint8_t len = rdata[pos++];
            if (len == 0)
                break;
            if (!result.empty())
                result += ".";
            result.append(rdata.begin() + pos, rdata.begin() + pos + len);
            pos += len;
        }
        return result;
    }

    if (type == static_cast<uint16_t>(dns::RecordType::SOA)) {
        return "[SOA record data]";
    }

    return "[binary data]";
}

int main() {
    std::cout << "DNS Server - Zone Loader Test\n";
    std::cout << "==============================\n\n";

    dns::ZoneLoader loader;

    if (!loader.load("zones/example.zone")) {
        std::cerr << "Failed to load zone file\n";
        return 1;
    }

    std::cout << "Zone file loaded successfully!\n\n";

    const auto &all_records = loader.get_all_records();
    std::cout << "Loaded " << all_records.size() << " unique domain names\n\n";

    for (const auto &[name, records] : all_records) {
        std::cout << "Domain: " << name << "\n";
        for (const auto &record : records) {
            std::cout << "  Type: " << std::setw(6) << std::left
                      << record_type_to_string(record.type)
                      << " | TTL: " << std::setw(6) << record.ttl << " | Data: "
                      << rdata_to_string(record.type, record.rdata) << "\n";
        }
        std::cout << "\n";
    }

    return 0;
}
