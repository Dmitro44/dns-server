#include "resolver.hpp"
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

    std::cout << "\n=== DNS Resolver Tests ===\n\n";

    dns::Resolver resolver(loader);

    auto test_query = [&](const std::string &qname, uint16_t qtype,
                          const std::string &desc) {
        std::cout << "Test: " << desc << "\n";
        std::cout << "Query: " << qname
                  << " (Type: " << record_type_to_string(qtype) << ")\n";

        dns::DNSPacket query;
        query.header.id = 12345;
        query.header.flags = 0;
        query.header.qdcount = 1;

        dns::DNSPacket::Question q;
        q.qname = qname;
        q.qtype = qtype;
        q.qclass = 1;
        query.questions.push_back(q);

        dns::DNSPacket response = resolver.resolve(query);

        uint16_t flags = response.header.flags;
        bool is_response = (flags >> 15) & 1;
        bool authoritative = (flags >> 10) & 1;
        bool recursion_available = (flags >> 7) & 1;
        uint8_t rcode = flags & 0x0F;

        std::cout << "Response ID: " << response.header.id
                  << " | QR=" << is_response << " | AA=" << authoritative
                  << " | RA=" << recursion_available
                  << " | RCODE=" << (int)rcode << "\n";

        if (rcode == 0) {
            std::cout << "Answers (" << response.answers.size() << "):\n";
            for (const auto &ans : response.answers) {
                std::cout << "  " << ans.name << " "
                          << record_type_to_string(ans.type) << " "
                          << rdata_to_string(ans.type, ans.rdata) << "\n";
            }
        } else if (rcode == 3) {
            std::cout << "Result: NXDOMAIN (domain not found)\n";
        } else if (rcode == 2) {
            std::cout << "Result: SERVFAIL (server failure)\n";
        }

        std::cout << "\n";
    };

    test_query("www.example.local.", static_cast<uint16_t>(dns::RecordType::A),
               "Direct A record query");

    test_query("www.example.local.",
               static_cast<uint16_t>(dns::RecordType::AAAA),
               "Direct AAAA record query");

    test_query("blog.example.local.", static_cast<uint16_t>(dns::RecordType::A),
               "CNAME chain resolution (blog -> www)");

    test_query("nonexistent.example.local.",
               static_cast<uint16_t>(dns::RecordType::A),
               "Non-existent domain (NXDOMAIN)");

    test_query("example.local.", static_cast<uint16_t>(dns::RecordType::NS),
               "NS record query");

    return 0;
}
