#include "dns_packet.hpp"
#include "dns_record.hpp"
#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>

namespace dns {

namespace {

bool read_u16(const uint8_t *data, size_t len, size_t &offset, uint16_t &out) {
    if (offset + 2 > len)
        return false;
    std::memcpy(&out, data + offset, sizeof(uint16_t));
    out = ntohs(out);
    offset += 2;
    return true;
}

bool read_u32(const uint8_t *data, size_t len, size_t &offset, uint32_t &out) {
    if (offset + 4 > len)
        return false;
    std::memcpy(&out, data + offset, sizeof(uint32_t));
    out = ntohl(out);
    offset += 4;
    return true;
}

// Parses a domain name from packet data (supports compression pointers).
// `offset` is advanced only for bytes consumed from the original stream.
bool parse_name(const uint8_t *data, size_t len, size_t &offset,
                std::string &out_name) {
    out_name.clear();

    size_t current = offset;
    bool jumped = false;
    size_t jumps = 0;

    while (true) {
        if (current >= len)
            return false;

        uint8_t length = data[current];

        // In DNS names, if top 2 bits are 11, this is a compression pointer.
        // Compression pointer: 11xxxxxx xxxxxxxx
        if ((length & 0xC0) == 0xC0) {
            if (current + 1 >= len)
                return false;

            uint16_t pointer = static_cast<uint16_t>(((length & 0x3F) << 8) |
                                                     data[current + 1]);
            if (pointer >= len)
                return false;

            if (!jumped) {
                // First pointer consumes 2 bytes in original stream.
                offset = current + 2;
                jumped = true;
            }

            current = pointer;

            // Guard against pointer loops / malformed packets.
            if (++jumps > len)
                return false;
            continue;
        }

        // Reserved label type 01/10 is invalid for QNAME labels.
        if ((length & 0xC0) != 0x00)
            return false;

        // End of name.
        if (length == 0) {
            if (!jumped)
                offset = current + 1;
            return true;
        }

        if (length > 63)
            return false;

        current += 1;
        if (current + length > len)
            return false;

        if (!out_name.empty())
            out_name.push_back('.');
        out_name.append(reinterpret_cast<const char *>(data + current), length);

        current += length;

        if (!jumped) {
            // While parsing in original stream (before first jump), keep offset
            // in sync.
            offset = current;
        }
    }
}

void write_u16(std::vector<uint8_t> &out, uint16_t value) {
    uint16_t be = htons(value);
    const auto *ptr = reinterpret_cast<const uint8_t *>(&be);
    out.insert(out.end(), ptr, ptr + 2);
}

void write_u32(std::vector<uint8_t> &out, uint32_t value) {
    uint32_t be = htonl(value);
    const auto *ptr = reinterpret_cast<const uint8_t *>(&be);
    out.insert(out.end(), ptr, ptr + 4);
}

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

        // Empty label in the middle (e.g. "a..b") is invalid.
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

    // Trailing dot means explicit root label (already covered by terminating
    // zero), so we ignore the final empty label and still emit one root
    // terminator below.
    if (!name.empty() && name.back() == '.') {
        // Reject single "." handled by empty case above, and avoid accepting
        // ".." patterns.
        if (name.size() > 1 && name[name.size() - 2] == '.')
            return false;
    }

    out.push_back(0);
    return true;
}

} // namespace

bool DNSPacket::parse(const uint8_t *data, size_t len) {
    if (data == nullptr || len < 12)
        return false;

    size_t offset = 0;

    if (!read_u16(data, len, offset, header.id))
        return false;
    if (!read_u16(data, len, offset, header.flags))
        return false;
    if (!read_u16(data, len, offset, header.qdcount))
        return false;
    if (!read_u16(data, len, offset, header.ancount))
        return false;
    if (!read_u16(data, len, offset, header.nscount))
        return false;
    if (!read_u16(data, len, offset, header.arcount))
        return false;

    questions.clear();
    questions.reserve(header.qdcount);

    for (uint16_t i = 0; i < header.qdcount; ++i) {
        Question q;
        if (!parse_name(data, len, offset, q.qname))
            return false;
        if (!read_u16(data, len, offset, q.qtype))
            return false;
        if (!read_u16(data, len, offset, q.qclass))
            return false;
        questions.push_back(std::move(q));
    }

    answers.clear();
    answers.reserve(header.ancount);
    for (uint16_t i = 0; i < header.ancount; ++i) {
        ResourceRecord rr;
        if (!parse_name(data, len, offset, rr.name))
            return false;
        if (!read_u16(data, len, offset, rr.type))
            return false;
        if (!read_u16(data, len, offset, rr.rclass))
            return false;
        if (!read_u32(data, len, offset, rr.ttl))
            return false;

        uint16_t rdlength;
        if (!read_u16(data, len, offset, rdlength))
            return false;

        if (offset + rdlength > len)
            return false;

        rr.rdata.assign(data + offset, data + offset + rdlength);
        offset += rdlength;

        answers.push_back(std::move(rr));
    }

    authorities.clear();
    authorities.reserve(header.nscount);
    for (uint16_t i = 0; i < header.nscount; ++i) {
        ResourceRecord rr;
        if (!parse_name(data, len, offset, rr.name))
            return false;
        if (!read_u16(data, len, offset, rr.type))
            return false;
        if (!read_u16(data, len, offset, rr.rclass))
            return false;
        if (!read_u32(data, len, offset, rr.ttl))
            return false;

        uint16_t rdlength;
        if (!read_u16(data, len, offset, rdlength))
            return false;

        if (offset + rdlength > len)
            return false;

        rr.rdata.assign(data + offset, data + offset + rdlength);
        offset += rdlength;

        authorities.push_back(std::move(rr));
    }

    additionals.clear();
    additionals.reserve(header.arcount);
    for (uint16_t i = 0; i < header.arcount; ++i) {
        ResourceRecord rr;
        if (!parse_name(data, len, offset, rr.name))
            return false;
        if (!read_u16(data, len, offset, rr.type))
            return false;
        if (!read_u16(data, len, offset, rr.rclass))
            return false;
        if (!read_u32(data, len, offset, rr.ttl))
            return false;

        uint16_t rdlength;
        if (!read_u16(data, len, offset, rdlength))
            return false;

        if (offset + rdlength > len)
            return false;

        rr.rdata.assign(data + offset, data + offset + rdlength);
        offset += rdlength;

        additionals.push_back(std::move(rr));
    }

    return true;
}

std::vector<uint8_t> DNSPacket::serialize() const {
    std::vector<uint8_t> result;

    write_u16(result, header.id);
    write_u16(result, header.flags);
    write_u16(result, static_cast<uint16_t>(questions.size()));
    write_u16(result, static_cast<uint16_t>(answers.size()));
    write_u16(result, static_cast<uint16_t>(authorities.size()));
    write_u16(result, static_cast<uint16_t>(additionals.size()));

    for (const auto &q : questions) {
        if (!write_name(result, q.qname)) {
            return {};
        }
        write_u16(result, q.qtype);
        write_u16(result, q.qclass);
    }

    for (const auto &rr : answers) {
        if (!write_name(result, rr.name)) {
            return {};
        }
        write_u16(result, rr.type);
        write_u16(result, rr.rclass);
        write_u32(result, rr.ttl);
        write_u16(result, static_cast<uint16_t>(rr.rdata.size()));
        result.insert(result.end(), rr.rdata.begin(), rr.rdata.end());
    }

    for (const auto &rr : authorities) {
        if (!write_name(result, rr.name)) {
            return {};
        }
        write_u16(result, rr.type);
        write_u16(result, rr.rclass);
        write_u32(result, rr.ttl);
        write_u16(result, static_cast<uint16_t>(rr.rdata.size()));
        result.insert(result.end(), rr.rdata.begin(), rr.rdata.end());
    }

    for (const auto &rr : additionals) {
        if (!write_name(result, rr.name)) {
            return {};
        }
        write_u16(result, rr.type);
        write_u16(result, rr.rclass);
        write_u32(result, rr.ttl);
        write_u16(result, static_cast<uint16_t>(rr.rdata.size()));
        result.insert(result.end(), rr.rdata.begin(), rr.rdata.end());
    }

    return result;
}

} // namespace dns

int main() {
    dns::DNSPacket packet;

    uint8_t query_data[] = {0x00, 0x01, // ID: 1
                            0x01, 0x00, // Flags: standard query
                            0x00, 0x01, // QDCOUNT: 1
                            0x00, 0x00, // ANCOUNT: 0
                            0x00, 0x00, // NSCOUNT: 0
                            0x00, 0x00, // ARCOUNT: 0
                            0x03, 'w',  'w',  'w',  0x07, 'e',  'x',
                            'a',  'm',  'p',  'l',  'e',  0x03, 'c',
                            'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01};

    if (!packet.parse(query_data, sizeof(query_data))) {
        std::cerr << "Failed to parse DNS query\n";
        return 1;
    }

    std::cout << "Parsed DNS Query:\n";
    std::cout << "  ID: " << packet.header.id << "\n";
    std::cout << "  Questions: " << packet.questions.size() << "\n";
    if (!packet.questions.empty()) {
        std::cout << "    Name: " << packet.questions[0].qname << "\n";
        std::cout << "    Type: " << packet.questions[0].qtype << "\n";
        std::cout << "    Class: " << packet.questions[0].qclass << "\n";
    }

    dns::DNSPacket response;
    response.header.id = packet.header.id;
    response.header.flags = 0x8180;
    response.questions = packet.questions;

    dns::DNSPacket::ResourceRecord rr;
    rr.name = "www.example.com";
    rr.type = 1;
    rr.rclass = 1;
    rr.ttl = 3600;

    dns::ARecord a_record("192.168.1.10");
    rr.rdata = a_record.serialize();

    response.answers.push_back(rr);

    auto response_data = response.serialize();
    std::cout << "\nSerialized DNS Response (" << response_data.size()
              << " bytes)\n";

    dns::DNSPacket parsed_response;
    if (!parsed_response.parse(response_data.data(), response_data.size())) {
        std::cerr << "Failed to parse serialized response\n";
        return 1;
    }

    std::cout << "Parsed DNS Response:\n";
    std::cout << "  ID: " << parsed_response.header.id << "\n";
    std::cout << "  Answers: " << parsed_response.answers.size() << "\n";
    if (!parsed_response.answers.empty()) {
        const auto &answer = parsed_response.answers[0];
        std::cout << "    Name: " << answer.name << "\n";
        std::cout << "    Type: " << answer.type << "\n";
        std::cout << "    TTL: " << answer.ttl << "\n";

        auto record =
            dns::parse_rdata(static_cast<dns::RecordType>(answer.type),
                             answer.rdata.data(), answer.rdata.size());
        if (record) {
            std::cout << "    RDATA: " << record->to_string() << "\n";
        }
    }

    return 0;
}
