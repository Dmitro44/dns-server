#include "resolver.hpp"
#include "dns_record.hpp"
#include "logger.hpp"

namespace dns {

// Normalize domain name to FQDN with trailing dot
static std::string normalize_name(const std::string &name) {
    if (name.empty() || name.back() == '.') {
        return name;
    }
    return name + '.';
}

Resolver::Resolver(ZoneLoader &zone_loader) : zone_loader_(zone_loader) {}

DNSPacket Resolver::resolve(const DNSPacket &query) {
    DNSPacket response;
    response.header.id = query.header.id;

    if (query.questions.empty()) {
        set_response_flags(response.header, false, 2);
        return response;
    }

    const auto &question = query.questions[0];
    response.questions.push_back(question);
    response.header.qdcount = 1;

    std::string qname = normalize_name(question.qname);

    RecordType query_type = static_cast<RecordType>(question.qtype);

    if (query_type == RecordType::A || query_type == RecordType::AAAA) {
        if (follow_cname_chain(qname, query_type, response.answers)) {
            set_response_flags(response.header, true, 0);
            response.header.ancount =
                static_cast<uint16_t>(response.answers.size());
        } else {
            set_response_flags(response.header, true, 3);
        }
    } else {
        auto records = zone_loader_.get_records(qname, query_type);
        if (!records.empty()) {
            response.answers = std::move(records);
            response.header.ancount =
                static_cast<uint16_t>(response.answers.size());
            set_response_flags(response.header, true, 0);
        } else {
            set_response_flags(response.header, true, 3);
        }
    }

    return response;
}

bool Resolver::follow_cname_chain(
    const std::string &start_name, RecordType target_type,
    std::vector<DNSPacket::ResourceRecord> &answer_records, int depth) {
    if (depth >= MAX_CNAME_DEPTH) {
        LOG_WARNING("CNAME chain too deep, possible loop detected for " << start_name);
        return false;
    }

    std::string search_name = normalize_name(start_name);

    auto direct_records = zone_loader_.get_records(search_name, target_type);
    if (!direct_records.empty()) {
        answer_records.insert(answer_records.end(), direct_records.begin(),
                              direct_records.end());
        return true;
    }

    auto cname_records =
        zone_loader_.get_records(search_name, RecordType::CNAME);

    if (cname_records.empty()) {
        return false;
    }

    for (const auto &cname_rec : cname_records) {
        answer_records.push_back(cname_rec);

        auto parsed = parse_rdata(RecordType::CNAME, cname_rec.rdata.data(),
                                  cname_rec.rdata.size());
        if (!parsed) {
            LOG_ERROR("Failed to parse CNAME rdata");
            return false;
        }

        auto *cname = dynamic_cast<CNAMERecord *>(parsed.get());
        if (!cname) {
            LOG_ERROR("CNAME record type mismatch");
            return false;
        }

        std::string target_name = normalize_name(cname->cname());

        if (follow_cname_chain(target_name, target_type, answer_records,
                               depth + 1)) {
            return true;
        }
    }

    return false;
}

void Resolver::set_response_flags(DNSPacket::Header &header, bool authoritative,
                                  uint8_t rcode) {
    uint16_t flags = 0;
    flags |= (1 << 15);

    if (authoritative) {
        flags |= (1 << 10);
    }

    flags |= (rcode & 0x0F);

    header.flags = flags;
}

} // namespace dns
