#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace dns {

// DNS record type constants
enum class RecordType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    AAAA = 28
};

// DNS class constants
enum class RecordClass : uint16_t {
    IN = 1, // Internet
};

// Base class for DNS records
class DNSRecord {
  public:
    virtual ~DNSRecord() = default;

    virtual RecordType type() const = 0;
    virtual std::vector<uint8_t> serialize() const = 0;
    virtual std::string to_string() const = 0;
};

// A record (IPv4 address)
class ARecord : public DNSRecord {
  public:
    explicit ARecord(uint32_t address);
    explicit ARecord(const std::string &ip_string);

    RecordType type() const override { return RecordType::A; }
    std::vector<uint8_t> serialize() const override;
    std::string to_string() const override;

    uint32_t address() const { return address_; }

  private:
    uint32_t address_; // Network byte order
};

// AAAA record (IPv6 address)
class AAAARecord : public DNSRecord {
  public:
    explicit AAAARecord(const uint8_t address[16]);
    explicit AAAARecord(const std::string &ip_string);

    RecordType type() const override { return RecordType::AAAA; }
    std::vector<uint8_t> serialize() const override;
    std::string to_string() const override;

    const uint8_t *address() const { return address_; }

  private:
    uint8_t address_[16];
};

// CNAME record (canonical name)
class CNAMERecord : public DNSRecord {
  public:
    explicit CNAMERecord(std::string cname);

    RecordType type() const override { return RecordType::CNAME; }
    std::vector<uint8_t> serialize() const override;
    std::string to_string() const override;

    const std::string &cname() const { return cname_; }

  private:
    std::string cname_;
};

// Factory function to parse RDATA into appropriate record type
std::unique_ptr<DNSRecord> parse_rdata(RecordType type, const uint8_t *rdata,
                                       size_t rdata_len);

} // namespace dns
