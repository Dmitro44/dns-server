#pragma once

#include "dns_packet.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <list>
#include <optional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace dns {

struct CacheKey {
    std::string name;
    uint16_t type;

    bool operator==(const CacheKey &other) const {
        return name == other.name && type == other.type;
    }
};

struct CacheKeyHash {
    std::size_t operator()(const CacheKey &k) const {
        return std::hash<std::string>()(k.name) ^
               (std::hash<uint16_t>()(k.type) << 1);
    }
};

struct CacheValue {
    std::vector<DNSPacket::ResourceRecord> records;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t ttl;
    bool is_negative;
};

class DNSCache {
  public:
    explicit DNSCache(size_t max_size = 10000);

    // Add or update an entry in the cache
    void put(const std::string &name, uint16_t type,
             const std::vector<DNSPacket::ResourceRecord> &records,
             uint32_t ttl);

    // Retrieve an entry from the cache, checking TTL
    std::optional<std::vector<DNSPacket::ResourceRecord>>
    get(const std::string &name, uint16_t type);

    // Statistics
    size_t get_hits() const;
    size_t get_misses() const;
    size_t size() const;

    // Clear the cache completely
    void clear();

  private:
    using ListType = std::list<std::pair<CacheKey, CacheValue>>;
    using MapType =
        std::unordered_map<CacheKey, ListType::iterator, CacheKeyHash>;

    size_t max_size_;
    ListType cache_list_;
    MapType cache_map_;

    mutable std::mutex mutex_;

    std::atomic<size_t> hits_{0};
    std::atomic<size_t> misses_{0};
};

} // namespace dns
