#include "cache.hpp"
#include "logger.hpp"
#include <mutex>

namespace dns {

DNSCache::DNSCache(size_t max_size) : max_size_(max_size > 0 ? max_size : 1) {}

void DNSCache::put(const std::string &name, uint16_t type,
                   const std::vector<DNSPacket::ResourceRecord> &records,
                   uint32_t ttl) {
    if (records.empty()) {
        return;
    }

    CacheKey key{name, type};
    CacheValue value{records, std::chrono::steady_clock::now(), ttl};

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
        // Update existing item and move to front
        cache_list_.erase(it->second);
    } else if (cache_map_.size() >= max_size_) {
        // Evict least recently used
        cache_map_.erase(cache_list_.back().first);
        cache_list_.pop_back();
    }

    cache_list_.emplace_front(std::make_pair(key, value));
    cache_map_[key] = cache_list_.begin();

    LOG_INFO("Cache PUT: " << name << " Type: " << type << " TTL: " << ttl);
}

std::optional<std::vector<DNSPacket::ResourceRecord>>
DNSCache::get(const std::string &name, uint16_t type) {
    CacheKey key{name, type};
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                            now - it->second->second.timestamp)
                            .count();

        if (duration <= it->second->second.ttl) {
            auto records = it->second->second.records;
            hits_.fetch_add(1, std::memory_order_relaxed);

            // Promote to front of LRU (most recently used)
            cache_list_.splice(cache_list_.begin(), cache_list_, it->second);

            LOG_DEBUG("Cache HIT: " << name << " Type: " << type);
            return records;
        } else {
            // Expired, so we should clean it up
            cache_list_.erase(it->second);
            cache_map_.erase(it);
            LOG_DEBUG("Cache EXPIRED: " << name << " Type: " << type);
        }
    }

    misses_.fetch_add(1, std::memory_order_relaxed);
    LOG_DEBUG("Cache MISS: " << name << " Type: " << type);
    return std::nullopt;
}

size_t DNSCache::get_hits() const {
    return hits_.load(std::memory_order_relaxed);
}

size_t DNSCache::get_misses() const {
    return misses_.load(std::memory_order_relaxed);
}

size_t DNSCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_map_.size();
}

void DNSCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_map_.clear();
    cache_list_.clear();
    hits_.store(0, std::memory_order_relaxed);
    misses_.store(0, std::memory_order_relaxed);
}

} // namespace dns
