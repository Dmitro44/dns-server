#include "cache.hpp"
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

using namespace dns;

void test_put_get() {
    DNSCache cache(10);
    std::vector<DNSPacket::ResourceRecord> records = {
        {"example.com", 1, 1, 60, {1, 2, 3, 4}}};
    cache.put("example.com", 1, records, 60);

    auto result = cache.get("example.com", 1);
    assert(result.has_value());
    assert(result->size() == 1);
    assert(result->at(0).name == "example.com");
    assert(cache.get_hits() == 1);
    assert(cache.get_misses() == 0);

    auto miss_result = cache.get("notfound.com", 1);
    assert(!miss_result.has_value());
    assert(cache.get_misses() == 1);

    std::cout << "test_put_get passed\n";
}

void test_lru_eviction() {
    DNSCache cache(3); // Max size 3

    for (int i = 0; i < 5; ++i) {
        std::vector<DNSPacket::ResourceRecord> records = {
            {"example" + std::to_string(i) + ".com", 1, 1, 60, {1, 2, 3, 4}}};
        cache.put("example" + std::to_string(i) + ".com", 1, records, 60);
    }

    assert(cache.size() == 3);

    // Items 0 and 1 should be evicted
    assert(!cache.get("example0.com", 1).has_value());
    assert(!cache.get("example1.com", 1).has_value());

    // Items 2, 3, 4 should still be there
    assert(cache.get("example2.com", 1).has_value());
    assert(cache.get("example3.com", 1).has_value());
    assert(cache.get("example4.com", 1).has_value());

    // Now example2.com should be most recently used. Let's add one more.
    std::vector<DNSPacket::ResourceRecord> records = {
        {"example5.com", 1, 1, 60, {1, 2, 3, 4}}};
    cache.put("example5.com", 1, records, 60);

    // example2.com was least recently used (queried first out of 2, 3, 4), so
    // it should be evicted
    assert(!cache.get("example2.com", 1).has_value());
    assert(cache.get("example3.com", 1).has_value());
    assert(cache.get("example4.com", 1).has_value());
    assert(cache.get("example5.com", 1).has_value());

    std::cout << "test_lru_eviction passed\n";
}

void test_ttl_expiration() {
    DNSCache cache(10);
    std::vector<DNSPacket::ResourceRecord> records = {
        {"example.com", 1, 1, 1, {1, 2, 3, 4}} // TTL = 1 second
    };
    cache.put("example.com", 1, records, 1);

    auto result = cache.get("example.com", 1);
    assert(result.has_value());

    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));

    auto result_expired = cache.get("example.com", 1);
    assert(!result_expired.has_value());

    std::cout << "test_ttl_expiration passed\n";
}

void test_concurrency() {
    DNSCache cache(100);
    std::vector<std::thread> threads;

    auto writer = [&cache]() {
        for (int i = 0; i < 1000; ++i) {
            std::vector<DNSPacket::ResourceRecord> records = {
                {"example" + std::to_string(i % 50) + ".com",
                 1,
                 1,
                 60,
                 {1, 2, 3, 4}}};
            cache.put("example" + std::to_string(i % 50) + ".com", 1, records,
                      60);
        }
    };

    auto reader = [&cache]() {
        for (int i = 0; i < 1000; ++i) {
            cache.get("example" + std::to_string(i % 50) + ".com", 1);
        }
    };

    for (int i = 0; i < 5; ++i) {
        threads.emplace_back(writer);
        threads.emplace_back(reader);
    }

    for (auto &t : threads) {
        t.join();
    }

    assert(cache.size() <= 100);
    std::cout << "test_concurrency passed\n";
}

int main() {
    test_put_get();
    test_lru_eviction();
    test_ttl_expiration();
    test_concurrency();

    std::cout << "All cache tests passed!\n";
    return 0;
}
