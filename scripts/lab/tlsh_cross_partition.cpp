#include <array>
#include <cstddef>
#include <cstdio>
#include <iostream>
#include <limits>
#include <memory>
#include <numeric>
#include <string>
#include <vector>

#include "tlsh.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int digest_input() {
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
        return 1;
    }
#endif
    constexpr std::size_t byte_limit = 50 * 1024 * 1024;
    std::array<char, 65536> buffer;
    std::size_t total = 0;
    Tlsh hash;
    while (std::cin.read(buffer.data(), buffer.size()) || std::cin.gcount() > 0) {
        const auto count = static_cast<std::size_t>(std::cin.gcount());
        if (count > byte_limit - total) {
            std::cerr << "TLSH input exceeds byte limit\n";
            return 1;
        }
        hash.update(reinterpret_cast<const unsigned char *>(buffer.data()), static_cast<unsigned int>(count));
        total += count;
    }
    if (!std::cin.eof() || std::cin.bad()) {
        return 1;
    }
    hash.final();
    const char *digest = hash.getHash();
    std::cout << (*digest ? digest : "TNULL") << '\n';
    return 0;
}

std::size_t representative(std::vector<std::size_t>& parents, std::size_t index) {
    while (parents[index] != index) {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    return index;
}

int fingerprint_components() {
    std::size_t count = 0;
    if (!(std::cin >> count) || count == 0 || count > 50000) {
        return 1;
    }
    std::vector<Tlsh> entries(count);
    for (auto& entry : entries) {
        std::string digest;
        if (!(std::cin >> digest) || entry.fromTlshStr(digest.c_str()) != 0) {
            return 1;
        }
    }
    std::vector<std::size_t> parents(count);
    std::iota(parents.begin(), parents.end(), 0);
    for (std::size_t i = 1; i < count; ++i) {
        auto root = representative(parents, i);
        for (std::size_t j = 0; j < i; ++j) {
            const auto other = representative(parents, j);
            if (other != root && entries[i].totalDiff(&entries[j]) <= 30) {
                parents[root] = other;
                root = other;
            }
        }
    }
    for (std::size_t i = 0; i < count; ++i) {
        std::cout << representative(parents, i) << '\n';
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && std::string(argv[1]) == "--digest") {
        return digest_input();
    }
    if (argc == 2 && std::string(argv[1]) == "--components") {
        return fingerprint_components();
    }
    if (argc != 1) {
        return 1;
    }
    std::size_t reference_count = 0;
    std::size_t query_count = 0;
    if (!(std::cin >> reference_count >> query_count) ||
        reference_count == 0 || reference_count > 50000 ||
        query_count == 0 || query_count > 50000) {
        std::cerr << "Invalid TLSH input counts\n";
        return 1;
    }

    std::vector<std::unique_ptr<Tlsh>> reference;
    reference.reserve(reference_count);
    for (std::size_t i = 0; i < reference_count; ++i) {
        std::string digest;
        auto entry = std::make_unique<Tlsh>();
        if (!(std::cin >> digest) || entry->fromTlshStr(digest.c_str()) != 0) {
            std::cerr << "Invalid reference TLSH\n";
            return 1;
        }
        reference.push_back(std::move(entry));
    }

    for (std::size_t i = 0; i < query_count; ++i) {
        std::string digest;
        Tlsh query;
        if (!(std::cin >> digest) || query.fromTlshStr(digest.c_str()) != 0) {
            std::cerr << "Invalid query TLSH\n";
            return 1;
        }
        int nearest = std::numeric_limits<int>::max();
        for (const auto &entry : reference) {
            int distance = query.totalDiff(entry.get());
            if (distance < nearest) {
                nearest = distance;
                if (nearest == 0) {
                    break;
                }
            }
        }
        std::cout << nearest << '\n';
    }
    return 0;
}
