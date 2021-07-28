#pragma once

#include <algorithm>

#include "Common.hpp"
#include "FinalRule.hpp"
#include <utility>
#include <array>


namespace filters {

    template<size_t digSize>
    class SimpleHashEngine {
    public:
        static unsigned compute(const Packet &packet) noexcept {
            return (packet.dst + packet.dport) % digSize;
        }
    };

    struct PacketMeta {
        uint32_t src;
        uint32_t dst;
        uint8_t l4_proto;
        uint16_t sport;
        uint16_t dport;

        PacketMeta &operator=(const Packet &right) {
            src = right.src;
            dst = right.dst;
            l4_proto = right.l4_proto;
            sport = right.sport;
            dport = right.dport;
            return *this;
        }

        [[nodiscard]] bool friend operator==(const PacketMeta &left, const Packet &right) {
            return left.src == right.src && left.dst == right.dst && left.l4_proto == right.l4_proto &&
                   left.sport == right.sport && left.dport == right.dport;
        }
    };

    template<size_t cacheSize, template<size_t> typename Hash>
    class RuleCache {
        const filters::FinalRule DenyAll = {};
        std::array<const filters::FinalRule *, cacheSize> cache;
    public:
        RuleCache() {
            cache.fill(&DenyAll);
        }

        [[nodiscard]] bool check(const Packet &packet) const noexcept {
            return cache[Hash<cacheSize>::compute(packet)]->check(packet);
        }

        void put(const Packet &packet, const filters::FinalRule *rule) {
            cache[Hash<cacheSize>::compute(packet)] = rule;
        }
    };

    template<size_t cacheSize, template<size_t> typename Hash>
    class PacketCache {
        const PacketMeta invalid = {0, 0, 0, 0, 0};
        std::array<PacketMeta, cacheSize> cache;
    public:
        PacketCache() {
            cache.fill(invalid);
        }

        [[nodiscard]] bool check(const Packet &packet) const noexcept {
            return cache[Hash<cacheSize>::compute(packet)] == packet;
        }

        void put(const Packet &packet) {
            cache[Hash<cacheSize>::compute(packet)] = packet;
        }
    };

    template<size_t cacheSize, template<size_t> typename Hash>
    class MemoryFilterWithCache {
        static constexpr auto algorithmMemorySize = std::numeric_limits<uint16_t>::max();
        using RuleWithCounter = std::pair<const filters::FinalRule *, int>;
        std::vector<RuleWithCounter> rules;

        unsigned cacheMissCounter = 0;
        RuleCache<cacheSize, Hash> ruleCache;

        void consolidate()
        {
            for(auto &[_, ruleCounter] : rules){
                ruleCounter /= 2;
            }
            std::sort(rules.begin(), rules.end(), [](RuleWithCounter a, RuleWithCounter b){
                return a.second > b.second;
            });
        }

    public:
        void initialize(const std::vector<filters::FinalRule> &_rules)
        {
            rules.reserve(_rules.size());
            for(const auto &rule : _rules){
                rules.emplace_back(std::make_pair(&rule, 0));
            }
        }

        [[nodiscard]] bool process(const Packet &packet)
        {
            if(ruleCache.check(packet)){
                return true;
            }

            if(cacheMissCounter == algorithmMemorySize){
                cacheMissCounter = 0;
                consolidate();
            }

            for(auto &[rule, ruleUseCounter] : rules) {
                if(rule->check(packet)){
                    ruleUseCounter++;
                    cacheMissCounter++;
                    ruleCache.put(packet, rule);
                    return true;
                }
            }
            return false;
        }
    };
}
