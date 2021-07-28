#pragma once

#include <vector>
#include <limits>
#include "Common.hpp"
#include "filters/FinalRule.hpp"
#include "filters/FilterAlgorithms.hpp"

class NetFilter
{
    static constexpr auto cacheSize = std::numeric_limits<uint8_t>::max();
    std::vector<filters::FinalRule> rules;

    mutable filters::PacketCache<cacheSize, filters::SimpleHashEngine> rejectedPacketCache;
    mutable filters::MemoryFilterWithCache<cacheSize, filters::SimpleHashEngine> algorithm;

public:
    explicit NetFilter(const std::vector<Rule> &_rules)
    {
        rules.reserve(_rules.size());
        for (const auto &rule : _rules){
            rules.emplace_back(filters::FinalRule(rule));
        }
        algorithm.initialize(rules);
    }
    [[nodiscard]] bool process(const Packet& packet) const
    {
        if(rejectedPacketCache.check(packet)){
            return false;
        }
        if(algorithm.process(packet)){
            return true;
        }
        rejectedPacketCache.put(packet);
        return false;
    }

};
