#pragma once

#include "Common.hpp"
#include "filters/Filters.hpp"

class QuickFilter
{
    static constexpr auto hashArraySize = 8;
    static constexpr auto filterLevels = 4;
    filters::Filter<hashArraySize, filterLevels> hashFilter;

public:
    explicit QuickFilter(const std::vector<Rule> &rules)
        : hashFilter(largestNetworkBits(rules))
    {
        for(const auto &rule: rules){
            hashFilter.add(rule);
        }
    }

    [[nodiscard]] bool process(const Packet& packet) const
    {
        return hashFilter.check(packet);
    }

private:
    [[nodiscard]] static uint8_t largestNetworkBits(const std::vector<Rule> &rules)
    {
        auto min = filters::constants::ipv4BitCount;
        for(const auto &rule : rules){
            if(rule.src.has_value()){
                min = std::min(min, rule.src.value().bits);
            }
            if(rule.dst.has_value()){
                min = std::min(min, rule.dst.value().bits);
            }
        }
        return filters::constants::ipv4BitCount - min;
    }

};
