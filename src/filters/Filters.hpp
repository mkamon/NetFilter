#pragma once

#include <algorithm>
#include <utility>
#include <array>
#include "Common.hpp"
#include "FinalRule.hpp"

namespace filters
{

    template <size_t S, size_t level> struct hashEngine
    {
        [[nodiscard]] static unsigned compute(const Packet &packet, uint8_t mask) noexcept;
        [[nodiscard]] static unsigned compute(const Packet &packet) noexcept;
        [[nodiscard]] static unsigned compute(const Rule &rule, uint8_t shift) noexcept;
        [[nodiscard]] static unsigned compute(const Rule &rule) noexcept;
    };
    template <size_t S> struct hashEngine<S,4>
    {
        [[nodiscard]] static unsigned compute(const Packet &packet, uint8_t shift) noexcept { return (packet.src >> shift) % S;}
        [[nodiscard]] static unsigned compute(const Rule &rule, uint8_t shift) noexcept { return (rule.src.value().addr >> shift) % S;}
    };
    template <size_t S> struct hashEngine<S,3>
    {
        [[nodiscard]] static unsigned compute(const Packet &packet, uint8_t shift) noexcept {return (packet.dst >> shift) % S;}
        [[nodiscard]] static unsigned compute(const Rule &rule, uint8_t shift) noexcept { return (rule.dst.value().addr >> shift) % S;}
    };
    template <size_t S> struct hashEngine<S,2>
    {
        [[nodiscard]] static unsigned compute(const Packet &packet) noexcept {return packet.l4_proto % S;}
        [[nodiscard]] static unsigned compute(const Rule &rule) noexcept { return rule.l4_proto.value() % S;}
    };
    template <size_t S> struct hashEngine<S,1>
    {
        [[nodiscard]] static unsigned compute(const Packet &packet) noexcept {return packet.sport % S;}
        [[nodiscard]] static unsigned compute(const Rule &rule) noexcept { return rule.sport.value() % S;}
    };
    template <size_t S> struct hashEngine<S,0>
    {
        [[nodiscard]] static unsigned compute(const Packet &packet) noexcept {return packet.dport % S;}
        [[nodiscard]] static unsigned compute(const Rule &rule) noexcept { return rule.dport.value() % S;}
    };

    template <size_t level> struct RuleParser
    {
        [[nodiscard]] static bool hasValue(const Rule &rule) noexcept;
    };
    template <> struct RuleParser<4>
    {
        [[nodiscard]] static bool hasValue(const Rule &rule) noexcept { return rule.src.has_value(); }
    };
    template <> struct RuleParser<3>
    {
        [[nodiscard]] static bool hasValue(const Rule &rule) noexcept { return rule.dst.has_value(); }
    };
    template <> struct RuleParser<2>
    {
        [[nodiscard]] static bool hasValue(const Rule &rule) noexcept { return rule.l4_proto.has_value(); }
    };
    template <> struct RuleParser<1>
    {
        [[nodiscard]] static bool hasValue(const Rule &rule) noexcept { return rule.sport.has_value(); }
    };
    template <> struct RuleParser<0>
    {
        [[nodiscard]] static bool hasValue(const Rule &rule) noexcept { return rule.dport.has_value(); }
    };

    class Rules
    {
        std::vector<filters::FinalRule> rules;
    public:
        void add(const Rule &rule){
            rules.emplace_back(filters::FinalRule(rule));
        }
        [[nodiscard]] bool check(const Packet &packet) const{
            return std::any_of(rules.begin(), rules.end(), [&](const filters::FinalRule& rule){
                return rule.check(packet) ;
            });
        }
    };

    template< size_t arrSize, size_t level>
    class Filter
    {
        using Node = std::array<std::optional<Filter<arrSize, level-1>>, arrSize>;
        uint8_t addressBitShift = 0;
        Filter<arrSize, level-1> anyValue;
        Node concreteValue;

    public:
        explicit Filter(uint8_t mask) : addressBitShift{mask}, anyValue(mask){}
        void add(const Rule &rule){
            if(RuleParser<level>::hasValue(rule)){
                auto idx = computeHash(rule);
                auto &filter = concreteValue[idx];
                if(not filter.has_value()){
                    filter.emplace(addressBitShift);
                }
                filter.value().add(rule);
            }
            else {
                anyValue.add(rule);
            }
        }

        [[nodiscard]] bool check(const Packet &packet) const {
            if(anyValue.check(packet)){
                return true;
            }
            auto idx = computeHash(packet);
            if(const auto &filter = concreteValue[idx]; filter.has_value()){
                return filter.value().check(packet);
            }
            return false;
        }
    private:
        static constexpr auto lowestSubnetFilter = 3;
        [[nodiscard]] unsigned computeHash(const Packet &packet) const
        {
            if constexpr (level < lowestSubnetFilter){
                return hashEngine<arrSize, level>::compute(packet);
            }
            else {
                return hashEngine<arrSize, level>::compute(packet, addressBitShift);
            }
        }
        [[nodiscard]] unsigned computeHash(const Rule &rule) const
        {
            if constexpr (level < 3){
                return hashEngine<arrSize, level>::compute(rule);
            }
            else {
                return hashEngine<arrSize, level>::compute(rule, addressBitShift);
            }
        }
    };

    template<size_t arrSize>
    class Filter<arrSize, 0>
    {
        using Leaf = std::array<Rules, arrSize>;
        Leaf concreteValue;
        Rules anyValue;

    public:
        explicit Filter([[maybe_unused]] uint8_t){}
        void add(const Rule &rule){
            if(rule.dport.has_value()){
                auto idx = hashEngine<arrSize, 0>::compute(rule);
                auto &rules = concreteValue[idx];
                rules.add(rule);
            }
            else{
                anyValue.add(rule);
            }
        }

        [[nodiscard]] bool check(const Packet &packet) const {
            if(anyValue.check(packet)){
                return true;
            }
            auto idx = hashEngine<arrSize, 0>::compute(packet);
            return concreteValue[idx].check(packet);
        }
    };
}
