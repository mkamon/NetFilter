#pragma once

#include <limits>
#include "Common.hpp"

namespace filters
{
    namespace constants
    {
        constexpr uint8_t ipv4BitCount = 32;
    }

    enum class Check : uint8_t
    {
        SourceAddress      = 1,
        DestinationAddress = 2,
        Protocol           = 4,
        SourcePort         = 8,
        DestinationPort    = 16
    };

    [[nodiscard]] inline bool operator& (uint8_t lhs, Check rhs) noexcept {
        return lhs & static_cast<uint8_t>(rhs);
    }

    [[nodiscard]] constexpr uint32_t bitsToMask(uint8_t bits) noexcept {
        uint8_t shiftBy = constants::ipv4BitCount - bits;
        return ((std::numeric_limits<uint32_t>::max() >> shiftBy ) << shiftBy );
    }

    class FinalRule
    {
    public:
        struct Net{
            uint32_t addr = 0;
            uint32_t mask = 0;

            [[nodiscard]] bool isNetworkOf(uint32_t address) const noexcept {
                return addr == (address & mask);
            }
        };

        FinalRule() = default;

        explicit FinalRule(const Rule &rule)
        {
            if(rule.src.has_value()){
                addCheck(Check::SourceAddress);
                const auto &value = rule.src.value();
                src = {value.addr, bitsToMask(value.bits)};
            }
            if(rule.dst.has_value()){
                addCheck(Check::DestinationAddress);
                const auto &value = rule.dst.value();
                dst = {value.addr, bitsToMask(value.bits)};
            }
            if(rule.l4_proto.has_value()){
                addCheck(Check::Protocol);
                l4_proto = rule.l4_proto.value();
            }
            if(rule.dport.has_value()){
                addCheck(Check::DestinationPort);
                dport = rule.dport.value();
            }
            if(rule.sport.has_value()){
                addCheck(Check::SourcePort);
                sport = rule.sport.value();
            }
        }

        void addCheck(Check check) noexcept {
            activeChecks += static_cast<uint8_t>(check);
        }

        [[nodiscard]] bool check(const Packet &packet) const noexcept {
            if( not activeChecks
                || ( (activeChecks & Check::SourceAddress) && !src.isNetworkOf(packet.src))
                || ( (activeChecks & Check::DestinationAddress) && !dst.isNetworkOf(packet.dst))
                || ( (activeChecks & Check::Protocol) && l4_proto != packet.l4_proto )
                || ( (activeChecks & Check::DestinationPort) && dport != packet.dport )
                || ( (activeChecks & Check::SourcePort) && sport != packet.sport ))
            {
                return false;
            }
            return true;
        }

    private:
        uint8_t activeChecks = 0;

        Net src;
        Net dst;
        uint8_t l4_proto = 0;
        uint16_t dport = 0;
        uint16_t sport = 0;
    };
}
