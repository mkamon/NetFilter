#pragma once

#include <optional>
#include <cstdint>

struct Packet
{
    uint32_t src;
    uint32_t dst;
    uint8_t l4_proto;
    uint16_t sport;
    uint16_t dport;

    uint8_t payload[1500];
};

struct Rule
{
    struct Net{
        uint32_t addr;
        uint8_t bits;
    };

    std::optional<Net> src;
    std::optional<Net> dst;
    std::optional<uint8_t> l4_proto;
    std::optional<uint16_t> sport;
    std::optional<uint16_t> dport;
};
