#pragma once

#include "testData.hpp"
#include "Common.hpp"

namespace testData
{
    namespace testSet1
    {
        Rule rule1{subnet::net1::net, subnet::net2::net, {l4_protocols[0]}, ports[0], ports[1] };
        Rule rule2{subnet::net1::net, subnet::net3::net, l4_protocols[0], ports[0], std::nullopt};
        Rule rule3{subnet::net1::net, subnet::net4::net, l4_protocols[0], std::nullopt, ports[0]};
        Rule rule4{subnet::net1::net, subnet::net5::net, std::nullopt, ports[0], ports[0]};
        Rule rule5{std::nullopt, subnet::net6::net, l4_protocols[0], ports[0], ports[0]};
        Rule rule6{subnet::net6::net, std::nullopt, l4_protocols[0], ports[0], ports[0]};

        Packet rule1Pass{subnet::net1::addresses[0], subnet::net2::addresses[0], l4_protocols[0], ports[0], ports[1]};
        Packet rule1Fail_1{subnet::net1::addresses[0], subnet::net2::addresses[0], l4_protocols[1], ports[0], ports[1]};
        Packet rule1Fail_2{subnet::net1::addresses[0], subnet::net2::addresses[0], l4_protocols[0], ports[1], ports[1]};
        Packet rule1Fail_3{subnet::net1::addresses[0], subnet::net2::addresses[0], l4_protocols[0], ports[0], ports[0]};

        Packet rule2Pass_1{subnet::net1::addresses[0], subnet::net3::addresses[0], l4_protocols[0], ports[0], ports[5]};
        Packet rule2Pass_2{subnet::net1::addresses[0], subnet::net3::addresses[0], l4_protocols[0], ports[0], ports[10]};
        Packet rule2Fail_1{subnet::net2::addresses[0], subnet::net3::addresses[0], l4_protocols[0], ports[0], ports[10]};
        Packet rule2Fail_2{subnet::net1::addresses[0], subnet::net3::addresses[0], l4_protocols[2], ports[0], ports[10]};
        Packet rule2Fail_3{subnet::net1::addresses[0], subnet::net3::addresses[0], l4_protocols[0], ports[3], ports[10]};

    }
}


