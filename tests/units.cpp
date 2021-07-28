#include "gtest/gtest.h"
#include "Common.hpp"
#include "NetFilter.hpp"
#include "testSet_basicFunctionalities.hpp"

#include "QuickFilter.hpp"
TEST(net_filter, rule1_tests)
{
    using namespace testData::testSet1;
    QuickFilter filter2({rule1});
    NetFilter filter({rule2, rule3, rule4, rule1 });

    ASSERT_TRUE(filter.process(rule1Pass));
    ASSERT_FALSE(filter.process(rule1Fail_1));
    ASSERT_FALSE(filter.process(rule1Fail_2));
    ASSERT_FALSE(filter.process(rule1Fail_3));
}

TEST(net_filter, rule2_tests)
{
    using namespace testData::testSet1;
    NetFilter filter({rule2 });

    ASSERT_TRUE(filter.process(rule2Pass_1));
    ASSERT_TRUE(filter.process(rule2Pass_2));
    ASSERT_FALSE(filter.process(rule2Fail_1));
    ASSERT_FALSE(filter.process(rule2Fail_2));
    ASSERT_FALSE(filter.process(rule2Fail_3));
}

TEST(quick_filter, rule1_tests)
{
    using namespace testData::testSet1;
//    QuickFilter filter2({rule1});
    QuickFilter filter({rule2, rule3, rule4, rule1 });

    ASSERT_TRUE(filter.process(rule1Pass));
    ASSERT_FALSE(filter.process(rule1Fail_1));
    ASSERT_FALSE(filter.process(rule1Fail_2));
    ASSERT_FALSE(filter.process(rule1Fail_3));
}

TEST(quick_filter, rule2_tests)
{
    using namespace testData::testSet1;
    QuickFilter filter({rule2 });

    ASSERT_TRUE(filter.process(rule2Pass_1));
    ASSERT_TRUE(filter.process(rule2Pass_2));
    ASSERT_FALSE(filter.process(rule2Fail_1));
    ASSERT_FALSE(filter.process(rule2Fail_2));
    ASSERT_FALSE(filter.process(rule2Fail_3));
}



TEST(final_rule, valid_subnet_tests)
{
    using namespace filters;
    using namespace testData::testSet1;
    using namespace testData::subnet;
    FinalRule::Net net = {net1::net.addr, bitsToMask(net1::net.bits)};

    for(auto addr : net1::addresses ){
        ASSERT_TRUE(net.isNetworkOf(addr));
    }
}

TEST(final_rule, invalid_subnet_tests)
{
    using namespace filters;
    using namespace testData::testSet1;
    using namespace testData::subnet;
    FinalRule::Net net = {net3::net.addr, bitsToMask(net3::net.bits)};

    for(auto addr : net4::addresses ){
        ASSERT_FALSE(net.isNetworkOf(addr));
    }
}

TEST(rule_cache, deny_all_test)
{
    using namespace filters;
    using namespace testData::testSet1;
    RuleCache<4, filters::SimpleHashEngine> cache;

    ASSERT_FALSE(cache.check(rule1Pass));
    ASSERT_FALSE(cache.check(rule1Fail_1));
    ASSERT_FALSE(cache.check(rule2Pass_1));
}

TEST(rule_cache, put_test)
{
    using namespace filters;
    using namespace testData::testSet1;
    FinalRule testRule(rule1);
    RuleCache<4, filters::SimpleHashEngine> cache;

    ASSERT_FALSE(cache.check(rule1Pass));
    cache.put(rule1Pass, &testRule);
    ASSERT_TRUE(cache.check(rule1Pass));
    ASSERT_FALSE(cache.check(rule1Fail_1));
}

TEST(packet_cache, no_packet_cached_test)
{
    using namespace filters;
    using namespace testData::testSet1;
    PacketCache<4, filters::SimpleHashEngine> cache;

    ASSERT_FALSE(cache.check(rule1Pass));
    ASSERT_FALSE(cache.check(rule1Fail_1));
    ASSERT_FALSE(cache.check(rule2Pass_1));
}

TEST(packet_cache, packet_cached_test)
{
    using namespace filters;
    using namespace testData::testSet1;
    PacketCache<4, filters::SimpleHashEngine> cache;

    ASSERT_FALSE(cache.check(rule1Pass));
    cache.put(rule1Pass);
    ASSERT_TRUE(cache.check(rule1Pass));
    ASSERT_FALSE(cache.check(rule1Fail_1));
}










