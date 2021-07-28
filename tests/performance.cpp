#include <gtest/gtest.h>
#include "simple.hpp"

TEST(Dummy, dummy){
    Filter filter({});
    Packet packet;
	ASSERT_TRUE(filter.process(packet));
}
