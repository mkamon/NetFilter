enable_testing()
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
include_directories(${PROJECT_INCLUDE_DIR})

add_executable( unitTests ./units.cpp )
target_link_libraries( unitTests gtest gtest_main ${GTEST_LIBRARIES} pthread)
add_test( unitTests unitTests )
