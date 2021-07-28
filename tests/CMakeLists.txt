enable_testing()
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
include_directories( ${PROJECT_INCLUDE_DIR} )

add_executable( unitTests ./units.cpp )
target_link_libraries( unitTests filter gtest gtest_main ${GTEST_LIBRARIES} pthread)
add_test( unitTests unitTests )

add_executable( performanceTests ./performance.cpp )
target_link_libraries( performanceTests filter gtest gtest_main ${GTEST_LIBRARIES} pthread)
add_test( performanceTests performanceTests )
