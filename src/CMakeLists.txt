add_library( filter
		simple.cpp
)

add_executable( main main.cpp )
target_link_libraries(main filter)
