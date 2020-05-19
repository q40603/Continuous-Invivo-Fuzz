cmake_minimum_required(VERSION 3.1)

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})

add_library(BSAPass MODULE
    BSA_pass.cpp
)

target_link_libraries(BSAPass
    ${Boost_LIBRARIES}
    ${PROTOBUF_LIBRARY}
)

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(BSAPass PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
# set_target_properties(TfPass PROPERTIES
#     COMPILE_FLAGS -fno-rtti
# )

# Get proper shared-library behavior (where symbols are not necessarily
# resolved when the shared library is linked) on OS X.
if(APPLE)
    set_target_properties(KlPass PROPERTIES
        LINK_FLAGS -undefined dynamic_lookup
    )
endif(APPLE)

