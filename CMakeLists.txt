cmake_minimum_required(VERSION 3.18)
project(oxide CXX)
set(CMAKE_CXX_STANDARD 17)

add_library(arm64-v8a SHARED src/main.cpp)
target_include_directories(arm64-v8a PRIVATE include/)
target_link_libraries(arm64-v8a android log dl EGL GLESv2)
set_target_properties(arm64-v8a PROPERTIES PREFIX "" SUFFIX ".so")
