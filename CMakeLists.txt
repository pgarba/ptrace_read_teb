cmake_minimum_required(VERSION 3.10)
project(ptrace_read_teb LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_executable(ptrace_read_teb
    src/ptrace_read_teb.cpp
)

target_include_directories(ptrace_read_teb PRIVATE include)
target_link_libraries(ptrace_read_teb PRIVATE pthread)