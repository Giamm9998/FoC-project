# See
# https://medium.com/heuristics/c-application-development-part-3-cmakelists-txt-from-scratch-7678253e5e24
# for an example CMake
cmake_minimum_required(VERSION 3.0)

# Name of the project
project(project)

#
# Files
#

include_directories(./includes ./src)

#
# Target
#
add_executable(binary ./src/main.cpp)
