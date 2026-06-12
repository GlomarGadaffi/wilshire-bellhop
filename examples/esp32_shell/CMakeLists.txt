cmake_minimum_required(VERSION 3.16)
# Find the littlessh component (this repo) when building the example in-tree.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../littlessh")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_shell)
