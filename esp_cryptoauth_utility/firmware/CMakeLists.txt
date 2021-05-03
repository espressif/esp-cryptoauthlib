# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)
set(EXTRA_COMPONENT_DIRS "../../")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# firmware generated for esp_cryptoauth_utility
project(ecu_firmware)
