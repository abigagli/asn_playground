cmake_minimum_required(VERSION 3.17)
project(ASNPLAYGROUND LANGUAGES C CXX VERSION 1.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")
find_package(PCAP REQUIRED)

set (APP_NAME asnplayground)
#include(GNUInstallDirs)
#include(FetchContent)

add_subdirectory(asn)

add_executable (${APP_NAME})
target_compile_features (${APP_NAME} PRIVATE cxx_std_20)

set_target_properties(${APP_NAME}
PROPERTIES
    DEBUG_POSTFIX "D")

target_sources(${APP_NAME}
PRIVATE
    src/main.cpp
    ${CMAKE_SOURCE_DIR}/compile_commands.json #<-- Having this as a dependency will cause the custom command below to execute...
)

#[[
target_include_directories(${APP_NAME}
PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/3rdParty/loguru/loguru-src)

target_compile_options(${APP_NAME}
PRIVATE
    -DLOGURU_WITH_STREAMS=1
    -DLOGURU_WITH_FILEABS=1)
#]]

target_link_libraries(${APP_NAME}
PRIVATE
    ASN::codec
    pcap::pcap
)

target_compile_definitions(${APP_NAME}
PRIVATE
    ${ASNCONSUMER_COMPILE_FLAGS}
)

target_compile_options (${APP_NAME}
PRIVATE
    #$<$<CONFIG:Debug>:-fno-omit-frame-pointer -fsanitize=address -fsanitize=signed-integer-overflow -fsanitize=unsigned-integer-overflow>
    $<$<CONFIG:Debug>:-fno-omit-frame-pointer -fsanitize=address -fsanitize=signed-integer-overflow>
)

target_link_options (${APP_NAME}
PRIVATE
    #$<$<CONFIG:Debug>:-fsanitize=address -fsanitize=signed-integer-overflow -fsanitize=unsigned-integer-overflow>
    $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=signed-integer-overflow>
)

# Since this custom command's OUTPUT is a dependency of our executable target
# the custom command itself will be executed at build time to produce such OUTPUT 
add_custom_command (
    OUTPUT
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMAND
        ln -sf ${CMAKE_BINARY_DIR}/compile_commands.json ${CMAKE_SOURCE_DIR}
    DEPENDS
        ${CMAKE_BINARY_DIR}/compile_commands.json
    COMMENT
        "Symlinking compile_commands.json"
    VERBATIM
    )
