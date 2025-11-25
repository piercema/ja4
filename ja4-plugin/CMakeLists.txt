cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginJA4)

include(ZeekPlugin)

zeek_plugin_begin(JA4 JA4 ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/ja4.cc src/helpers.cc)
zeek_plugin_bif(src/ja4.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(scripts/__load__.zeek
                    scripts/JA4/JA4/__load__.zeek)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})

# Enable AddressSanitizer and LeakSanitizer in Debug builds
if (CMAKE_BUILD_TYPE MATCHES "Debug")
    message(STATUS "Enabling AddressSanitizer (ASan)")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

endif ()
