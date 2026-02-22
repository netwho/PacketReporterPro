# CMakeLists.txt for PacketReporter Pro native plugin
# Wireshark epan plugin with Qt settings window and Cairo PDF output
# No external tool dependencies (rsvg-convert, pdfunite, etc.) required

include(WiresharkPlugin)

set_module_info(packetreporterpro 0 1 1 0)

# Qt support for the settings window
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── RPATH ────────────────────────────────────────────────────────
# Let the plugin find Qt/Cairo libs relative to its own location at
# runtime.  On Linux/macOS, Wireshark plugins live under
#   <prefix>/lib/wireshark/plugins/<ver>/epan/
# and Qt/Cairo libs sit under <prefix>/lib/.
# $ORIGIN (Linux) / @loader_path (macOS) resolves to the plugin dir.
if(NOT WIN32)
    set(CMAKE_INSTALL_RPATH
        "$ORIGIN"
        "$ORIGIN/.."
        "$ORIGIN/../.."
        "$ORIGIN/../../../.."
    )
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH_USE_LINK_RPATH TRUE)
endif()

# ── Qt6 ──────────────────────────────────────────────────────────
# Prefer the Qt that Wireshark's own build already resolved.  When
# building with BUILD_wireshark=OFF the variable USE_qt6 may not be
# set, so we hardcode the major version.
set(qtver "6")

# If the parent Wireshark CMake run already found Qt6, the imported
# targets (Qt6::Core etc.) are already available and find_package is
# a fast no-op.  Otherwise we fall through to the normal search.
if(NOT TARGET Qt6::Core)
    find_package(Qt${qtver} REQUIRED COMPONENTS Core Widgets Gui)
endif()

# ── Cairo for PDF rendering ───────────────────────────────────────
option(CAIRO_STATIC "Statically link Cairo and its deps for portable binaries" OFF)

if(WIN32)
    find_path(CAIRO_INCLUDE_DIR cairo/cairo.h
        HINTS
            ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include
            $ENV{VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}/include
    )
    find_library(CAIRO_LIB cairo
        HINTS
            ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib
            $ENV{VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}/lib
    )
    if(NOT CAIRO_INCLUDE_DIR OR NOT CAIRO_LIB)
        message(FATAL_ERROR "Cairo not found.  Install with: vcpkg install cairo:x64-windows")
    endif()
    set(CAIRO_INCLUDE_DIRS ${CAIRO_INCLUDE_DIR} ${CAIRO_INCLUDE_DIR}/cairo)
    set(CAIRO_LIBRARIES    ${CAIRO_LIB})
    set(CAIRO_LIBRARY_DIRS "")
    set(CAIRO_CFLAGS_OTHER "")
    message(STATUS "Cairo (Windows): ${CAIRO_LIB}")
elseif(CAIRO_STATIC AND APPLE)
    # Static linking on macOS: embed Cairo + deps so the plugin has
    # zero external library requirements beyond Wireshark + system.
    if(NOT CAIRO_STATIC_PREFIX)
        message(FATAL_ERROR "Set CAIRO_STATIC_PREFIX to the Homebrew prefix (e.g. /opt/homebrew)")
    endif()
    set(_P "${CAIRO_STATIC_PREFIX}/opt")
    set(CAIRO_INCLUDE_DIRS
        "${_P}/cairo/include/cairo"
        "${_P}/pixman/include/pixman-1"
        "${_P}/freetype/include/freetype2"
        "${_P}/fontconfig/include"
        "${_P}/libpng/include/libpng16"
    )
    set(CAIRO_LIBRARIES
        "${_P}/cairo/lib/libcairo.a"
        "${_P}/pixman/lib/libpixman-1.a"
        "${_P}/libpng/lib/libpng.a"
        "${_P}/freetype/lib/libfreetype.a"
        "${_P}/fontconfig/lib/libfontconfig.a"
        "${_P}/gettext/lib/libintl.a"
    )
    find_library(EXPAT_LIB expat)
    if(EXPAT_LIB)
        list(APPEND CAIRO_LIBRARIES ${EXPAT_LIB})
    endif()
    list(APPEND CAIRO_LIBRARIES
        "-framework CoreText"
        "-framework CoreGraphics"
        "-framework CoreFoundation"
        "-framework ImageIO"
        z bz2 iconv
    )
    set(CAIRO_LIBRARY_DIRS "")
    set(CAIRO_CFLAGS_OTHER "")
    message(STATUS "Cairo (static macOS): ${_P}/cairo/lib/libcairo.a")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CAIRO REQUIRED cairo cairo-pdf cairo-png)
endif()

set(PLUGIN_NAME packetreporterpro)

# C sources (analysis + rendering)
set(DISSECTOR_SRC
    reporter_plugin.c
    packet_collector.c
    wifi_collector.c
    report_renderer.c
    pdf_export.c
    config_reader.c
)

# C++ sources (Qt UI)
set(CXX_SRC
    pro_window.cpp
    ui_bridge.cpp
)

set(PLUGIN_FILES
    plugin.c
    ${DISSECTOR_SRC}
    ${CXX_SRC}
)

set(PLUGIN_HEADERS
    reporter_plugin.h
    packet_collector.h
    wifi_collector.h
    report_renderer.h
    pdf_export.h
    config_reader.h
    pro_window.h
    ui_bridge.h
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CAIRO_INCLUDE_DIRS}
)

link_directories(${CAIRO_LIBRARY_DIRS})

# Prevent Qt MOC from processing the auto-generated plugin.c
set_source_files_properties(
    plugin.c
    PROPERTIES
    SKIP_AUTOGEN ON
    LANGUAGE C
)

set_source_files_properties(
    ${PLUGIN_FILES}
    PROPERTIES
    COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

# Ensure C++ sources are compiled as C++
set_source_files_properties(
    ${CXX_SRC}
    PROPERTIES
    LANGUAGE CXX
)

# ABI compatibility: allow plugin to load with any Qt 6.x runtime
add_definitions(-DQT_NO_VERSION_TAGGING)

# Generate plugin.c registration entry point
register_plugin_files(plugin.c
    plugin
    ${DISSECTOR_SRC}
)

add_wireshark_plugin_library(${PLUGIN_NAME} epan)

target_link_libraries(${PLUGIN_NAME}
    epan
    wiretap
    ${CAIRO_LIBRARIES}
    Qt${qtver}::Core
    Qt${qtver}::Widgets
    Qt${qtver}::Gui
)

target_compile_options(${PLUGIN_NAME} PRIVATE ${CAIRO_CFLAGS_OTHER})

install_plugin(${PLUGIN_NAME} epan)
