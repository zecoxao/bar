cmake_minimum_required(VERSION 3.19)
project(bar LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Threads REQUIRED)

# PS4 backups can exceed 2 GB across split parts: 64-bit file offsets.
add_compile_definitions(_FILE_OFFSET_BITS=64)

# AES-NI intrinsics need -maes/-msse4.1 on GCC/Clang x86. The software AES
# fallback is used at runtime when the CPU lacks AES-NI; on ARM the intrinsics
# are compiled out entirely (see bar_crypto.h), so add the flags only on x86.
set(BAR_X86_AES "")
if(NOT MSVC)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _proc)
  if(_proc MATCHES "x86_64|amd64|i[3-6]86|x86")
    set(BAR_X86_AES -maes -msse4.1)
  endif()
endif()

# ---------------------------------------------------------------------------
# CLIs
# ---------------------------------------------------------------------------
add_executable(p4br_extract p4br_extract.c)
add_executable(p4br_create  p4br_create.c)
foreach(t p4br_extract p4br_create)
  target_link_libraries(${t} PRIVATE Threads::Threads)
  if(BAR_X86_AES)
    target_compile_options(${t} PRIVATE ${BAR_X86_AES})
  endif()
endforeach()

# ---------------------------------------------------------------------------
# Qt GUI  (p4br-qt) : two tabs (Extract / Create) over the same portable cores
# ---------------------------------------------------------------------------
find_package(Qt6 COMPONENTS Widgets QUIET)
if(Qt6_FOUND)
  qt_standard_project_setup()
  set(GUI_SOURCES
    qt/main.cpp
    qt/mainwindow.cpp
    qt/mainwindow.h
    qt/worker.h
    qt/bar_bridge.h
    qt/extract_bridge.c
    qt/create_bridge.c
  )
  if(WIN32)
    qt_add_executable(p4br-qt WIN32 ${GUI_SOURCES})
  elseif(APPLE)
    qt_add_executable(p4br-qt MACOSX_BUNDLE ${GUI_SOURCES})
    set_target_properties(p4br-qt PROPERTIES
      MACOSX_BUNDLE_BUNDLE_NAME "p4br"
      MACOSX_BUNDLE_GUI_IDENTIFIER "com.zecoxao.p4br"
      MACOSX_BUNDLE_BUNDLE_VERSION "1.0.0"
      MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.0")
  else()
    qt_add_executable(p4br-qt ${GUI_SOURCES})
  endif()
  target_include_directories(p4br-qt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} qt)
  target_link_libraries(p4br-qt PRIVATE Qt6::Widgets Threads::Threads)
  if(BAR_X86_AES)
    # applies to the C bridge TUs that pull in the AES-NI intrinsics
    target_compile_options(p4br-qt PRIVATE $<$<COMPILE_LANGUAGE:C>:${BAR_X86_AES}>)
  endif()
else()
  message(STATUS "Qt6 not found - building CLIs only (set CMAKE_PREFIX_PATH to your Qt).")
endif()

install(TARGETS p4br_extract p4br_create RUNTIME DESTINATION bin)
if(Qt6_FOUND)
  install(TARGETS p4br-qt BUNDLE DESTINATION . RUNTIME DESTINATION bin)
endif()
