# - Find botan
# Find the botan cryptographic library
#
# This module defines the following variables:
#   BOTAN_FOUND  -  True if library and include directory are found
# If set to TRUE, the following are also defined:
#   BOTAN_INCLUDE_DIRS  -  The directory where to find the header file
#   BOTAN_LIBRARIES  -  Where to find the library file
#
# For conveniance, these variables are also set. They have the same values
# than the variables above.  The user can thus choose his/her prefered way
# to write them.
#   BOTAN_LIBRARY
#   BOTAN_INCLUDE_DIR
#
# This file is in the public domain

find_package(Botan CONFIG)

if(NOT BOTAN_FOUND)
  pkg_check_modules(botan BOTAN_FOUND)
endif()


if(NOT BOTAN_FOUND)
  find_path(BOTAN_INCLUDE_DIRS NAMES botan/version.h
      PATH_SUFFIXES botan-3 botan-2
      DOC "The botan include directory")

  find_library(BOTAN_LIBRARIES NAMES botan-3 botan-2 botan
      DOC "The botan library")

  # Use some standard module to handle the QUIETLY and REQUIRED arguments, and
  # set BOTAN_FOUND to TRUE if these two variables are set.
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(BOTAN REQUIRED_VARS BOTAN_LIBRARIES BOTAN_INCLUDE_DIRS)

  if(BOTAN_FOUND)
    set(BOTAN_LIBRARY ${BOTAN_LIBRARIES} CACHE INTERNAL "")
    set(BOTAN_INCLUDE_DIR ${BOTAN_INCLUDE_DIRS} CACHE INTERNAL "")
    set(BOTAN_FOUND ${BOTAN_FOUND} CACHE INTERNAL "")
  endif()
endif()

if(BOTAN_FOUND AND NOT BOTAN_VERSION_MAJOR)
  find_file(BOTAN_BUILD_H botan/build.h PATHS ${BOTAN_INCLUDE_DIRS} NO_DEFAULT_PATH)
  if(BOTAN_BUILD_H)
    file(STRINGS ${BOTAN_BUILD_H} _botan_major_line
         REGEX "^#define[ \t]+BOTAN_VERSION_MAJOR[ \t]+[0-9]+")
    string(REGEX REPLACE ".*BOTAN_VERSION_MAJOR[ \t]+([0-9]+).*" "\\1"
           BOTAN_VERSION_MAJOR "${_botan_major_line}")
  endif()
endif()

mark_as_advanced(BOTAN_INCLUDE_DIRS BOTAN_LIBRARIES BOTAN_BUILD_H)
