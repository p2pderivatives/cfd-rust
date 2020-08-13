cmake_minimum_required(VERSION 3.13)

set(PACKAGE_VERSION   1.0.0)

####################
# options
####################
include(cmake/CfdCommonOption.cmake)
include(cmake/ConvertSrclistFunction.cmake)
include(cmake/CfdWallyOption.cmake)
include(cmake/CfdCommonSetting.cmake)

option(ENABLE_CAPI  "enable c-api (ON or OFF. default:ON)" ON)
option(IGNORE_DUMMY_EXE  "ignore dummy exe (ON or OFF. default:ON)" ON)

####################
# dummy build
####################
project(cfdrust_external CXX)
set(DUMMY_LIB_NAME  win_dummy)
include(cmake/Cpp11Setting.cmake)

if(WIN32 AND (NOT ${IGNORE_DUMMY_EXE}))
add_executable(${DUMMY_LIB_NAME} win_dummy.cpp)
target_compile_options(${DUMMY_LIB_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
    >
)
#add_dependencies(${DUMMY_LIB_NAME} copy_cfd_library)
endif()

####################
# copy library
####################
message(STATUS "[CMAKE_ASM_FLAGS] ${CMAKE_ASM_FLAGS}")
message(STATUS "[CMAKE_ASM_FLAGS_DEBUG] ${CMAKE_ASM_FLAGS_DEBUG}")

find_package(univalue QUIET CONFIG)
find_package(wally    QUIET CONFIG)
find_package(cfdcore  QUIET CONFIG)
find_package(cfd  CONFIG)
if((NOT cfd_FOUND) OR (NOT ${cfd_FOUND}))
set(USE_INSTALLED_LIBRARY FALSE)
add_custom_target(
    copy_cfd_library
    COMMAND echo "not copy library."
    WORKING_DIRECTORY ${CFD_ROOT_BINARY_DIR}
)
else()
set(INSTALLED_LIBRARY_DIR  ${cfd_DIR}/../lib)

if(WIN32)
set(LIB_PREFIX "")
set(LIB_SUFFIX ".dll")
set(LIB_SUFFIX_STATIC ".lib")
else()
if(APPLE)
set(LIB_PREFIX "lib")
set(LIB_SUFFIX ".dylib")
set(LIB_SUFFIX_STATIC ".a")
else()
set(LIB_PREFIX "lib")
set(LIB_SUFFIX ".so")
set(LIB_SUFFIX_STATIC ".a")
endif()
endif()

set(CFD_STATIC   ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}cfd${LIB_SUFFIX_STATIC})
set(CFD_DYNAMIC  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}cfd${LIB_SUFFIX})

add_custom_target(
    copy_cfd_library0
    ${CMAKE_COMMAND} -E make_directory ${CFD_OBJ_BINARY_DIR}
    WORKING_DIRECTORY ${CFD_ROOT_BINARY_DIR}
)

# check static or dynamic
if(EXISTS ${CFD_DYNAMIC})
set(EXIST_CFD_LIBRARY  TRUE)
set(LIBWALLY_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}wally${LIB_SUFFIX})
set(UNIVALUE_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}univalue${LIB_SUFFIX})
set(CFDCORE_LIB_PATH   ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}cfdcore${LIB_SUFFIX})

set(LIBWALLY_LIB_PATH_STATIC  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}wally${LIB_SUFFIX_STATIC})
set(UNIVALUE_LIB_PATH_STATIC  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}univalue${LIB_SUFFIX_STATIC})
set(CFDCORE_LIB_PATH_STATIC   ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}cfdcore${LIB_SUFFIX_STATIC})

add_custom_command(
    TARGET ${DUMMY_LIB_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy  ${LIBWALLY_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${UNIVALUE_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CFDCORE_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CFD_DYNAMIC} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${LIBWALLY_LIB_PATH_STATIC} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${UNIVALUE_LIB_PATH_STATIC} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CFDCORE_LIB_PATH_STATIC} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CFD_STATIC} ${CFD_OBJ_BINARY_DIR}
)

else()
if(EXISTS ${CFD_STATIC})
set(EXIST_CFD_LIBRARY  TRUE)
set(LIBWALLY_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}wally${LIB_SUFFIX_STATIC})
set(UNIVALUE_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}univalue${LIB_SUFFIX_STATIC})
set(CFDCORE_LIB_PATH   ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}cfdcore${LIB_SUFFIX_STATIC})

add_custom_command(
    TARGET ${DUMMY_LIB_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy  ${LIBWALLY_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${UNIVALUE_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CFDCORE_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CFD_STATIC} ${CFD_OBJ_BINARY_DIR}
)

else()
set(EXIST_CFD_LIBRARY  FALSE)
message(STATUS "[check library file] cfd is empty. path:${CFD_DYNAMIC}")
endif()
endif()

if(${EXIST_CFD_LIBRARY})
message(STATUS "[CMAKE_C_FLAGS] ${CMAKE_C_FLAGS}")
message(STATUS "[CMAKE_C_FLAGS_DEBUG] ${CMAKE_C_FLAGS_DEBUG}")
set(USE_INSTALLED_LIBRARY TRUE)

else(${EXIST_CFD_LIBRARY})
add_custom_target(
    copy_cfd_library
    COMMAND echo "not copy library."
    WORKING_DIRECTORY ${CFD_ROOT_BINARY_DIR}
)
set(USE_INSTALLED_LIBRARY FALSE)
endif(${EXIST_CFD_LIBRARY})
endif()

####################
# subdirectories
####################
if((NOT CFD_SINGLE_BUILD) AND (NOT ${USE_INSTALLED_LIBRARY}))
add_subdirectory(external)
endif()

####################
# install
####################
if(WIN32 AND (NOT ${IGNORE_DUMMY_EXE}))
include(GNUInstallDirs)
set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON) 

install(TARGETS       ${DUMMY_LIB_NAME}
        EXPORT        ${DUMMY_LIB_NAME}-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        OBJECTS       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(EXPORT ${DUMMY_LIB_NAME}-export
        FILE ${DUMMY_LIB_NAME}-config.cmake
        DESTINATION "cmake/"
        EXPORT_LINK_INTERFACE_LIBRARIES)
endif()
