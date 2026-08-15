# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    ApiTest.cpp
    BasicTest.cpp
    DatagramTest.cpp
    DataTest.cpp
    DrillDescriptor.cpp
    EventTest.cpp
    HandshakeTest.cpp
    MtuTest.cpp
    OwnershipTest.cpp
    PathTest.cpp
    QuicDrill.cpp
    TestConnection.cpp
    TestListener.cpp
    TestStream.cpp
    TestHelpers.h
    TestUtility.h
)

add_library(testlib STATIC ${SOURCES})

# Compile the self-registering gtest cases into each testlib consumer. Keeping
# these as interface sources prevents the linker from discarding their static
# registration object as an otherwise-unreferenced member of testlib.a.
target_sources(testlib INTERFACE IceDatapathTest.cpp)

target_include_directories(testlib PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

target_link_libraries(testlib PRIVATE inc warnings)

set_property(TARGET testlib PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")
