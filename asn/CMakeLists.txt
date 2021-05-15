include(ExternalProject)

set(ASNCONSUMER_COMPILE_FLAGS
    ASN_DISABLE_BER_SUPPORT
    ASN_DISABLE_XER_SUPPORT
    ASN_DISABLE_OER_SUPPORT
    ASN_DISABLE_UPER_SUPPORT
    ASN_DISABLE_RFILL_SUPPORT
    ASN_PDU_COLLECTION
    PARENT_SCOPE)

ExternalProject_Add(
    ASN1C_PRJ
    GIT_REPOSITORY 	https://github.com/abigagli/asn1c.git #https://github.com/mouse07410/asn1c.git
    GIT_TAG origin/vlm_master
    #GIT_TAG a6376b401be9f41bd6e7cddea2d60a0aeea00a6a
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
    INSTALL_DIR INSTALL
    #Need to keep UPDATE_COMMAND disabled to prevent configure/build to always run, see https://gitlab.kitware.com/cmake/cmake/-/issues/16419
    UPDATE_COMMAND ""
    #CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env "$<$<CONFIG:Debug>:CFLAGS=-g3 -O0>" <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> --enable-static --disable-tests --without-documentation ${CROSS_COMPILING_SUPPORT}
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
    EXCLUDE_FROM_ALL ON
    BUILD_ALWAYS OFF
    BUILD_BYPRODUCTS <INSTALL_DIR>/bin/asn1c
    )

ExternalProject_Add_Step(
    ASN1C_PRJ
    GenerateConfigure
    WORKING_DIRECTORY <SOURCE_DIR>
    COMMAND autoreconf -iv
    COMMENT "Running asn1c autoreconf"
    DEPENDEES download
    DEPENDERS configure
    BYPRODUCTS configure
    LOG ON
    )

ExternalProject_Get_Property(ASN1C_PRJ INSTALL_DIR)

set (ASN1C_ARTIFACTS_FOLDER ARTIFACTS)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${ASN1C_ARTIFACTS_FOLDER})

add_custom_command(
    WORKING_DIRECTORY 
        ${ASN1C_ARTIFACTS_FOLDER}
    OUTPUT
        ${ASN1C_ARTIFACTS_FOLDER}/converter-example.mk
        #${CMAKE_CURRENT_BINARY_DIR}/asn1c.stamp
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/module.asn
    COMMAND
        ${INSTALL_DIR}/bin/asn1c
        -pdu=all
        -fcompound-names
        -fline-refs
        -no-gen-BER
        -no-gen-XER
        -no-gen-OER
        -no-gen-UPER
        -no-gen-random-fill
        -fno-include-deps
        -findirect-choice
        -flink-skeletons
        ${CMAKE_CURRENT_SOURCE_DIR}/module.asn
#    COMMAND
#        cmake -E touch ${CMAKE_CURRENT_BINARY_DIR}/asn1c.stamp
    COMMENT
        "Compiling ASN1 definition"
    VERBATIM
)

add_custom_target(
    build_asncodec_static
    WORKING_DIRECTORY 
        ${ASN1C_ARTIFACTS_FOLDER}
    COMMAND
        ${CMAKE_COMMAND} -E env "CFLAGS=$<$<CONFIG:Debug>:-g3 -O0>" make -f converter-example.mk libasncodec.a
    BYPRODUCTS
        ${ASN1C_ARTIFACTS_FOLDER}/libasncodec.a
    COMMENT
        "Building custom target 'build_asncodec_static'"
    DEPENDS
        ASN1C_PRJ
        ${ASN1C_ARTIFACTS_FOLDER}/converter-example.mk
    VERBATIM
)

add_library (asncodec_imported STATIC IMPORTED)
set_target_properties(asncodec_imported PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${ASN1C_ARTIFACTS_FOLDER}/libasncodec.a)

add_library(asncodec_static INTERFACE)
add_dependencies(asncodec_static build_asncodec_static)
target_include_directories(asncodec_static SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/${ASN1C_ARTIFACTS_FOLDER})
target_link_libraries(asncodec_static INTERFACE asncodec_imported)
add_library(ASN::codec ALIAS asncodec_static)
