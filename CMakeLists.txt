project (lssocket) 

file(GLOB lssocket_sources ./src/**.c)
set(lssocket ${lssocket_sources})

add_library(lssocket ${lssocket})
target_compile_definitions(lssocket PUBLIC LSS_HAS_BUNDLED_ROOT_CERTIFICATES)
target_link_libraries(lssocket)