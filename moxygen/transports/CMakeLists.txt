add_library(
  moqtransports STATIC
  PicoQuicExecutor.cpp
  PicoQuicWebTransport.cpp
)

# Filter out non-existent picoquic libraries (e.g., picotls-fusion which may not be built)
set(FILTERED_PICOQUIC_LIBRARIES "")
foreach(lib ${picoquic_LIBRARIES})
  if(EXISTS "${lib}")
    list(APPEND FILTERED_PICOQUIC_LIBRARIES "${lib}")
  else()
    message(STATUS "Skipping non-existent picoquic library: ${lib}")
  endif()
endforeach()

target_link_libraries(
  moqtransports
  PUBLIC
    proxygen::proxygen
    proxygen::quicwebtransport
    proxygen::wt_stream_manager
    Folly::folly
    ${FILTERED_PICOQUIC_LIBRARIES}
)

target_include_directories(
  moqtransports
  PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${picoquic_INCLUDE_DIR}
)

target_compile_options(
  moqtransports
  PRIVATE
    ${_MOXYGEN_COMMON_COMPILE_OPTIONS}
)
