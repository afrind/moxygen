moxygen_add_test(TARGET PicoWebTransportBaseTests
  SOURCES PicoWebTransportBaseTest.cpp
  DEPENDS
    openmoq_pico_base
    testmain
)
target_include_directories(PicoWebTransportBaseTests PRIVATE
  ${proxygen_SOURCE_DIR}/proxygen/lib/http/webtransport/test)
