include_directories(${LIBSCAP_INCLUDE_DIR} ${LIBSCAP_DIR}/driver)

set(DNS_PLUGIN_SOURCES
	main.cpp
)

add_library(dns SHARED "${DNS_PLUGIN_SOURCES}")
