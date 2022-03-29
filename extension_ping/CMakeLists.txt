function(osqueryExtensionPing)
	if(OSQUERY_BUILD_TESTS)
		add_subdirectory("tests")
	endif()

    generateOsqueryExtensionPingHelperLib()
	
	generateOsqueryExtensionPing()
endfunction()

function(generateOsqueryExtensionPingHelperLib)
    add_osquery_library(osquery_extension_ping_helper_lib EXCLUDE_FROM_ALL
		icmp_packet.cpp  
		icmp_packet.h
		icmp_ping_executor.cpp
		icmp_ping_executor.h
		ipv4_packet.cpp
		ipv4_packet.h 
		utils.cpp
		utils.h 		
	)

	#set(public_header_files
	#	icmp_ping_executor.h
	#	icmp_packet.h
	#	ipv4_packet.h 
	#	utils.h
	#)
	
	#generateIncludeNamespace(osquery_utils_status "osquery/extensions/ping" "FILE_ONLY" ${public_header_files})	
  
    target_link_libraries(osquery_extension_ping_helper_lib PUBLIC
		osquery_cxx_settings
		osquery_extensions
		osquery_extensions_implthrift
	)
	
  add_test(NAME osquery_extension_ping_tests COMMAND osquery_extension_ping_tests)	
endfunction()

function(generateOsqueryExtensionPing)
	addOsqueryExtension(osquery_extension_ping EXCLUDE_FROM_ALL
		main.cpp 
	)

    target_link_libraries(osquery_extension_ping PUBLIC
		osquery_cxx_settings
		osquery_extensions
		osquery_extensions_implthrift
		osquery_extension_ping_helper_lib		
	)	
endfunction()

osqueryExtensionPing()
