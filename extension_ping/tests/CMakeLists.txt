function(osqueryExtensionPingTests)
	generateOsqueryExtensionTests()  
endfunction()

function(generateOsqueryExtensionTests)
    add_osquery_executable(osquery_extension_ping_tests main.cpp)

    target_link_libraries(osquery_extension_ping_tests PRIVATE
            osquery_cxx_settings
            osquery_core
            osquery_extensions
            osquery_extensions_implthrift
            osquery_registry
            tests_helper
            thirdparty_googletest
            thirdparty_boost
			osquery_extension_ping_helper_lib			
	)
endfunction()

osqueryExtensionPingTests()