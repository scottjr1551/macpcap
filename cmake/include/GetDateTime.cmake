include(cmake/include/datetime.cmake)

function(getdatetime)
    DATE(DR)
    string(STRIP ${DR} DR)
    TIME(TR)
    string(STRIP ${TR} TR)
    set(dt "${DR}-${TR}" PARENT_SCOPE)
endfunction()