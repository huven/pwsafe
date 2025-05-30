include(CheckLibraryExists)

set (CORE_SRCS
 
  CheckVersion.cpp
  Command.cpp
  CoreAlias.cpp
  CoreImpExp.cpp
  CoreOtherDB.cpp
  ExpiredList.cpp
  ItemAtt.cpp
  Item.cpp
  ItemData.cpp
  ItemField.cpp
  Match.cpp
  PolicyManager.cpp
  PWCharPool.cpp
  PWHistory.cpp
  PWPolicy.cpp
  PWSAuxParse.cpp
  PWScore.cpp
  PWSdirs.cpp
  PWSfile.cpp
  PWSfileHeader.cpp
  PWSfileV1V2.cpp
  PWSfileV3.cpp
  PWSfileV4.cpp
  PWSFilters.cpp
  PWSLog.cpp
  PWSprefs.cpp
  PWSrand.cpp
  PWStime.cpp
  Report.cpp
  RUEList.cpp
  StringX.cpp
  SysInfo.cpp
  TotpCore.cpp
  UnknownField.cpp
  UTF8Conv.cpp
  Util.cpp
  Validate.cpp
  VerifyFormat.cpp
  XMLprefs.cpp
  crypto/AES.cpp
  crypto/BlowFish.cpp
  crypto/KeyWrap.cpp
  crypto/pbkdf2.cpp
  crypto/sha1.cpp
  crypto/sha256.cpp
  crypto/TwoFish.cpp
  crypto/external/Chromium/base32.cpp
  XML/XMLFileHandlers.cpp
  XML/XMLFileValidation.cpp
  pugixml/pugixml.cpp
  )

if (XML_MSXML)
  list (APPEND CORE_SRCS
    XML/MSXML/MFileSAX2Handlers.cpp
    XML/MSXML/MFileValidator.cpp
    XML/MSXML/MFileXMLProcessor.cpp
    XML/MSXML/MFilterSAX2Handlers.cpp
    XML/MSXML/MFilterXMLProcessor.cpp
  )
endif (XML_MSXML)

if (XML_XERCESC)
  list (APPEND CORE_SRCS
    XML/Xerces/XFileSAX2Handlers.cpp
    XML/Xerces/XFileValidator.cpp
    XML/Xerces/XFileXMLProcessor.cpp
    XML/Xerces/XFilterSAX2Handlers.cpp
    XML/Xerces/XFilterXMLProcessor.cpp
    XML/Xerces/XSecMemMgr.cpp
   )
endif (XML_XERCESC)

if (NOT XML_MSXML AND NOT XML_XERCESC)
  list (APPEND CORE_SRCS
    XML/Pugi/PFileXMLProcessor.cpp
    XML/Pugi/PFilterXMLProcessor.cpp
  )
endif (NOT XML_MSXML AND NOT XML_XERCESC)

if (NOT WIN32 OR WX_WINDOWS)
  list (APPEND CORE_SRCS ${CMAKE_CURRENT_BINARY_DIR}/core_st.cpp)
  if (WIN32)
    set (PERL_EXECUTABLE "Perl_executable_undefined" CACHE FILEPATH
    "Path to perl.exe, from activestate.com or Cygwin") 
    set (MV "move")
    string (REPLACE "/" "\\" FROM "${PROJECT_SOURCE_DIR}/src/core/core_st")
    string (REPLACE "/" "\\" TO "${CMAKE_CURRENT_BINARY_DIR}/core_st")
  else (WIN32)
    set (PERL_EXECUTABLE "perl")
    set (MV "mv")
    set (FROM "${PROJECT_SOURCE_DIR}/src/core/core_st")
    set (TO "${CMAKE_CURRENT_BINARY_DIR}/core_st")
  endif (WIN32)
  set (RC2CPP "${PROJECT_SOURCE_DIR}/Misc/rc2cpp.pl")

  add_custom_command (
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/core_st.cpp ${CMAKE_CURRENT_BINARY_DIR}/core_st.h
    COMMAND "${PERL_EXECUTABLE}" "${RC2CPP}" "${PROJECT_SOURCE_DIR}/src/core/core.rc2"
    COMMAND "${MV}" "${FROM}.cpp" "${TO}.cpp"
    COMMAND "${MV}" "${FROM}.h" "${TO}.h"
    DEPENDS core.rc2
    )
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
else (NOT WIN32 OR WX_WINDOWS)
  list (APPEND CORE_SRCS core.rc2)
endif(NOT WIN32 OR WX_WINDOWS)

add_library(core STATIC ${CORE_SRCS})
target_link_libraries(core PRIVATE harden_interface)
