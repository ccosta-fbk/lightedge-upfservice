
add_custom_target(click-lvnfs2-clean
  COMMAND autoconf
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/configure --prefix=${CLICK_PREFIX}
  COMMAND make distclean
  COMMENT "Cleaning lvnfs2 Click package build files")  

add_custom_target(click-lvnfs2-build
  ALL
  COMMAND autoconf
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/configure --prefix=${CLICK_PREFIX}
  COMMAND make distclean
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/configure --prefix=${CLICK_PREFIX}
  COMMAND make
  COMMENT "Building lvnfs2 Click package")

add_custom_target(click-lvnfs2-install
  COMMAND make install
  COMMENT "Installing lvnfs2 Click package (Click installed in ${CLICK_PREFIX})")

add_dependencies(click-lvnfs2-build ${UPFROUTER_LIBS})

set_target_properties(click-lvnfs2-install PROPERTIES EXCLUDE_FROM_ALL 1)

  

  
