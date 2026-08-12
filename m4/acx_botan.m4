AC_DEFUN([ACX_BOTAN],[
	WITH_BOTAN=
	AC_ARG_WITH(botan,
		AS_HELP_STRING([--with-botan=PATH],[Specify prefix of path of Botan]),
		[
			BOTAN_PATH="$withval"
			WITH_BOTAN=1
		],
		[
			BOTAN_PATH="/usr/local"
		])

	if test -n "${PKG_CONFIG}" && test -z "${WITH_BOTAN}"; then
		PKG_CHECK_MODULES([BOTAN], [botan-3], [
			BOTAN_VERSION_MAJOR=3
			BOTAN_VERSION_MINOR=0
		],[
			PKG_CHECK_MODULES([BOTAN], [botan-2 >= $1.$2.$3], [
				BOTAN_VERSION_MAJOR=2
				BOTAN_VERSION_MINOR=0
			],[
				AC_MSG_ERROR([Cannot find Botan])
			])
		])
	else
		if test -f "$BOTAN_PATH/include/botan-3/botan/version.h"; then
			BOTAN_VERSION_MAJOR=3
			BOTAN_VERSION_MINOR=0
		elif test -f "$BOTAN_PATH/include/botan-2/botan/version.h"; then
			BOTAN_VERSION_MAJOR=2
			BOTAN_VERSION_MINOR=0
		else
			AC_MSG_ERROR([Cannot find Botan includes])
		fi

		BOTAN_CFLAGS="-I$BOTAN_PATH/include/botan-${BOTAN_VERSION_MAJOR}"
		BOTAN_LIBS="-L$BOTAN_PATH/lib -lbotan-${BOTAN_VERSION_MAJOR}"

		AC_SUBST(BOTAN_CFLAGS)
		AC_SUBST(BOTAN_LIBS)
	fi

	AC_MSG_CHECKING(what are the Botan includes)
	AC_MSG_RESULT($BOTAN_CFLAGS)

	AC_MSG_CHECKING(what are the Botan libs)
	AC_MSG_RESULT($BOTAN_LIBS)

	dnl Botan 3 public headers use C++20 constructs (concepts, std::span), so
	dnl anything including them must also be built as C++20.
	if test "x${BOTAN_VERSION_MAJOR}" = "x3"; then
		CXX=`echo "$CXX" | sed -e 's/ -std=c++11//g'`
		CXXFLAGS=`echo "$CXXFLAGS" | sed -e 's/ -std=c++11//g'`

		dnl The feature probe trips over its own warnings under -Werror
		acx_botan_saved_CXXFLAGS="$CXXFLAGS"
		CXXFLAGS=""
		for acx_botan_flag in $acx_botan_saved_CXXFLAGS; do
			case $acx_botan_flag in
				-Werror) ;;
				*) CXXFLAGS="$CXXFLAGS $acx_botan_flag" ;;
			esac
		done

		AX_CXX_COMPILE_STDCXX([20],[noext],[mandatory])

		CXXFLAGS="$acx_botan_saved_CXXFLAGS"
	else
		AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])
	fi

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $BOTAN_CFLAGS"
	LIBS="$LIBS $BOTAN_LIBS"

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[#include <botan/version.h>],
			[#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR($1,$2,$3)
			#error "Botan version too old";
			#endif])],
		[AC_MSG_RESULT([checking for Botan >= v$1.$2.$3 ... yes])],
		[AC_MSG_RESULT([checking for Botan >= v$1.$2.$3 ... no])
		 AC_MSG_ERROR([Missing the correct version of the Botan library])]
	)
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BOTAN_VERSION_MAJOR)
	AC_SUBST(BOTAN_VERSION_MINOR)
])
