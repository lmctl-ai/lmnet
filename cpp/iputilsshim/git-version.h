/* Stand-in for the iputils git-version.h that meson would generate from
 * git-version.h.meson. Values match the vendored release (iputils.lock). */
#pragma once
#define PACKAGE_NAME "iputils"
#define PACKAGE_VERSION "20250605"
#define IPUTILS_VERSION(_prog) "%s from %s %s\n", _prog, PACKAGE_NAME, PACKAGE_VERSION
