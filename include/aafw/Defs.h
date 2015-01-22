#ifndef AAFW_DEFS_
#define AAFW_DEFS_

#ifdef _WIN32
#  ifdef aafw_EXPORTS
#    define AAFW_API __declspec(dllexport)
#  else
#    define AAFW_API __declspec(dllimport)
#  endif
#else
#  define AAFW_API
#endif

#endif