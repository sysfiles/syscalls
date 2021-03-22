#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <iterator>
#include <unordered_map>
#include <random>
#include <VersionHelpers.h>
#include <mutex>

// comment out if you don't want to randomize the bytes used in the page. allowing encryption
// removes your chances of being signature scanned if you're using this in an unethical environment.
#define USE_ENCRYPTION