#pragma once
#include <cstddef>

namespace config {
inline namespace compiletime {
    size_t constexpr SCTP_MAX_DATA_CHUNKS = 4;
}
inline namespace runtime {
    inline size_t sctp_reassembly_sessions = 2;
} // namespace runtime
} // namespace config
