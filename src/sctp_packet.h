#pragma once
#include "types.h"

#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace SCTP {
using tag_t = uint32_t;
using tsn_t = uint32_t;

struct DataChunk
{
    tsn_t tsn;
    uint16_t sid;
    uint16_t ssn;
    uint32_t payload_protoid;
    std::variant<std::span<std::byte const>, // Not fragmented: non-owning,
                                             // content is in the pcap
                                             // buffer
                 std::vector<std::byte>>     // Reassembled: owning, content is
                                             // in a dedicated vector
      bytes;
};

template <size_t MAX_CHUNKS>
struct Packet
{
    types::timestamp ts;
    uint64_t pktnum;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    tag_t verification_tag;
    uint16_t vlan_id;
    std::array<DataChunk, MAX_CHUNKS> chunks;
    uint8_t num_chunks;
};

} // namespace SCTP