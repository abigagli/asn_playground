#pragma once
#include "sctp_dissect.hpp"
#include "types.h"

#include <map>
#include <tuple>
#include <vector>

namespace SCTP {

class Associations
{
    struct ip_port
    {
        uint32_t ip   = 0;
        uint16_t port = 0;
        bool operator<(ip_port const &rhs) const noexcept
        {
            return std::forward_as_tuple(ip, port) <
                   std::forward_as_tuple(rhs.ip, rhs.port);
        }
    };
    struct ip_port_ts
    {
        ip_port ipp;
        types::timestamp ts{types::timestamp::duration::zero()};
    };

    struct peer
    {
        uint32_t tag = 0;
        std::vector<ip_port_ts> endpoints;
    };
    class association
    {
        uint64_t id_;
        types::timestamp creation_ts_;
        std::pair<peer, peer> peers_;

    public:
        explicit association(uint64_t id, types::timestamp ts)
          : id_(id), creation_ts_(ts)
        {}

        uint64_t id() const { return id_; }
    };

    std::map<types::timestamp, association> associations_;
    std::map<tag_t, decltype(associations_)::iterator> by_tag_;
    std::map<ip_port, decltype(associations_)::iterator> by_ipp_;
};
} // namespace SCTP