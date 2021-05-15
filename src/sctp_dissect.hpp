#pragma once
#include "binary.hpp"
#include "sctp_packet.h"
#include "sctp_reassemble.hpp"
#include "types.h"

#include <cstddef>
#include <iostream>
#include <span>
#include <variant>
#include <vector>


namespace SCTP {
class Dissector
{
public:
    struct Error
    {
        uint64_t pktnum;
        size_t offset;
        enum
        {
            ShortETH,
            ShortIP,
            NoIPv4,
            FragmentedIP,
            ShortSCTPHeader,
            ShortSCTPChunk,
            TooManySCTPChunks,
        } code;
    };

    struct NoSctp
    {
        uint64_t pktnum;
    };

private:
    size_t parser_offset_ = 0;
    std::span<std::byte const> bytes_;
    Reassembler reassembler_;

    auto has_bytes(size_t n) const { return binary::has_bytes(n, bytes_); }

    void consume(size_t n) { parser_offset_ += binary::consume(bytes_, n); }

    template <class T>
    auto from_bytes() const
    {
        return binary::from_bytes<T>(bytes_);
    }

    template <class T>
    auto from_bytes(size_t offset) const
    {
        return binary::from_bytes<T>(bytes_.subspan(offset, sizeof(T)));
    }

    Error failed(uint64_t pktnum, decltype(Error::code) code) const
    {
        return {pktnum, parser_offset_, code};
    }
    struct reassembly_result_visitor
    {
        bool operator()(Reassembler::Completed const &c) const
        {
            std::clog << "\t#" << c.pkt_nums.back()
                      << ": REASSEMBLED: " << c.bytes.size() << " BYTES (";
            std::copy(std::begin(c.pkt_nums),
                      std::end(c.pkt_nums),
                      std::ostream_iterator<uint64_t>(std::clog, " "));
            std::clog << ")\n";
            return true;
        }
        bool operator()(Reassembler::InProgress const &) const { return false; }
        bool operator()(Reassembler::Error const &err) const
        {
            std::cerr << "\t#" << err.pktnum << ": REASSEMBLY: ERROR "
                      << err.code << std::endl;
            return false;
        }
    };

public:
    explicit Dissector(size_t max_reassembly_sessions)
      : reassembler_(max_reassembly_sessions)
    {}

    template <size_t MAX_CHUNKS>
    std::variant<Packet<MAX_CHUNKS>, NoSctp, Error> parse(
      uint64_t pktnum,
      types::timestamp ts,
      std::span<std::byte const> bytes)
    {
        uint8_t constexpr SCTP_PROTOCOL          = 0x84;
        uint8_t constexpr SCTP_DATA_CHUNK_TYPE   = 0x00;
        uint8_t constexpr SCTP_FIXED_HEADER_SIZE = 16;

        parser_offset_ = 0;
        bytes_         = bytes;

        // ETHERNET LAYER
        if (!has_bytes(12))
            return failed(pktnum, Error::ShortETH);

        consume(12);

        Packet<MAX_CHUNKS> pktdesc{.ts = ts, .pktnum = pktnum};
        /* VLAN[s]? as per https://en.wikipedia.org/wiki/IEEE_802.1Q */
        // if outer (ISP) vlan is present, just skip it
        while (has_bytes(4))
        {
            const bool outer_vlan = from_bytes<uint16_t>() == 0x88A8;
            if (outer_vlan)
                consume(4);
            else
                break;
        }

        // If inner VLAN(s) are present, walk over them and remember the last
        // VLANID
        while (has_bytes(4))
        {
            const bool inner_vlan = from_bytes<uint16_t>() == 0x8100;

            if (inner_vlan)
            {
                pktdesc.vlan_id = from_bytes<uint16_t>(2) & 0xFFF;
                consume(4);
            }
            else
                break;
        }

        // Skip MPLS, if any
        if (has_bytes(6))
        {
            const bool mpls = from_bytes<uint16_t>() == 0x8847 ||
                              from_bytes<uint16_t>() == 0x8848;

            if (mpls)
            {
                bool stack_bottom = false;
                consume(2);
                do
                {
                    stack_bottom = std::to_integer<uint8_t>(bytes_[2]) & 0x1;
                    consume(4);
                } while (!stack_bottom && has_bytes(4));
            }
        }

        // Now we want IPv4!
        if (!has_bytes(3))
            return failed(pktnum, Error::ShortIP);

        if ((from_bytes<uint16_t>() != 0x0800) ||
            ((std::to_integer<uint8_t>(bytes_[2]) & 0xF0) != 0x40))
            return failed(pktnum, Error::NoIPv4);

        unsigned int const header_len =
          (std::to_integer<uint8_t>(bytes_[2]) & 0xF) * 4;
        consume(2);

        // IP LAYER
        if (!has_bytes(header_len))
            return failed(pktnum, Error::ShortIP);

        auto const total_len = from_bytes<uint16_t>(2);
        bytes_               = bytes_.first(total_len);

        bool const more_fragments = std::to_integer<uint8_t>(bytes_[6]) & 0x20;
        auto const frag_offset    = from_bytes<uint16_t>(6) & 0x1FFF;

        // IP fragmentation not supported
        if (more_fragments || frag_offset != 0)
            return failed(pktnum, Error::FragmentedIP);

        const auto protocol = std::to_integer<uint8_t>(bytes_[9]);

        if (protocol != SCTP_PROTOCOL)
            return NoSctp{pktnum};


        pktdesc.src_ip  = from_bytes<uint32_t>(12);
        pktdesc.dest_ip = from_bytes<uint32_t>(16);
        consume(header_len);

        // SCTP LAYER
        // Fixed Header
        if (!has_bytes(12))
            return failed(pktnum, Error::ShortSCTPHeader);

        pktdesc.src_port         = from_bytes<uint16_t>();
        pktdesc.dest_port        = from_bytes<uint16_t>(2);
        pktdesc.verification_tag = from_bytes<uint32_t>(4);

        consume(12);

        // SCTP Chunks
        while (has_bytes(4))
        {
            auto const chunk_type  = std::to_integer<uint8_t>(bytes_[0]);
            auto const chunk_flags = std::to_integer<uint8_t>(bytes_[1]);
            auto const chunk_len   = from_bytes<uint16_t>(2);

            if (!has_bytes(chunk_len))
                return failed(pktnum, Error::ShortSCTPChunk);

            if (chunk_type != SCTP_DATA_CHUNK_TYPE)
            {
                consume(chunk_len);
                continue;
            }

            DataChunk dc{
              .tsn             = from_bytes<uint32_t>(4),
              .sid             = from_bytes<uint16_t>(8),
              .ssn             = from_bytes<uint16_t>(10),
              .payload_protoid = from_bytes<uint32_t>(12),
            };

            const bool unordered_delivery =
              static_cast<bool>(chunk_flags & 0x4);
            const bool first_segment = static_cast<bool>(chunk_flags & 0x2);
            const bool last_segment  = static_cast<bool>(chunk_flags & 0x1);

            consume(SCTP_FIXED_HEADER_SIZE);

            if (first_segment && last_segment)
            {
                if (pktdesc.num_chunks == MAX_CHUNKS)
                    return failed(pktnum, Error::TooManySCTPChunks);

                dc.bytes                             = bytes_;
                pktdesc.chunks[pktdesc.num_chunks++] = std::move(dc);
            }
            else
            {
                auto const res =
                  reassembler_.addFragment(pktdesc.verification_tag,
                                           dc.tsn,
                                           {{.pktnum        = pktnum,
                                             .ts            = ts,
                                             .sid           = dc.sid,
                                             .ssn           = dc.ssn,
                                             .first_segment = first_segment,
                                             .last_segment  = last_segment},
                                            bytes_});

                if (std::visit(reassembly_result_visitor{}, res))
                {
                    if (pktdesc.num_chunks == MAX_CHUNKS)
                        return failed(pktnum, Error::TooManySCTPChunks);

                    dc.bytes = std::get<Reassembler::Completed>(res).bytes;
                    pktdesc.chunks[pktdesc.num_chunks++] = std::move(dc);
                }
            }

            auto const padded_payload_len =
              binary::padded<uint16_t>(chunk_len - SCTP_FIXED_HEADER_SIZE, 4);
            consume(padded_payload_len);
        }
        return pktdesc;
    }
};

} // namespace SCTP
