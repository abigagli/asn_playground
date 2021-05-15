#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "S1AP-PDU.h"
#include "binary.hpp"
#include "config.hpp"
#include "pcap++.hpp"
#include "sctp_dissect.hpp"
#include "types.h"

#include <array>
#include <asn_application.h>
#include <asn_internal.h> /* for ASN__DEFAULT_STACK_MAX */
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <variant>

#define DEF(T) asn_DEF_##T

using namespace std::string_literals;

struct processing_context
{
    struct stats_t: types::CRTPDumpable<stats_t>
    {
        uint64_t packets          = 0;
        uint64_t asn1_decode_fail = 0;
        template <std::true_type = std::true_type{}>
        void dump(std::ostream &os) const
        {}
    } stats;

    SCTP::Dissector sctp_dissect{config::sctp_reassembly_sessions};
};

struct DissectResultVisitor
{
    size_t operator()(typename SCTP::Dissector::Error const &err) const
    {
        std::cerr << '#' << err.pktnum << ": DISSECT: ERROR " << +err.code
                  << std::endl;
        return 0;
    }
    size_t operator()(typename SCTP::Dissector::NoSctp const &ns) const
    {
        std::clog << '#' << ns.pktnum << ": DISSECT: NO SCTP \n";
        return 0;
    }
    template <size_t MAX_CHUNKS>
    size_t operator()(typename SCTP::Packet<MAX_CHUNKS> const &pkt) const
    {
        std::clog << '#' << pkt.pktnum << ": DISSECT: DATA CHUNKS "
                  << +pkt.num_chunks << std::endl;
        return pkt.num_chunks;
    }
};

void
process_s1ap_pdu(S1AP_PDU_t const *pdu)
{
    if (pdu->present == S1AP_PDU_PR_initiatingMessage)
    {
        auto const &im = pdu->choice.initiatingMessage;
        if (im->value.present == InitiatingMessage__value_PR_Paging)
        {
            assert(im->procedureCode == ProcedureCode_id_Paging);

            auto const &pg = im->value.choice.Paging;
            for (auto i = 0; i != pg.protocolIEs.list.count; ++i)
            {
                PagingIEs const *pie = reinterpret_cast<PagingIEs const *>(
                  pg.protocolIEs.list.array[i]);
                if (pie->value.present == PagingIEs__value_PR_UEPagingID)
                {
                    assert(pie->id == ProtocolIE_ID_id_UEPagingID);

                    auto const &uepi = pie->value.choice.UEPagingID;
                    if (uepi.present == UEPagingID_PR_s_TMSI)
                    {
                        auto const mEC      = uepi.choice.s_TMSI->mMEC;
                        auto const &t       = uepi.choice.s_TMSI->m_TMSI;
                        uint32_t const tmsi = binary::from_bytes<uint32_t>(
                          std::as_bytes(std::span{t.buf, t.size}));

                        std::cout << "Paging with TMSI: " << std::hex << tmsi
                                  << std::dec << '\n';
                    }
                    else if (uepi.present == UEPagingID_PR_iMSI)
                    {
                        auto const &i       = uepi.choice.iMSI;
                        uint64_t const imsi = binary::from_bytes<uint64_t>(
                          std::as_bytes(std::span{i.buf, i.size}));

                        std::cout << "Paging with IMSI: " << std::hex << imsi
                                  << std::dec << '\n';
                    }
                }
            }
        }
    }
}

void
packet_handler(uint8_t *ctx, pcap_pkthdr const *hdr, uint8_t const *data)
{
    static uint32_t constexpr S1AP_PROTOID = 0x12;
    struct get_bytes_view
    {
        std::span<std::uint8_t const> operator()(
          std::span<std::byte const> const &sp) const
        {
            return {reinterpret_cast<uint8_t const *>(sp.data()), sp.size()};
        }
        std::span<std::uint8_t const> operator()(
          std::vector<std::byte> const &v) const
        {
            return {reinterpret_cast<uint8_t const *>(v.data()), v.size()};
        }
    };

    auto *cxt = reinterpret_cast<processing_context *>(ctx);

    auto &pktnum = cxt->stats.packets;
    ++pktnum;

    auto const d = std::chrono::seconds(hdr->ts.tv_sec) +
                   std::chrono::microseconds(hdr->ts.tv_usec);
    auto const tp = types::timestamp{
      std::chrono::duration_cast<types::timestamp::duration>(d)};

    auto const parse_result =
      cxt->sctp_dissect.parse<config::SCTP_MAX_DATA_CHUNKS>(
        pktnum, tp, std::as_bytes(std::span{data, hdr->caplen}));

    if (auto const num_data_chunks =
          std::visit(DissectResultVisitor{}, parse_result))
    {
        auto const packet =
          std::get<SCTP::Packet<config::SCTP_MAX_DATA_CHUNKS>>(parse_result);
        for (auto c = 0ULL; c != num_data_chunks &&
                            packet.chunks[c].payload_protoid == S1AP_PROTOID;
             ++c)
        {
            auto const &bytes =
              std::visit(get_bytes_view{}, packet.chunks[c].bytes);

            S1AP_PDU_t pdu{};
            auto *p = &pdu;

            auto const decode_result = asn_decode(nullptr,
                                                  ATS_ALIGNED_BASIC_PER,
                                                  &DEF(S1AP_PDU),
                                                  reinterpret_cast<void **>(&p),
                                                  bytes.data(),
                                                  bytes.size());
            if (decode_result.code != RC_OK)
            {
                // throw std::runtime_error("#"s + std::to_string(pktnum) +
                //                          ": ASN decoding failed"s);
                std::cerr << '#' << pktnum
                          << ": ***** ASN decoding failed ***** ";
                ++cxt->stats.asn1_decode_fail;
            }
            else
            {
                process_s1ap_pdu(p);
            }

            std::cout << '#' << pktnum << ": Decoded size "
                      << decode_result.consumed << '\n';

            // asn_fprint(stdout, &DEF(S1AP_PDU), p);
            // ASN_STRUCT_FREE(DEF(S1AP_PDU), &result);
            ASN_STRUCT_RESET(DEF(S1AP_PDU), p);
        }
    }
}

int
main(int argc, char *argv[])
{
    if (argc < 2)
        return -1;

    capture::pcap_offline pcaprx(argv[1]);

    processing_context cxt;

    pcaprx.loop(-1, packet_handler, reinterpret_cast<uint8_t *>(&cxt));

    std::cout << "STATS:\n";
    // std::cout << "ACTIVE REASSEMBLY SESSIONS: " <<
    // reassembler.activeSessions() << std::endl;
    std::cout << "PROCESSED       : " << cxt.stats.packets << '\n';
    std::cout << "ASN1_DECODE_FAIL: " << cxt.stats.asn1_decode_fail << '\n';
    return 0;
}


// void
// asn1test()
// {
//     OUTER_t stacko{};
//     // OUTER_t *o = static_cast<OUTER_t *>(calloc(1, sizeof(OUTER_t)));
//     OUTER_t *o = &stacko;
//     o->outerId = 666;
//     // OCTET_STRING_fromBuf(&o->opaque, "ciao", 4);
//     OCTET_STRING_fromString(&o->opaque, "ciao");

//     o->nested.nestedId = 777;
//     o->nested.value1   = 10;
//     o->nested.value2   = true;

//     std::array<uint8_t, 128> buffer;
//     auto const encode_result = asn_encode_to_buffer(
//       0, ATS_ALIGNED_BASIC_PER, &DEF(OUTER), o, buffer.data(),
//       buffer.size());


//     std::cout << "Encoded size " << encode_result.encoded << '\n';


//     OUTER_t *result{};
//     auto const decode_result = asn_decode(nullptr,
//                                           ATS_ALIGNED_BASIC_PER,
//                                           &DEF(OUTER),
//                                           reinterpret_cast<void
//                                           **>(&result), buffer.data(),
//                                           buffer.size());

//     std::cout << "Decoded size " << decode_result.consumed << '\n';

//     int compare_result = DEF(OUTER).op->compare_struct(&DEF(OUTER), o,
//     result); assert(compare_result == 0);

//     asn_fprint(stdout, &DEF(OUTER), o);
//     asn_fprint(stdout, &DEF(OUTER), result);
//     // ASN_STRUCT_FREE(DEF(OUTER, o);
//     ASN_STRUCT_RESET(DEF(OUTER), o);
// }
