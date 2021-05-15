#pragma once
#include "sctp_packet.h"
#include "types.h"

#include <any>
#include <cassert>
#include <cstddef>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <span>
#include <unordered_map>
#include <variant>
#include <vector>


namespace SCTP {
class Reassembler
{
public:
    struct PacketInfo
    {
        uint64_t pktnum;
        types::timestamp ts;
        uint16_t sid;
        uint16_t ssn;
        bool first_segment;
        bool last_segment;
    };

    struct Fragment
    {
        PacketInfo info;
        std::span<std::byte const> bytes;
    };

    struct Error
    {
        uint64_t pktnum;
        enum
        {
            DuplicateTSN,
            // NotTracked,
            // TooManySessions,
            SSNMismatch,
            // TSNNonSeq,
        } code;
    };

    struct Completed
    {
        std::vector<uint64_t> pkt_nums;
        std::vector<std::byte> bytes;
    };

private:
    struct fragments;
    using session_map_t = std::unordered_map<tag_t, fragments>;
    using lru_toc_t     = std::map<types::timestamp, std::any>;

    class fragment_holder
    {
        PacketInfo info_;
        std::vector<std::byte> bytes_;

    public:
        fragment_holder(Fragment const &f)
          : info_(f.info), bytes_(std::begin(f.bytes), std::end(f.bytes))
        {}

        [[nodiscard]] PacketInfo const &info() const { return info_; }
        [[nodiscard]] auto const &bytes() const { return bytes_; }

        [[nodiscard]] bool rtxOf(Fragment const &rhs) const
        {
            return info_.sid == rhs.info.sid && info_.ssn == rhs.info.ssn &&
                   bytes_.size() == rhs.bytes.size();
        }
    };

    class fragments: private std::map<tsn_t, fragment_holder>
    {
        using base          = std::map<tsn_t, fragment_holder>;
        size_t total_bytes_ = 0;
        bool first_present_ = false;
        bool last_present_  = false;

    public:
        using base::find;
        using base::begin;
        using base::end;
        using base::size;
        using base::empty;
        lru_toc_t::iterator m_lru;
        bool addFragment(tsn_t tsn, Fragment const &fragment)
        {
            if (try_emplace(tsn, fragment).second)
            {
                total_bytes_ += fragment.bytes.size();
                if (fragment.info.first_segment)
                    first_present_ = true;

                if (fragment.info.last_segment)
                    last_present_ = true;

                return true;
            }

            return false;
        }

        [[nodiscard]] bool collectable() const
        {
            if (empty() || !first_present_ || !last_present_)
                return false;

            auto next_tsn  = begin()->first;
            auto const ssn = begin()->second.info().ssn;

            for (auto it = cbegin(); it != cend(); ++it)
            {
                if (it->first != next_tsn || it->second.info().ssn != ssn)
                    return false;
                ++next_tsn;
            }

            return true;
        }

        [[nodiscard]] Completed collect() const
        {
            Completed result;
            result.pkt_nums.reserve(size());
            result.bytes.reserve(total_bytes_);

            std::accumulate(
              begin(),
              end(),
              0ULL,
              [&result](size_t pos, auto const &elem)
              {
                  auto const fragment = elem.second;
                  result.pkt_nums.push_back(fragment.info().pktnum);

                  result.bytes.insert(std::next(std::begin(result.bytes), pos),
                                      std::begin(fragment.bytes()),
                                      std::end(fragment.bytes()));
                  return pos + fragment.bytes().size();
              });

            return result;
        }
    };

    size_t max_sessions_;
    session_map_t sessions_;
    lru_toc_t lru_toc_;

    auto start_reassembly_session(tag_t tag,
                                  tsn_t tsn,
                                  Fragment const &fragment)
    {
        auto [session_it, session_inserted_ok] =
          sessions_.insert({tag, fragments{}});

        assert(session_inserted_ok);

        auto [lru_it, lru_inserted_ok] =
          lru_toc_.insert({fragment.info.ts, session_it});

        assert(lru_inserted_ok);

        auto &fragments  = session_it->second;
        fragments.m_lru  = lru_it;
        bool const added = fragments.addFragment(tsn, fragment);

        assert(added);
        assert(sessions_.size() == lru_toc_.size());
        return session_it;
    }

    auto terminate_reassembly_session(session_map_t::iterator session_it)
    {
        assert(session_it != std::end(sessions_));

        auto node = sessions_.extract(session_it);
        lru_toc_.erase(node.mapped().m_lru);
        assert(sessions_.size() == lru_toc_.size());
        return node;
    }

    void evict_lru()
    {
        auto oldest_it = std::begin(lru_toc_);
        assert(oldest_it != std::end(lru_toc_));

        // TODO: Add counter
        terminate_reassembly_session(
          std::any_cast<session_map_t::iterator>(oldest_it->second));
        // **** oldest_it invalidated from here *****
    }

public:
    struct InProgress
    {
        decltype(sessions_)::iterator session;
    };

    explicit Reassembler(size_t max_sessions)
      : max_sessions_(max_sessions), sessions_(max_sessions)
    {}

    [[nodiscard]] auto activeSessions() const { return sessions_.size(); }

    std::variant<Completed, InProgress, Error>
    addFragment(tag_t tag, tsn_t tsn, Fragment const &fragment)
    {
        auto session_it = sessions_.find(tag);

        if (session_it == std::end(sessions_)) // Sink
        {
            // TODO: Add logging
            if (!fragment.info.first_segment)
                std::clog << '#' << fragment.info.pktnum
                          << ": Misorederd first fragment\n";

            if (activeSessions() + 1 > max_sessions_)
            {
                // return Error{fragment.info.pktnum, Error::TooManySessions};
                evict_lru();
            }

            session_it = start_reassembly_session(tag, tsn, fragment);

            if (session_it->second.collectable())
            {
                return terminate_reassembly_session(session_it)
                  .mapped()
                  .collect();
            }

            return InProgress{session_it};
        }

        // session_it valid here

        auto &fragments                 = session_it->second;
        auto const fragment_with_tsn_it = fragments.find(tsn);

        if (fragment_with_tsn_it != std::end(fragments)) [[unlikely]] // Sink
        {
            auto const &fragment_with_tsn = fragment_with_tsn_it->second;
            // If we have already seen this TSN for this TAG, tolerate it
            // only if it seems like a RTX
            if (fragment_with_tsn.rtxOf(fragment))
            {
                // TODO: Add logging
                std::clog << '#' << fragment.info.pktnum << ": DUPLICATE TSN "
                          << tsn << " (PREVIOUS PACKET "
                          << fragment_with_tsn.info().pktnum << ")\n";

                // No need to add this fragment, just check if we can collect
                if (session_it->second.collectable())
                {
                    return terminate_reassembly_session(session_it)
                      .mapped()
                      .collect();
                }

                return InProgress{session_it};
            }
            else
            {
                // Otherwise something's screwed up, and we'd better forget
                // about this whole reassembly session
                terminate_reassembly_session(session_it);
                return Error{fragment.info.pktnum, Error::DuplicateTSN};
            }
        }

        if (!fragments.empty())
        {
            // If we already have at least a fragment, perform an SSN sanity
            // check: SSN should be the same over all fragments
            auto const last_fragment_it = std::prev(std::end(fragments));
            if (last_fragment_it->second.info().ssn != fragment.info.ssn)
            {
                terminate_reassembly_session(session_it);
                return Error{fragment.info.pktnum, Error::SSNMismatch};
            }

            // TODO: Add logging
            if (last_fragment_it->first + 1 != tsn)
                std::clog << '#' << fragment.info.pktnum
                          << ": Misorederd fragment\n";
        }

        // We got here with fragments_it == std::end(fragments), so this can
        // never fail
        fragments.addFragment(tsn, fragment);

        if (session_it->second.collectable())
        {
            return terminate_reassembly_session(session_it).mapped().collect();
        }

        return InProgress{session_it};
    }
};
} // namespace SCTP
