#pragma once
#include "constraints.hpp"

namespace state_machine {
inline namespace convenience_handlers {
    template <class ACTION>
    struct ByDefault
    {
        struct event_type
        {};
        template <class EVENT>
        ACTION handle(EVENT const &) const
        {
            return {};
        }
    };

    template <class EVENT, class ACTION>
    struct On
    {
        using event_type = EVENT;
        ACTION handle(EVENT const &) const { return {}; }
    };
} // namespace convenience_handlers

template <ConvenienceHandler... HANDLERS>
struct Will: HANDLERS...
{
    using HANDLERS::handle...;
};


} // namespace state_machine