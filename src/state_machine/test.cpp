#include "convenience_handlers.hpp"
#include "state_machine.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>

void
test_sm()
{
    using namespace state_machine;
    struct open_event
    {};
    struct close_event
    {};
    struct lock_event
    {
        uint32_t new_key;
    };
    struct unlock_event
    {
        uint32_t key;
    };

    struct closed_state;
    struct open_state;
    struct locked_state;

    class locked_state: public ByDefault<NoTransition>
    {
    public:
        using ByDefault::handle;

        locked_state(uint32_t key = 0) : key_(key) {}

        Maybe<TransitionTo<closed_state>> handle(const unlock_event &e) const
        {
            if (e.key == key_)
            {
                return TransitionTo<closed_state>{};
            }
            return NoTransition{};
        }

        void onEnter(lock_event const &e) { key_ = e.new_key; }

    private:
        uint32_t key_;
    };


    struct closed_state:
      Will<ByDefault<NoTransition>,
           On<lock_event, TransitionTo<locked_state>>,
           On<open_event, TransitionTo<open_state>>>
    {};

    struct open_state
    {
        NoTransition handle(lock_event const &) const
        {
            std::cout << "CAN'T LOCK OPEN DOOR\n";
            return {};
        }
        NoTransition handle(unlock_event const &) const
        {
            std::cout << "CAN'T UNLOCK OPEN DOOR\n";
            return {};
        }

        NoTransition handle(open_event const &) const
        {
            std::cout << "DOOR ALREADY OPEN\n";
            return {};
        }
        TransitionTo<closed_state> handle(close_event const &) const
        {
            std::cout << "Closing the door\n";
            return {};
        }
    };

    state_machine::Engine<closed_state, open_state, locked_state> sm(
      {}, {}, {});
    state_machine::EventHandler<open_event, decltype(sm)> auto o = open_state{};
    assert(sm.currentState<closed_state>());

    sm.handle(open_event{});
    assert(sm.currentState<open_state>());

    sm.handle(close_event{});
    assert(sm.currentState<closed_state>());

    sm.handle(lock_event{666});
    assert(sm.currentState<locked_state>());

    sm.handle(unlock_event{777});
    assert(sm.currentState<locked_state>());

    sm.handle(unlock_event{666});
    assert(sm.currentState<closed_state>());

    sm.handle(close_event{});
    assert(sm.currentState<closed_state>());

    sm.handle(open_event{});
    assert(sm.currentState<open_state>());
}
