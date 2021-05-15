#pragma once
#include <utility>
#include <variant>

namespace state_machine {
template <class I, class... S>
class Engine;

#if 0
inline namespace lambda_actions {
    template <class STATE>
    auto inline transition_to = []<class I, class... S>(Engine<I, S...> &engine)
    {
        engine.template transitionTo<STATE>();
    };
    auto inline no_transition = []<class I, class... S>(Engine<I, S...> &){};
} // namespace lambda_actions
#endif

inline namespace actions {
    template <class TARGET_STATE>
    struct TransitionTo
    {
        template <class STATE, class EVENT, class I, class... S>
        void operator()(Engine<I, S...> &engine,
                        STATE &prev_state,
                        EVENT const &event)
        {
            leave(prev_state, event);
            TARGET_STATE &new_state =
              engine.template transitionTo<TARGET_STATE>();
            enter(new_state, event);
        }

    private:
        void leave(...) // Catch-all
        {}

        template <class STATE, class EVENT>
        requires requires(STATE s, EVENT e) { s.onLeave(e); }
        auto leave(STATE &state, EVENT const &event)
        {
            return state.onLeave(event);
        }

        void enter(...) // Catch-all
        {}

        template <class STATE, class EVENT>
        requires requires(STATE s, EVENT e) { s.onEnter(e); }
        auto enter(STATE &state, EVENT const &event)
        {
            return state.onEnter(event);
        }
    };

    struct NoTransition
    {
        template <class STATE, class EVENT, class I, class... S>
        void operator()(Engine<I, S...> &, STATE &, EVENT const &)
        {}
    };
} // namespace actions

template <class... ACTIONS>
class OneOf
{
public:
    template <typename T>
    OneOf(T &&arg) : options(std::forward<T>(arg))
    {}

    template <class STATE, class EVENT, class I, class... S>
    void operator()(Engine<I, S...> &engine,
                    STATE &prev_state,
                    EVENT const &event)
    {
        std::visit([&engine, &prev_state, &event](auto &action)
                   { action(engine, prev_state, event); },
                   options);
    }

private:
    std::variant<ACTIONS...> options;
};

template <class ACTION>
struct Maybe: OneOf<ACTION, NoTransition>
{
    using OneOf<ACTION, NoTransition>::OneOf;
};

} // namespace state_machine