#pragma once
#include "constraints.hpp"

#include <functional>
#include <tuple>
#include <variant>
namespace state_machine {

template <class INITIAL_STATE, class... STATES>
class Engine
{
    std::tuple<INITIAL_STATE, STATES...> states_;
    std::variant<INITIAL_STATE *, STATES *...> current_state_ =
      &std::get<INITIAL_STATE>(states_);

public:
    Engine() = default;
    Engine(INITIAL_STATE is, STATES... ss)
      : states_(std::move(is), std::move(ss)...)
    {}

    template <class STATE>
    STATE &transitionTo()
    {
        auto &state    = std::get<STATE>(states_);
        current_state_ = &state;
        return state;
    }

    template <class STATE>
    STATE *currentState() const
    {
        if (auto *result = std::get_if<STATE *>(&current_state_))
            return *result;

        return nullptr;
    }

    template <class EVENT>
    void handle(EVENT const &event)
    {
        auto pass_event_to_state =
          [this, &event]<class STATE>(
            STATE *
              state_ptr) // requires EventHandler<STATE, EVENT, decltype(*this)>
        {
            constexpr bool state_satisfies_requirements =
              EventHandler<STATE, EVENT, decltype(*this)>;
            static_assert(state_satisfies_requirements);
            auto action = state_ptr->handle(event);
            action(*this, *state_ptr, event);
        };

        std::visit(pass_event_to_state, current_state_);
    }
};

} // namespace state_machine
