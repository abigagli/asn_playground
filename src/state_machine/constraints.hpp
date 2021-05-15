#pragma once

namespace state_machine {
template <class I, class... S>
class Engine;

inline namespace constraints {
    template <class ACTION,
              class STATE,
              class EVENT,
              class ENGINE = Engine<void>>
    concept Action =
      requires(ACTION action, STATE prev_state, EVENT event, ENGINE engine)
    {
        action(engine, prev_state, event);
    };

    template <class STATE, class EVENT, class ENGINE>
    concept EventHandler = requires(STATE state, EVENT event)
    {
        {
            state.handle(event)
            } -> Action<STATE, EVENT, ENGINE>;
    };

    template <class HANDLER>
    concept ConvenienceHandler =
      EventHandler<HANDLER, typename HANDLER::event_type, Engine<void>>;
} // namespace constraints
} // namespace state_machine