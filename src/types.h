#pragma once
#include <chrono>
#include <iosfwd>

namespace types {
using timestamp =
  std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;


template <class... Ts>
struct overload: Ts...
{
    using Ts::operator()...;
};
template <class... Ts>
overload(Ts...) -> overload<Ts...>;

template <class T, template <class> class Base>
struct CRTP
{
    // Convenience downcasting functions
    T &underlying() { return static_cast<T &>(*this); }
    T const &underlying() const { return static_cast<T &>(*this); }

private:
    // Safety net to prevent mismatches such as Derived1 : Base<Derived2>
    CRTP() = default;
    friend Base<T>;
};

template <class T>
class CRTPDumpable: public CRTP<T, CRTPDumpable>
{
    static bool constexpr is_overridden = requires(T const &t, std::ostream &os)
    {
        t.template dump<std::true_type{}>(os);
    };

public: template <std::false_type = std::false_type{}>
    requires is_overridden void dump(std::ostream &os) const
    {
        this->underlying().dump(os);
    }
};

} // namespace types