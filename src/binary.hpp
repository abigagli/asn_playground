#pragma once
#include <cstdint>
#include <span>
#include <type_traits>

namespace binary {
template <typename T>
requires std::is_integral_v<T> T
from_bytes(std::span<std::byte const> bytes);

template <typename T>
requires std::is_integral_v<T> && std::is_unsigned_v<T> T
padded(unsigned int val, unsigned int multiple)
{
    return val + (multiple - 1) & -multiple;
}


template <>
uint64_t inline from_bytes<uint64_t>(std::span<std::byte const> bytes)
{
    return std::to_integer<uint64_t>(bytes[0]) << 56 |
           std::to_integer<uint64_t>(bytes[1]) << 48 |
           std::to_integer<uint64_t>(bytes[2]) << 40 |
           std::to_integer<uint64_t>(bytes[3]) << 32 |
           std::to_integer<uint64_t>(bytes[4]) << 24 |
           std::to_integer<uint64_t>(bytes[5]) << 16 |
           std::to_integer<uint64_t>(bytes[6]) << 8 |
           std::to_integer<uint64_t>(bytes[7]);
}

template <>
uint32_t inline from_bytes<uint32_t>(std::span<std::byte const> bytes)
{
    return std::to_integer<uint32_t>(bytes[0]) << 24 |
           std::to_integer<uint32_t>(bytes[1]) << 16 |
           std::to_integer<uint32_t>(bytes[2]) << 8 |
           std::to_integer<uint32_t>(bytes[3]);
}

template <>
uint16_t inline from_bytes<uint16_t>(std::span<std::byte const> bytes)
{
    return std::to_integer<uint16_t>(bytes[0]) << 8 |
           std::to_integer<uint16_t>(bytes[1]);
}

template <class T>
bool
has_bytes(size_t n, std::span<T> sp)
{
    return !(sp.size() < n);
}

template <class T>
size_t
consume(std::span<T> &sp, size_t n)
{
    sp = sp.last(sp.size() - n);
    return n;
}
} // namespace binary