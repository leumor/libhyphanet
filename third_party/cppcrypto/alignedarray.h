/*
This code is written by kerukuro for cppcrypto library
(http://cppcrypto.sourceforge.net/) and released into public domain.
*/

#ifndef CPPCRYPTO_ALIGNEDARRAY_H
#define CPPCRYPTO_ALIGNEDARRAY_H

#include "portability.h"
#include <algorithm>
#include <cstring>
#include <stdlib.h>

namespace cppcrypto {
template<typename T, size_t N, size_t A> class aligned_pod_array {
public:
    aligned_pod_array()
    {
        auto size = (sizeof(T) * N / A + 1) * A;
        t = static_cast<T*>(aligned_allocate(size, A));
    }
    ~aligned_pod_array() { reset(); }
    explicit(false) operator T*() { return t; }
    T* get() { return t; }
    const T* get() const { return t; }
    void reset()
    {
        if (t) {
            aligned_deallocate(t);
            t = nullptr;
        }
    }
    size_t size() const { return N; }
    size_t bytes() const { return sizeof(T) * N; }

    aligned_pod_array(aligned_pod_array&& other) noexcept: t{other.t}
    {
        other.t = nullptr;
    }

    aligned_pod_array& operator=(aligned_pod_array&& other) noexcept
    {
        std::swap(t, other.t);
        return *this;
    }

    aligned_pod_array(const aligned_pod_array& other)
    {
        t = static_cast<T*>(aligned_allocate(sizeof(T) * N, A));
        *this = other;
    }

    aligned_pod_array& operator=(const aligned_pod_array& other)
    {
        memcpy(t, other.t, sizeof(T) * N);
        return *this;
    }
private:
    T* t{nullptr};
};

template<typename T, size_t A> class aligned_impl_ptr {
public:
    aligned_impl_ptr() = default;
    ~aligned_impl_ptr() { destroy(); }

    template<typename RT> void create()
    {
        void* p = aligned_allocate(sizeof(RT), A);
        t = new (p) RT;
    }

    void destroy()
    {
        if (t) {
            t->~T();
            aligned_deallocate(t);
            t = nullptr;
        }
    }

    template<typename RT, typename P> void create(const P& param)
    {
        void* p = aligned_allocate(sizeof(RT), A);
        t = new (p) RT(param);
    }

    explicit(false) operator T*() { return t; }
    T* get() { return t; }
    const T* get() const { return t; }

    T* operator->() const { return t; }

    aligned_impl_ptr(aligned_impl_ptr&& other) noexcept: t{other.t}
    {
        other.t = nullptr;
    }

    aligned_impl_ptr& operator=(aligned_impl_ptr&& other) noexcept
    {
        std::swap(t, other.t);
        return *this;
    }
private:
    aligned_impl_ptr(const aligned_impl_ptr& other) = delete;
    aligned_impl_ptr& operator=(const aligned_impl_ptr& other) = delete;
    T* t{nullptr};
};

} // namespace cppcrypto

#endif /* CPPCRYPTO_ALIGNEDARRAY_H */
