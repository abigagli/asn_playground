#pragma once

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <functional>
#include <iostream>
#include <iterator>
#include <pcap.h>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

namespace capture {

///////////////////////////////////////////////
// sockaddr
///////////////////////////////////////////////

struct sockaddr
{
    explicit sockaddr(const ::sockaddr *s) : m_storage()
    {
        if (s == nullptr)
            return;

        if (s->sa_family == AF_INET)
            memcpy(&m_storage, s, sizeof(struct sockaddr_in));

        if (s->sa_family == AF_INET6)
            memcpy(&m_storage, s, sizeof(struct sockaddr_in6));
    }

    int family() const
    {
        return reinterpret_cast<const struct ::sockaddr &>(m_storage).sa_family;
    }

    uint16_t port() const
    {
        switch (this->family())
        {
        case AF_INET:
            return htons(
              reinterpret_cast<const struct sockaddr_in &>(m_storage).sin_port);
        case AF_INET6:
            return htons(
              reinterpret_cast<const struct sockaddr_in6 &>(m_storage)
                .sin6_port);
        }
        return 0;
    }

    std::string addr() const
    {
        char buf[64] = {'\0'};

        switch (this->family())
        {
        case AF_INET: {
            if (inet_ntop(
                  AF_INET,
                  &reinterpret_cast<const struct sockaddr_in &>(m_storage)
                     .sin_addr,
                  buf,
                  sizeof(buf)) == nullptr)
                throw std::runtime_error("pcap::sockaddr::addr");
        }
        break;

        case AF_INET6: {
            if (inet_ntop(
                  AF_INET6,
                  &reinterpret_cast<const struct sockaddr_in6 &>(m_storage)
                     .sin6_addr,
                  buf,
                  sizeof(buf)) == nullptr)
                throw std::runtime_error("pcap::sockaddr::addr");
        }
        break;
        }

        return std::string(buf);
    }

private:
    struct sockaddr_storage m_storage;
};

///////////////////////////////////////////////
// address structure
///////////////////////////////////////////////

struct address
{
    sockaddr addr;
    sockaddr netmask;
    sockaddr broadaddr;
    sockaddr dstaddr;

    explicit address(pcap_addr_t *p)
      : addr(p->addr)
      , netmask(p->netmask)
      , broadaddr(p->broadaddr)
      , dstaddr(p->dstaddr)
    {}
};


template <typename CharT, typename Traits>
inline std::basic_ostream<CharT, Traits> &
operator<<(std::basic_ostream<CharT, Traits> &out, const address &a)
{
    out << '[';

    if (a.addr.family() == AF_INET || a.addr.family() == AF_INET6)
        out << a.addr.addr() << '/' << a.netmask.addr() << ' '
            << a.broadaddr.addr();

    if (a.dstaddr.family())
        out << " p-t-p:" << a.dstaddr.addr();

    return out << ']';
}

///////////////////////////////////////////////
// interface structure
///////////////////////////////////////////////

struct interface
{
    std::string name;
    std::string description;
    std::vector<address> addresses;
    unsigned int flags;

    explicit interface(pcap_if_t *i)
      : name(i->name)
      , description(i->description ? i->description : "")
      , flags(i->flags)
    {
        for (pcap_addr_t *addr = i->addresses; addr; addr = addr->next)
        {
            addresses.push_back(address(addr));
        }
    }
};

template <typename CharT, typename Traits>
inline std::basic_ostream<CharT, Traits> &
operator<<(std::basic_ostream<CharT, Traits> &out, const interface &i)
{
    out << "interface[ name:" << i.name << " descr:'" << i.description
        << "' flags:" << i.flags << " ";
    std::copy(i.addresses.begin(),
              i.addresses.end(),
              std::ostream_iterator<address>(out, ","));
    return out << " ]";
}

///////////////////////////////////////////////
// bfp program class
///////////////////////////////////////////////

struct bpf_prog
{
    bpf_prog(std::string str, bool optimize = true, bpf_u_int32 netmask = 0)
      : m_prog(), m_str(std::move(str)), m_opt(optimize), m_netmask(netmask)
    {}

    bpf_prog(const bpf_prog &) = delete;
    bpf_prog &operator=(const bpf_prog &) = delete;

    ~bpf_prog() { pcap_freecode(&m_prog); }

    void operator()(
      pcap_t *p) // the program is to be compiled by the pcap class...
    {
        if (pcap_compile(p, &m_prog, m_str.c_str(), m_opt, m_netmask) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(p)));
    }

    bpf_program &c_prg() { return m_prog; }

    const bpf_program &c_prg() const { return m_prog; }

    std::string c_str() const { return m_str; }

private:
    struct bpf_program m_prog;

    const std::string m_str;
    bool m_opt;
    bpf_u_int32 m_netmask;
};

///////////////////////////////////////////////
///////////////////////////////////////////////
// pcap base: class
///////////////////////////////////////////////
///////////////////////////////////////////////

static void
static_handler(u_char *that, const struct pcap_pkthdr *h, const u_char *bytes);

struct pcap_dumper;

struct pcap_base
{
protected:
    friend struct pcap_dumper;

    virtual ~pcap_base()
    {
        if (m_handle)
            pcap_close(m_handle);
    }

    pcap_base()                  = default;
    pcap_base(const pcap_base &) = delete;
    pcap_base &operator=(const pcap_base &) = delete;


    /////////////////////////////////////////////////////////////////////////
    // get pcap_t * handle...

    const pcap_t *handle() const { return m_handle; }

    pcap_t *handle() { return m_handle; }

public:
    pcap_base(pcap_base &&other)
      : m_errbuf(), m_handle(std::move(other.m_handle))
    {
        other.m_handle = nullptr;
    }

    pcap_base &operator=(pcap_base &&other)
    {
        if (this != &other)
        {
            if (m_handle)
                pcap_close(m_handle);

            m_handle = std::move(other.m_handle);
            memcpy(m_errbuf, other.m_errbuf, sizeof(m_errbuf));

            other.m_handle = nullptr;
        }
        return *this;
    }

    virtual void packet_handler(const struct pcap_pkthdr *, const u_char *)
    {
        throw std::runtime_error("packet_handler not implemented!");
    }

    /////////////////////////////////////////////////////////////////////////

    void nonblock(bool value)
    {
        clear_errbuf();

        if (pcap_setnonblock(m_handle, value, m_errbuf) == -1)
            throw std::runtime_error(std::string("pcap: ").append(m_errbuf));
    }

    bool is_nonblock() const
    {
        clear_errbuf();

        int value;
        if ((value = pcap_getnonblock(m_handle, m_errbuf)) == -1)
            throw std::runtime_error(std::string("pcap: ").append(m_errbuf));

        return value;
    }

    virtual std::string device() const { return "pcap::device"; }

    /////////////////////////////////////////////////////////////////////////

    int dispatch(int cnt)
    {
        int n;
        if ((n = pcap_dispatch(m_handle,
                               cnt,
                               static_handler,
                               reinterpret_cast<u_char *>(this))) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
        return n;
    }

    // direct version...
    int dispatch(int cnt, pcap_handler h, u_char *u = nullptr)
    {
        int n;
        if ((n = pcap_dispatch(m_handle, cnt, h, u)) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
        return n;
    }

    int loop(int cnt)
    {
        int n;
        if ((n = pcap_loop(m_handle,
                           cnt,
                           static_handler,
                           reinterpret_cast<u_char *>(this))) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
        return n;
    }

    // direct version...
    int loop(int cnt, pcap_handler h, u_char *u = nullptr)
    {
        int n;
        if ((n = pcap_loop(m_handle, cnt, h, u)) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
        return n;
    }

    const u_char *next(struct pcap_pkthdr *h)
    {
        // Unfortunately, there is no way to determine whether an error occurred
        // or not. nullptr is returned if no packers were read from a live
        // capture, or if no more packets are available in a ``savefile``.

        return pcap_next(m_handle, h);
    }

    int next_ex(struct pcap_pkthdr **pkt_header, const u_char **pkt_data)
    {
        int n;
        if ((n = pcap_next_ex(m_handle, pkt_header, pkt_data)) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
        return n;
    }

    void breakloop() { pcap_breakloop(m_handle); }

    /////////////////////////////////////////////////////////////////////////
    // filters...

    void filter(bpf_prog &prog)
    {
        // compile the bpf_prog first.
        //
        prog(m_handle);

        if (pcap_setfilter(m_handle, &prog.c_prg()) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
    }

    void direction(pcap_direction_t dir)
    {
        if (pcap_setdirection(m_handle, dir) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
    }

    /////////////////////////////////////////////////////////////////////////

    int inject(const void *buf, size_t size)
    {
        int r;
        if ((r = pcap_inject(m_handle, buf, size)) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));

        return r;
    }

    ///////////////////////////////////////////////
    // get errors...

    std::string geterr() const { return pcap_geterr(m_handle); }

    std::string errbuf() const { return std::string(m_errbuf); }

    ///////////////////////////////////////////////
    // datalink...

    void set_datalink(int dlt)
    {
        if (pcap_set_datalink(m_handle, dlt) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
    }

    int datalink() const
    {
        return pcap_datalink(const_cast<pcap_t *>(m_handle));
    }

    size_t datalink_len(int dtl = -1) const
    {
        if (dtl == -1)
            dtl = this->datalink();

        switch (dtl)
        {
        case DLT_NULL:
            return 4;
        case DLT_EN10MB:
            return 14;
        case DLT_EN3MB:
            return 14;
        // case DLT_AX25: return -1;
        // case DLT_PRONET: return -1;
        // case DLT_CHAOS: return -1;
        case DLT_IEEE802:
            return 22;
            // case DLT_ARCNET: return -1;
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
  defined(__BSDI__)
        case DLT_SLIP:
            return 16;
#else
        case DLT_SLIP:
            return 24;
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        case DLT_PPP:
            return 4;
#elif defined(__sun)
        case DLT_PPP:
            return 8;
#else
        case DLT_PPP:
            return 24;
#endif
        case DLT_FDDI:
            return 21;
        case DLT_ATM_RFC1483:
            return 8;

        case DLT_LOOP:
            return 4; // according to OpenBSD DLT_LOOP
                      // collision: see "bpf.h"
        case DLT_RAW:
            return 0;

        case DLT_SLIP_BSDOS:
            return 16;
        case DLT_PPP_BSDOS:
            return 4;
            // case DLT_ATM_CLIP: return -1;
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        case DLT_PPP_SERIAL:
            return 4;
        case DLT_PPP_ETHER:
            return 4;
#elif defined(__sun)
        case DLT_PPP_SERIAL:
            return 8;
        case DLT_PPP_ETHER:
            return 8;
#else
        case DLT_PPP_SERIAL:
            return 24;
        case DLT_PPP_ETHER:
            return 24;
#endif
        // case DLT_C_HDLC: return -1;
        case DLT_IEEE802_11:
            return 30;
        case DLT_LINUX_SLL:
            return 16;
            // case DLT_LTALK: return -1;
            // case DLT_ECONET: return -1;
            // case DLT_IPFILTER: return -1;
            // case DLT_PFLOG: return -1;
            // case DLT_CISCO_IOS: return -1;
            // case DLT_PRISM_HEADER: return -1;
            // case DLT_AIRONET_HEADER: return -1;
        }

        throw std::runtime_error("pcap: unknown datalink type");
    }

protected:
    void clear_errbuf() const { m_errbuf[0] = '\0'; }

    bool warning() const { return strlen(m_errbuf) > 0; }

    mutable char m_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *m_handle;
};

///////////////////////////////////////////////
// static functions
///////////////////////////////////////////////

static inline void
static_handler(u_char *that, const struct pcap_pkthdr *h, const u_char *bytes)
{
    reinterpret_cast<pcap_base *>(that)->packet_handler(h, bytes);
}

static inline std::string
lookupdev()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *ifaces;
    int const num_devs = pcap_findalldevs(&ifaces, errbuf);
    if (num_devs < 1)
        throw std::runtime_error(std::string("pcap: ").append(errbuf));

    return std::string(ifaces[0].name);
}

static inline std::pair<bpf_u_int32, bpf_u_int32>
lookupnet(const char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        throw std::runtime_error(std::string("pcap: ").append(errbuf));

    return std::make_pair(net, mask);
}

static inline std::string
ipv4_dotform(bpf_u_int32 value)
{
    char buf[16];
    if (inet_ntop(AF_INET, &value, buf, sizeof(buf)) == nullptr)
        throw std::runtime_error("sockaddress::inet_ntop");

    return std::string(buf);
}

static inline std::vector<interface>
findalldevs()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all, *dev;
    if (pcap_findalldevs(&all, errbuf) == -1)
        throw std::runtime_error(std::string("pcap: ").append(errbuf));

    std::vector<interface> ret;
    for (dev = all; dev; dev = dev->next)
        ret.push_back(interface(dev));

    pcap_freealldevs(all);
    return ret;
}

static inline const char *
lib_version()
{
    return pcap_lib_version();
}

static inline int
datalink_name_to_val(const char *name)
{
    return pcap_datalink_name_to_val(name);
}

static inline const char *
datalink_val_to_name(int dlt)
{
    return pcap_datalink_val_to_name(dlt);
}

static inline const char *
datalink_val_to_description(int dlt)
{
    return pcap_datalink_val_to_description(dlt);
}

///////////////////////////////////////////////
// pcap_live class
///////////////////////////////////////////////

struct pcap_live: pcap_base
{
    pcap_live(std::string dev, int snaplen, bool promisc, int to_ms)
      : pcap_base()
      , m_device(std::move(dev))
      , m_snaplen(snaplen)
      , m_promisc(promisc)
      , m_to_ms(to_ms)
    {
        this->clear_errbuf();

        m_handle = pcap_open_live(
          m_device.c_str(), m_snaplen, m_promisc, m_to_ms, m_errbuf);
        if (m_handle == nullptr)
            throw std::runtime_error(std::string("pcap: ").append(m_errbuf));

        if (this->warning())
            std::clog << "pcap warning: " << m_errbuf << std::endl;
    }

    // moveability...
    //

    pcap_live(pcap_live &&) = default;
    pcap_live &operator=(pcap_live &&) = default;

    std::string device() const { return m_device; }

    int snaplen() const { return m_snaplen; }

    bool promisc() const { return m_promisc; }

    int timeo_ms() const { return m_to_ms; }

    void stats(struct pcap_stat *ps)
    {
        if (pcap_stats(m_handle, ps) == -1)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(m_handle)));
    }

private:
    std::string m_device;
    int m_snaplen;
    bool m_promisc;
    int m_to_ms;
};

///////////////////////////////////////////////
// pcap_dead class
///////////////////////////////////////////////

struct pcap_dead: pcap_base
{
    pcap_dead(int linktype, int snaplen)
      : pcap_base(), m_linktype(linktype), m_snaplen(snaplen)
    {
        this->clear_errbuf();

        m_handle = pcap_open_dead(linktype, m_snaplen);
        if (m_handle == nullptr)
            throw std::runtime_error(std::string("pcap: ").append(m_errbuf));

        if (this->warning())
            std::clog << "pcap warning: " << m_errbuf << std::endl;
    }

    // moveability...
    //

    pcap_dead(pcap_dead &&other) = default;
    pcap_dead &operator=(pcap_dead &&other) = default;

    int snaplen() const { return m_snaplen; }

    int linktype() const { return m_linktype; }

private:
    int m_linktype;
    int m_snaplen;
};

///////////////////////////////////////////////
// pcap_offline class (read pcap file)
///////////////////////////////////////////////

struct pcap_offline: pcap_base
{
    explicit pcap_offline(std::string fname)
      : pcap_base(), m_device(std::move(fname))
    {
        clear_errbuf();
        m_handle = pcap_open_offline(m_device.c_str(), m_errbuf);
        if (m_handle == nullptr)
            throw std::runtime_error(std::string("pcap: ").append(m_errbuf));

        if (this->warning())
            std::clog << "pcap warning: " << m_errbuf << std::endl;
    }

    // moveability...
    //

    pcap_offline(pcap_offline &&) = default;
    pcap_offline &operator=(pcap_offline &&) = default;

    std::string device() const { return m_device; }

    int major_version() const { return pcap_major_version(m_handle); }

    int minor_version() const { return pcap_minor_version(m_handle); }

    bool is_swapped() const { return pcap_is_swapped(m_handle); }

private:
    std::string m_device;
};

///////////////////////////////////////////////
// pcap_dumper class (write to a pcap file)
///////////////////////////////////////////////

struct pcap_dumper
{
    pcap_dumper(pcap_base &source, const std::string &fname)
      : pcap_dumper(source, fname.c_str())
    {}

    pcap_dumper(pcap_base &source, const char *fname) : m_dumper(nullptr)
    {
        pcap_t *h = source.handle();
        if ((m_dumper = pcap_dump_open(h, fname)) == nullptr)
            throw std::runtime_error(
              std::string("pcap: ").append(pcap_geterr(h)));
    }

    ~pcap_dumper() { pcap_dump_close(m_dumper); }

    void dump(const struct pcap_pkthdr *h, const u_char *sp)
    {
        pcap_dump(reinterpret_cast<u_char *>(m_dumper), h, sp);
    }

    void flush()
    {
        if (pcap_dump_flush(m_dumper) == -1)
            throw std::runtime_error(std::string("pcap: pcap_dump_flush"));
    }

    static void handler(u_char *user,
                        const struct pcap_pkthdr *h,
                        const u_char *sp)
    {
        pcap_dumper *that = reinterpret_cast<pcap_dumper *>(user);
        that->dump(h, sp);
    }

private:
    pcap_dumper_t *m_dumper;
};

} // namespace capture


template <typename CharT, typename Traits>
inline std::basic_ostream<CharT, Traits> &
operator<<(std::basic_ostream<CharT, Traits> &out, const pcap_pkthdr &h)
{
    return out << '[' << h.ts.tv_sec << ':' << h.ts.tv_usec
               << " caplen:" << h.caplen << " len:" << h.len << ']';
}
