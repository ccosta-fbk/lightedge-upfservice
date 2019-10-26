#ifndef CLICK_UPFROUTER_PCAP_HH
#define CLICK_UPFROUTER_PCAP_HH

// clang-format off
#include <click/element.hh>
#include <click/task.hh>
CLICK_DECLS
// clang-format on

#include <s1aplib/s1aplib.hh>

/*
 * =c
 * UPFRouterPcapReader
 * =s debugging
 *
 * =d

 * This element reads Ethernet frames from a .pcap file, supporting
 * both Ethernet records and LinuxCooked records (in this latter case,
 * a fake Ethernet header is prepended, with a fake destination MAC
 * address -- source MAC address and EthType are taken from the
 * LinuxCooked header, see NetworkLib::PcapEthReader).
 */
class UPFRouterPcapReader : public Element {
  public:
    UPFRouterPcapReader() : mActive(false), mTask(this){};
    ~UPFRouterPcapReader(){};

    // clang-format off
    const char *class_name() const	{ return "UPFRouterPcapReader"; }
    const char *port_count() const      { return PORTS_0_1; }
    const char *processing() const      { return AGNOSTIC; }
    // clang-format on

    // Implement the Element interface
    virtual int configure(Vector<String> &conf, ErrorHandler *errh) override;
    virtual int initialize(ErrorHandler *errh) override;
    virtual Packet *pull(int port) override;
    virtual bool run_task(Task *) override;

  private:
    WritablePacket *doRead();

    bool mActive;
    Task mTask;

    // Note: a unique_ptr, as filename must be given on
    //       construction
    std::unique_ptr<NetworkLib::PcapEthReader> mEthReader;
    String mFilename;
    std::size_t mRepeats = 1;
};

/*
 * =c
 * UPFRouterPcapWriter
 * =s debugging
 *
 * =d

 * This element writes Ethernet frames or IPv4 packets/fragments to a
 * .pcap file.
 *
 */
class UPFRouterPcapWriter : public Element {
  public:
    UPFRouterPcapWriter() : mActive(false), mTask(this) {}

    ~UPFRouterPcapWriter() {}

    // clang-format off
    const char *class_name() const	{ return "UPFRouterPcapWriter"; }
    const char *port_count() const      { return "1/0"; }
    const char *processing() const      { return AGNOSTIC; }
    // clang-format on

    // Implement the Element interface
    virtual int configure(Vector<String> &conf, ErrorHandler *errh) override;
    virtual int initialize(ErrorHandler *errh) override;
    virtual void push(int port, Packet *p) override;
    virtual Packet *pull(int port) override;

    virtual bool run_task(Task *) override;

  private:
    void doWrite(Packet *p);

    bool mActive;
    Task mTask;

    // Note: a unique_ptr as filename must be given on
    //       construction
    std::unique_ptr<NetworkLib::PcapEthWriterPlus> mEthWriter;
    String mFilename;

    // By default, write out Ethernet packets
    bool mWriteIPv4 = false;
};

// clang-format off
CLICK_ENDDECLS
// clang-format on
#endif
