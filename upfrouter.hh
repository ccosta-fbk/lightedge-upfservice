#ifndef CLICK_UPFROUTER_HH
#define CLICK_UPFROUTER_HH

// clang-format off
#include <click/element.hh>
CLICK_DECLS
// clang-format on

#include <networklib/networklib.hh>
#include <upfrouterlib/upfrouterlib.hh>

// For std::unique_ptr<T>
#include <memory>

/*
 * =c
 * UPFRouter([enableudpchecksum {true|false}]
 *           [enableunknowntrafficdump * {true|false}])
 *
 * =s general
 * In a 4G network, route network traffic between eNodeB's and EPCs,
 * deviating part of it to Virtual Network Functions.
 *
 * =d
 *
 * All input and output packets are IPv4 traffic.
 *
 * This element analyzes all IPv4 traffic put through it and then:
 *
 * 1. it looks for S1AP messages sent between eNodeBs and EPCs,
 *    extracting from them the information to build and keep
 *    up-to-date a map between an UE's IPv4 address and its GTPv1
 *    tunnel endopoints.
 *
 *    Other than that, this kind of traffic is forwarded to its
 *    original destination unmodified, through output port 0 and 1.
 *
 * 2. it looks at IPv4 traffic encapsulated in GTPv1-U (i.e. UE user
 *    traffic): if it comes from a known UE and it matches one of the
 *    rules, then it is decapsulated and sent through output
 *    port 2 to be processed further.
 *
 * 3. it looks at plain IPv4 traffic coming from/destined to the
 *    address of a known UE (i.e. VNF responses) from port 2: the
 *    traffic is ecapsulated in the appropriate GTPv1-U tunnel and
 *    sent either to the appropriate eNodeB or EPC through output port
 *    0 or 1.
 */

class UPFRouter : public Element {
  public:
    UPFRouter(){};
    ~UPFRouter(){};

    // clang-format off
    const char *class_name() const { return "UPFRouter"; }
    const char *port_count() const { return "3/3-4"; }
    const char *processing() const { return "aaa/hhhh"; }
    // clang-format on

    // Implement the Element interface
    virtual int configure(Vector<String> &conf, ErrorHandler *errh) override;
    virtual int initialize(ErrorHandler *errh) override;

    // Note: overriding Click's Element::simple_action() is not
    //       enough, as we also need to know the source port of the
    //       packet. Therefore, we override both Element::push() and
    //       Element::pull().
    //
    virtual void push(int port, Packet *p) override {
        if (p) {
            p = simple_action_extended(p, port);

            if (p) {
                output(port).push(p);
            }
        }
    }

    virtual Packet *pull(int port) override {
        Packet *p = input(port).pull();
        if (p)
            p = simple_action_extended(p, port);
        return p;
    }

    // Note: this is just like Click's Element::simple_action(), but
    //       is passed also the input port of the packet.
    Packet *simple_action_extended(Packet *p, int inputPort);

    void add_handlers();

  private:
    UPFRouterLib::Router mRouter;

    UPFRouterLib::RuleMatcher mRuleMatcher;

    NetworkLib::BufferWritableView mIPv4WriteBuffer = {
        NetworkLib::BufferWritableView::makeIPv4Buffer()};
    NetworkLib::IPv4PacketTap mIPv4Tap;

    NetworkLib::IPv4IdentificationSource mIdentificationSource;

    UPFRouterLib::GTPv1UEncapSink mGTPEncapSink = {
        mIPv4Tap, mIPv4WriteBuffer, mRouter, mIdentificationSource};

    bool mDoEnableUnknownTrafficDump = true;

    ///@brief Handles GTPv1-U traffic
    bool handleInterceptedGTPv1UTraffic(
        NetworkLib::EthPacketProcessor::Context &context);

    ///@brief Handles plain IPv4 traffic
    bool
    handleIPv4PostProcess(NetworkLib::EthPacketProcessor::Context &context);

    ///@brief Handles non-IPv4 traffic
    bool handleNonIPv4(NetworkLib::EthPacketProcessor::Context &context);

    ///@brief Handles IPv4 traffic to/from an unknown UE
    bool handleIPv4UnknownUE(const NetworkLib::BufferView &ipv4data);

    ///@brief Handle all remaining traffic
    bool handleCommonTraffic(NetworkLib::EthPacketProcessor::Context &context);

    ///@name Click's read handler for UEMap
    ///
    ///@{

    ///@brief Return UEMap content
    String rh_UEMap(void *vparam);

    ///@brief Glue code
    static String read_handler_UEMap(Element *e, void *vparam) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.rh_UEMap(vparam);
    }

    ///@}

    ///@name Click's read handler for MatchMap
    ///
    ///@{

    ///@brief Return UEMap content
    String rh_MatchMap(void *vparam);

    ///@brief Glue code
    static String read_handler_MatchMap(Element *e, void *vparam) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.rh_MatchMap(vparam);
    }

    ///@}

    ///@name Click's write handlers for updating MatchMap content
    ///
    ///@{

    /// @brief Insert a rule in the given position
    int wh_MatchMap_insert(const String &str, void *vparam, ErrorHandler *errh);

    /// @brief Glue code
    static int write_handler_MatchMap_insert(const String &str, Element *e,
                                             void *vparam, ErrorHandler *errh) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.wh_MatchMap_insert(str, vparam, errh);
    }

    /// @brief Append a rule at the end
    int wh_MatchMap_append(const String &str, void *vparam, ErrorHandler *errh);

    /// @brief Glue code
    static int write_handler_MatchMap_append(const String &str, Element *e,
                                             void *vparam, ErrorHandler *errh) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.wh_MatchMap_append(str, vparam, errh);
    }

    /// @brief Delete the rule at the given position
    int wh_MatchMap_delete(const String &str, void *vparam, ErrorHandler *errh);

    /// @brief Glue code
    static int write_handler_MatchMap_delete(const String &str, Element *e,
                                             void *vparam, ErrorHandler *errh) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.wh_MatchMap_delete(str, vparam, errh);
    }

    /// @brief Delete the rule at the given position
    int wh_MatchMap_clear(const String &str, void *vparam, ErrorHandler *errh);

    /// @brief Glue code
    static int write_handler_MatchMap_clear(const String &str, Element *e,
                                            void *vparam, ErrorHandler *errh) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.wh_MatchMap_clear(str, vparam, errh);
    }

    ///@}

    ///@name Click's write handler for enabling/disabling UPD checksums
    ///
    ///@{

    /// @brief Enable/disable computing UDP checksums for IPv4 traffic
    ///        being encapsulated in GTPv1-U
    int wh_enableUPDChecksum(const String &str, void *vparam,
                             ErrorHandler *errh);

    /// @brief Glue code
    static int write_handler_enableUDPChecksum(const String &str, Element *e,
                                               void *vparam,
                                               ErrorHandler *errh) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.wh_enableUPDChecksum(str, vparam, errh);
    }

    ///@}

    ///@name Click's write handler for enabling/disabling dump of plain IPv4
    /// traffic
    ///      that should
    ///
    ///@{

    /// @brief Enable/disable dumping unknown IPv4 traffic that can't be
    /// encapsulated
    ///        back into GTPv1-U
    int wh_enableUnknownTrafficDump(const String &str, void *vparam,
                                    ErrorHandler *errh);

    /// @brief Glue code
    static int write_handler_enableUknownTrafficDump(const String &str,
                                                     Element *e, void *vparam,
                                                     ErrorHandler *errh) {
        UPFRouter &self = *(static_cast<UPFRouter *>(e));
        return self.wh_enableUnknownTrafficDump(str, vparam, errh);
    }

    ///@}
};

// clang-format off
CLICK_ENDDECLS
// clang-format on
#endif
