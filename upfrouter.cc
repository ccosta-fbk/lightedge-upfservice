/*
 * upfrouter.{cc,hh} -- Click element for eNodeB <-> EPC traffic
 * (based on sample Click Element by Eddie Kohler)
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2000 Mazu Networks, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

// clang-format off
// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
// clang-format on

#include "upfrouter.hh"
#include <click/error.hh>
#include <click/args.hh>
#include <click/router.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>

// clang-format off
CLICK_DECLS
// clang-format on

// Non-Click includes
#include <upfnetworklib/networklib.hh>
#include <upfs1aplib/s1aplib.hh>
#include <upfdumperlib/dumper.hh>

#include <sstream>

//////////////////////////////////////////////////////////////////////

// Click <-> UPFRouter NetworkLib adapters

// Make a new WritablePacket out of the content of a
// Networklib::BuffeView, by copying data.
//
// Note that a BufferView can't give up ownership of its
// underlying buffer, because either:
//
// * the BufferView has no PacketBuffer and doesn't own its underlying
//   buffer, so it can't give up ownership of something it doesn't
//   own;
//
// * the BufferView shares ownership of the underlying PacketBuffer
//   with others, therefore it can't give up ownership also for them.
static WritablePacket *
makeWritablePacket(const NetworkLib::BufferView &bufferView,
                   std::size_t headroom = 0) {

    WritablePacket *p =
        Packet::make(headroom, (const unsigned char *)0, bufferView.size(),
                     0); // No tailroom

    if (p) {
        // Copy data into packet
        bufferView.copyTo(0, bufferView.size(), p->data());

        // Add IPv4 annotations
        const click_ip *ip = reinterpret_cast<const click_ip *>(p->data());
        p->set_ip_header(ip, ip->ip_hl << 2);
    }

    return p;
}

// Hack to use click_chatter() as an std::ostream.
// You can then use
//
//     chatter << "Hello, world!" << std::flush;
//
// to print something via click_chatter();
//
class ClickChatterBuffer : public std::stringbuf {
  public:
    virtual int sync() {
        click_chatter("%s", str().c_str());
        str("");
        return 0;
    }
};

ClickChatterBuffer myBuffer;
std::ostream chatter(&myBuffer);

#if 0
/// @brief Convert a Click's EtherAddress to a NetworkLib::MACAddress
static NetworkLib::MACAddress
toMACAddress(const EtherAddress &clickEtherAddress) {
    const unsigned char *d = clickEtherAddress.data();
    return NetworkLib::MACAddress(d[0], d[1], d[2], d[3], d[4], d[5]);
}

/// @brief Convert a Click's IPAddress to a NetworkLib::IPv4Address
static NetworkLib::IPv4Address toIPv4Address(const IPAddress &clickIPAddress) {
    return NetworkLib::IPv4Address(
        NetworkLib::swapByteOrder(clickIPAddress.addr()));
}
#endif

/// @brief Get the Click input port number of the packet from the Context
///        (it's defined as a separate function just for clarity).
static inline int getClickInputPortFromContext(
    const NetworkLib::EthPacketProcessor::Context &context) {
    return context.userData.intUserData;
}

/// @brief True if a packet came from the EPC
static inline bool
packetCameFromEPC(NetworkLib::EthPacketProcessor::Context &context) {
    return (getClickInputPortFromContext(context) == 0);
}

/// @brief True if a packet came from a eNodeB
static inline bool
packetCameFromENodeB(NetworkLib::EthPacketProcessor::Context &context) {
    return (getClickInputPortFromContext(context) == 1);
}

/// @brief Similar to Click's configuration parsing function
///        `skip_spacevec_item()`, but instead using spaces as
///        delimiters, it looks for comma (`,`), end-of-line and start
///        of comments.
static const char *upf_skip_commavec_item(const char *s, const char *end) {
    while (s < end) {
        switch (*s) {

        case '/':
            // a comment ends the item
            if (s + 1 < end && (s[1] == '/' || s[1] == '*'))
                return s;
            s++;
            break;

            // A comma or a newline ends the item
        case ',':
        case '\n':
            return s;

        default:
            s++;
            break;
        }
    }
    return s;
}

/// @brief Equivalent to Click's `skip_comment()`. Unfortunately, it's
///        a static function, so we can't reuse it.
const char *upf_skip_comment(const char *s, const char *end) {
    if (s[1] == '/') {
        // comment to end-of-line
        for (s += 2; s < end; ++s) {
            if ((*s == '\n') || (*s == '\r')) {
                return s + 1;
            }
        }

        return end;
    } else {
        // multi-line comment
        for (s += 2; (s + 2) < end; ++s) {
            if (s[0] == '*' && s[1] == '/') {
                return s + 2;
            }
        }

        return end;
    }
}

/// @brief Similar to Click's configuration parsing function
///        `cp_skip_comment_space()`, but it searches for the first
///        non-comma character.
const char *upf_cp_skip_comment_comma(const char *begin, const char *end) {
    for (; begin < end; begin++) {
        if (*begin == ',')
            /* nada */;
        else if (*begin == '/' && begin + 1 < end &&
                 (begin[1] == '/' || begin[1] == '*'))
            begin = upf_skip_comment(begin, end) - 1;
        else
            break;
    }
    return begin;
}

/// @brief Similar to Click's configuration parsing function
///        `cp_shift_spacevec()`, but items are separated by comma
///        (`,`) or end-of-line instead of spaces.
String upf_cp_shift_commavec(String &str) {
    const char *item = upf_cp_skip_comment_comma(str.begin(), str.end());
    const char *item_end = upf_skip_commavec_item(item, str.end());
    String answer = str.substring(item, item_end);
    item_end = upf_cp_skip_comment_comma(item_end, str.end());
    str = str.substring(item_end, str.end());
    return answer;
}

//////////////////////////////////////////////////////////////////////

int UPFRouter::configure(Vector<String> &conf, ErrorHandler *errh) {

    bool doEnableUDPChecksum = true;
    bool doEnableUnknownTrafficDump = true;
    String matchmap;

    if (Args(conf, this, errh)
            .read("enableudpchecksum", BoolArg(), doEnableUDPChecksum)
            .read("enableunknowntrafficdump", BoolArg(),
                  doEnableUnknownTrafficDump)
            .read("matchmap", StringArg(), matchmap)
            .complete() < 0) {
        errh->error("Error while parsing arguments!");
        return -1;
    }

    if (!matchmap.empty()) {
        int rc = wh_MatchMap_append(matchmap, nullptr, errh);

        if (rc != 0) {
            return rc;
        }
    }

    mGTPEncapSink.enableUDPChecksum(doEnableUDPChecksum);
    mDoEnableUnknownTrafficDump = doEnableUnknownTrafficDump;
    return 0;
}

int UPFRouter::initialize(ErrorHandler *) {
    /////////////////////////
    // Configure callbacks //
    /////////////////////////

    mRouter.onGTPv1U_IPv4([this](auto &context) -> bool {
        return this->handleInterceptedGTPv1UTraffic(context);
    });

    mGTPEncapSink.onUnknownUE([this](const NetworkLib::BufferView &ipv4Data) {
        return this->handleIPv4UnknownUE(ipv4Data);
    });

    mRouter.onIPv4PostProcess([this](auto &context) -> bool {
        return this->handleIPv4PostProcess(context);
    });

    mRouter.onNonIPv4(
        [this](auto &context) -> bool { return this->handleNonIPv4(context); });

    mRouter.onFinalProcess([this](auto &context) -> bool {
        return this->handleCommonTraffic(context);
    });

    // DEBUG CODE
    mRouter.onS1APRelevantTraffic([]() { click_chatter("CBK S1AP Traffic"); });

    // Optional callback to print out entries added to the UE map
    // as they are added/updated.
    mRouter.beforeUEMapUpsert([](auto &pair) -> bool {
        std::ostringstream s;
        s << "*** Inserting UE IP: " << pair.first // UE IP address
          << " --> (eNB <-> EPC) " << pair.second  // GTP tunnel endpoints
          << '\n';
        click_chatter("%s", s.str().c_str());

        // Add/update the entry into the UE map.
        return true;
    });

#if 0
    // DEBUG: initialize UEMap
    auto &ueMap = mRouter.getUEMap();

    {
        UPFRouterLib::GTPv1UTunnelInfo ti;

        // Test code
    
        ti.eNBEndPoint.ipAddress = NetworkLib::IPv4Address("192.168.0.177");
        ti.eNBEndPoint.teid = NetworkLib::GTP_TEID::Number(0x00ee0003);

        ti.epcEndPoint.ipAddress = NetworkLib::IPv4Address("192.168.0.167");
        ti.epcEndPoint.teid = NetworkLib::GTP_TEID::Number(0x00000011);

        ueMap[NetworkLib::IPv4Address("45.45.0.10")] = ti;
    }

    {
        UPFRouterLib::GTPv1UTunnelInfo ti;

        // Test code 
        ti.eNBEndPoint.ipAddress = NetworkLib::IPv4Address("192.168.0.177");
        ti.eNBEndPoint.teid = NetworkLib::GTP_TEID::Number(0x00f70003);

        ti.epcEndPoint.ipAddress = NetworkLib::IPv4Address("192.168.0.167");
        ti.epcEndPoint.teid = NetworkLib::GTP_TEID::Number(0x00000013);

        ueMap[NetworkLib::IPv4Address("45.45.0.11")] = ti;
    }

    // Print out the map
    String s = rh_UEMap(nullptr);
    click_chatter("%s",s.c_str());
#endif

    return 0;
}

Packet *UPFRouter::simple_action_extended(Packet *p, int inputPort) {

    click_chatter("got packet %p from port %d", p, inputPort);

    try {
        // Build a BufferView out of the Click Packet. We expect a
        // packet with IPv4 data.
        NetworkLib::BufferView buffer =
            NetworkLib::BufferView::makeNonOwningBufferView(p->data(),
                                                            p->length());

        NetworkLib::ContextUserData userData = {};

        userData.ptrUserData = reinterpret_cast<void *>(p);

        // Save the Click input port in the context.
        // (see also getClickInputPortFromContext())
        userData.intUserData = inputPort;

        // Push it down through our router.
        //
        // The router callbacks will then push the packet down to the
        // appropriate port.
        mRouter.consumeIPv4Packet(buffer, userData);

    } catch (std::exception &e) {
        click_chatter("*** UPFRouter::simple_action(Packet *): "
                      "caught exception: %s",
                      e.what());
    }

    // Note: packet killing will be done in our callbacks
    return nullptr;
}

bool UPFRouter::handleInterceptedGTPv1UTraffic(
    NetworkLib::EthPacketProcessor::Context &context) {

    click_chatter("in gtpv1utraffic");

    // Let's have a look at the IPv4 traffic encapsulated in GTPv1-U.
    //
    // Since it is encapsulated in GTPv1-U, we assume it occurs
    // between a eNodeB and a EPC, from/to some UE (actually, we check
    // this by looking at which Click's port it came in -- port 0 is
    // supposed to carry traffic only from/to the EPC, while port 1 is
    // supposed to carry traffic only from/to a eNodeB).
    //
    // The UE may be a known one, or an unknown one.
    const NetworkLib::BufferView encapIpv4Data =
        context.gtpv1uDecoder->getData();
    const NetworkLib::IPv4Decoder ipv4DecoderEncap(encapIpv4Data);

    bool rc;
    UPFRouterLib::Router::UEMap_t::iterator it;

    if (packetCameFromENodeB(context) &&
        ((std::tie(it, rc) = mRouter.isIPv4TrafficFromKnownUE(ipv4DecoderEncap),
          rc))) {

        // This is IPv4 traffic encapsulated in GTPv1-U actually
        // **from** a known UE and coming from Click port 1 (i.e. from
        // an actual eNodeB).

        {
            // Workaround for changing TEIDs: extract the TEID
            // and update UEmap if it is not the same
            auto newTeid = context.gtpv1uDecoder->getTEID();

            if (it->second.epcEndPoint.teid != newTeid) {

                std::ostringstream ostr;
                ostr << "Updating EPC GTP TEID for UE "
                     << ipv4DecoderEncap.getSrcAddress() << " from "
                     << it->second.epcEndPoint.teid << " to " << newTeid;
                click_chatter("%s", ostr.str().c_str());

                it->second.epcEndPoint.teid = newTeid;
            }
        }

        // If the encapsulated traffic also matches some rule in
        // MatchMap, the encapsulated IPv4 traffic should be
        // decapsulated and redirected (unchanged) to some VNF through
        // Click port 2.

        if (mRuleMatcher.match(ipv4DecoderEncap)) {
            // Make a (new) Click Packet out of the (now decapsulated)
            // IPv4 data...
            Packet *p1 = makeWritablePacket(encapIpv4Data);

            if (p1) {
                // Take the original packet (GTPv1-U) and kill it.
                Packet *p =
                    reinterpret_cast<Packet *>(context.userData.ptrUserData);
                if (p) {
                    click_chatter("Killing packet 1");
                    p->kill();
                    context.userData.ptrUserData = nullptr;
                }

                // ... and push the new Packet down Click's output
                // port 2 (for local processing)
                checked_output_push(2, p1);
            }

            // Ensure it doesn't get post-processed (redundant, as we
            // don't allow further processing by returning false).
            context.postProcessIPv4 = false;
            return false;
        }

    } else if (packetCameFromEPC(context) &&
               (std::tie(it, rc) =
                    mRouter.isIPv4TrafficToKnownUE(ipv4DecoderEncap),
                rc)) {

        // This is IPv4 traffic encapsulated in GTPv1-U **to** a known
        // UE and coming from Click port 0 (i.e. from the EPC).

        {
            // Workaround for changing TEIDs: extract the TEID
            // and update UEmap if it is not the same
            auto newTeid = context.gtpv1uDecoder->getTEID();

            if (it->second.eNBEndPoint.teid != newTeid) {

                std::ostringstream ostr;
                ostr << "Updating eNodeB GTP TEID for UE "
                     << ipv4DecoderEncap.getDstAddress() << " from "
                     << it->second.eNBEndPoint.teid << " to " << newTeid;
                click_chatter("%s", ostr.str().c_str());

                it->second.eNBEndPoint.teid = newTeid;
            }
        }

        if (mRuleMatcher.match(ipv4DecoderEncap)) {

            // Make a (new) Click Packet out of the (now decapsulated)
            // IPv4 data...
            Packet *p1 = makeWritablePacket(encapIpv4Data);

            if (p1) {
                // Take the original packet (GTPv1-U) and kill it.
                Packet *p =
                    reinterpret_cast<Packet *>(context.userData.ptrUserData);
                if (p) {
                    click_chatter("Killing packet 2");
                    p->kill();
                    context.userData.ptrUserData = nullptr;
                }

                // ... and push the new Packet down Click output port
                // 2 (for local processing)
                checked_output_push(2, p1);
            }

            // Ensure it doesn't get post-processed (redundant, as we
            // don't allow further processing by returning false).
            context.postProcessIPv4 = false;
            return false;
        }
    }

    // Otherwise, this is GTPv1-U traffic from/to an unknown UE and/or not
    // matching any entry in MatchMap. Forward "as-is" to its original
    // destination.

    // Ensure it doesn't get post-processed, but allow final
    // processing so it is forwarded "as-is".
    context.postProcessIPv4 = false;
    return true;
}

bool UPFRouter::handleIPv4PostProcess(
    NetworkLib::EthPacketProcessor::Context &context) {

    click_chatter("in ipv4postprocess");

    // This is called on plain IPv4 traffic that wasn't processed
    // before:
    //
    // * S1AP traffic explicitly skips this processing by setting
    //   'context.postProcessIPv4' to false;
    //
    // * GTPv1-U traffic from/to an unknown UE skips this processing
    //   by setting 'context.postProcessIPv4' to false as well.
    //
    // Therefore: this is either:
    //
    // * plain IPv4 traffic phisically coming from some VNF, but
    //   figuring as destined either to a known UE or to the EPC of a
    //   known UE (actually, we look at the source address in this
    //   latter case, checking if it comes from a known UE);
    //
    // * other IPv4 traffic.

    NetworkLib::ContextUserData outputUserData;
    mGTPEncapSink.consumeIPv4Packet(context.ipv4Decoder->getIPv4Packet(),
                                    outputUserData);

    // Note: the last packet written out by mGTPEncapSink can be empty
    //       because we instructed it to write out empty packets on
    //       unknown UEs, via the onUnknownUE callback returning true.
    NetworkLib::BufferView ipv4Packet = mIPv4Tap.getLastIPv4Packet();

    if (ipv4Packet.empty()) {
        // Unknown UE? This is other IPv4 traffic (not encapsulated in
        // GTPv1-U) between a eNodeB and a EPC, therefore it is
        // unrelated to an UE.

        if (packetCameFromEPC(context) || packetCameFromENodeB(context)) {
            // Do nothing and forward it as it is.
            return true;
        } else {

            // If it came from elsewhere, just try to push it out on Click
            // port 3, as we weren't supposed to receive this, and forget
            // it. If port 3 is not connected, the traffic is just dropped
            // (and the Click's Packet is killed).

            Packet *p =
                reinterpret_cast<Packet *>(context.userData.ptrUserData);
            if (p) {
                // checked_output_push(3, p);
                click_chatter("again, shoulnt be here...");

                // In any case, the Packet will be killed by somebody
                // else.
                context.userData.ptrUserData = nullptr;
            }

            // In any case, stop processing here.
            return false;
        }
    }

    // Otherwise, this is a packet from/to a known UE, now properly
    // encapsulated in GTPv1-U.

    // Make a (new) Click Packet out of the given BufferView...
    Packet *p1 = makeWritablePacket(ipv4Packet);

    if (p1) {
        // Take the original packet and kill it.
        Packet *p = reinterpret_cast<Packet *>(context.userData.ptrUserData);
        if (p) {
            click_chatter("Killing packet 3");
            p->kill();
            context.userData.ptrUserData = nullptr;
        }

        // The GTPv1UEncapSink saved here if the encapsulated packet
        // is directed to the EPC (0) or to a eNodeB (1) -- so we use
        // it as Click's output port.
        int outputPort = outputUserData.intUserData;

        // ... and push the new Packet down Click
        checked_output_push(outputPort, p1);
    } else {
        click_chatter(
            "UPFRouter::handleIPv4PostProcess(NetworkLib::"
            "EthPacketProcessor::Context &): can't make a new WritablePacket!");
    }

    return false;
}

bool UPFRouter::handleNonIPv4(
    NetworkLib::EthPacketProcessor::Context &context) {

    click_chatter("in nonipv4");

    // This is not IPv4 traffic.
    //
    // Note: this should be impossible, as we are supposed to deal
    //       only with IPv4 traffic.
    //
    // Just try to push it out on Click port 3, as we weren't
    // supposed to receive this, and forget it. If port 3 is not
    // connected, the traffic is just dropped (and the Click's
    // Packet is killed).
    Packet *p = reinterpret_cast<Packet *>(context.userData.ptrUserData);
    if (p) {
        click_chatter("shouldnt be here...");
        // checked_output_push(3, p);

        // In any case, the Packet will be killed by somebody
        // else.
        context.userData.ptrUserData = nullptr;
    }

    // In any case, stop processing here.
    return false;
}

bool UPFRouter::handleIPv4UnknownUE(const NetworkLib::BufferView &ipv4Data) {

    click_chatter("in unknownue");

    if (mDoEnableUnknownTrafficDump) {
        click_chatter("myedit");
        click_chatter("*** Plain IPv4 traffic to/from unknown UE");
        DumperLib::IPv4Dumper dumper(ipv4Data);
        std::ostringstream s;
        s << dumper;
        click_chatter("%s", s.str().c_str());
    }

    // Return true so mGTPEncapSink sends down an empty packet to
    // destination (this is intercepted later).
    return true;
}

bool UPFRouter::handleCommonTraffic(

    NetworkLib::EthPacketProcessor::Context &context) {

    click_chatter("in commontraffic");

    // If it came from Click port 1, it goes to port 0 and vice-versa.
    int outputPort = 1 - getClickInputPortFromContext(context);
    click_chatter("out port is %d", outputPort);

    // Take the original Click Packet we received from the context...
    Packet *p = reinterpret_cast<Packet *>(context.userData.ptrUserData);
    if (p) {
        // ... and push it out on the matching port
        checked_output_push(outputPort, p);
    }

    click_chatter("exiting commontraffic");

    return false;
}

//////////////////////////////////////////////////////////////////////

void UPFRouter::add_handlers() {
    add_read_handler("uemap", read_handler_UEMap);
    add_read_handler("matchmap", read_handler_MatchMap);

    add_write_handler("matchmapinsert", write_handler_MatchMap_insert);
    add_write_handler("matchmapappend", write_handler_MatchMap_append);
    add_write_handler("matchmapdelete", write_handler_MatchMap_delete);
    add_write_handler("matchmapclear", write_handler_MatchMap_clear);
    add_write_handler("enableudpchecksum", write_handler_enableUDPChecksum);
    add_write_handler("enableunknowntrafficdump",
                      write_handler_enableUknownTrafficDump);
}

String UPFRouter::rh_UEMap(void *) {
    std::ostringstream res;

    for (auto const &it : mRouter.getUEMap()) {

        res << it.first << ',' << it.second.eNBEndPoint.ipAddress << ','
            << NetworkLib::asHex32(it.second.eNBEndPoint.teid) << ','
            << it.second.epcEndPoint.ipAddress << ','
            << NetworkLib::asHex32(it.second.epcEndPoint.teid) << '\n';
    }

    return String(res.str().c_str());
}

String UPFRouter::rh_MatchMap(void *) {
    std::ostringstream res;

    int i = 0;
    for (auto const &it : mRuleMatcher.getRules()) {
        res << ++i << ',' << it << '\n';
    }

    return String(res.str().c_str());
}

int UPFRouter::wh_MatchMap_insert(const String &str, void *,
                                  ErrorHandler *errh) {
    String entry = str;
    String nextWord;
    int position;

    nextWord = upf_cp_shift_commavec(entry);

    if (!IntArg().parse(nextWord, position)) {
        errh->error(
            "Error while parsing MatchMap: |%s| is not a valid position",
            nextWord.c_str());
        return -1;
    }

    if (position < 0) {
        errh->error(
            "Error while parsing MatchMap: |%s| is not a valid position (< 0)",
            nextWord.c_str());
        return -1;
    }

    nextWord = upf_cp_shift_commavec(entry);

    UPFRouterLib::MatchingRule rule;

    try {
        UPFRouterLib::MatchingRule newRule(std::string(nextWord.c_str()));
        rule = newRule;
        mRuleMatcher.addRule(rule, static_cast<std::size_t>(position));

    } catch (const std::exception &e) {
        errh->error("Error while parsing MatchMap: |%s| is not a valid rule",
                    nextWord.c_str());
        return -1;
    }

    return 0;
}

int UPFRouter::wh_MatchMap_append(const String &str, void *vparam,
                                  ErrorHandler *errh) {
    String entry = str;
    String nextWord;

    (void)vparam;

    while (true) {

        nextWord = upf_cp_shift_commavec(entry);

        if (nextWord.length() == 0) {
            // No next word
            break;
        }

        UPFRouterLib::MatchingRule rule;

        try {
            UPFRouterLib::MatchingRule newRule(std::string(nextWord.c_str()));
            rule = newRule;
            mRuleMatcher.addRule(rule, UPFRouterLib::RuleMatcher::endPosition);

        } catch (const std::exception &e) {
            errh->error(
                "Error while parsing MatchMap: |%s| is not a valid rule",
                nextWord.c_str());
            return -1;
        }
    }

    return 0;
}

int UPFRouter::wh_MatchMap_delete(const String &str, void *vparam,
                                  ErrorHandler *errh) {
    String entry = str;
    String nextWord;
    int position;

    (void)vparam;

    nextWord = upf_cp_shift_commavec(entry);

    if (!IntArg().parse(nextWord, position)) {
        errh->error(
            "Error while parsing MatchMap: |%s| is not a valid position",
            nextWord.c_str());
        return -1;
    }

    if (position < 0) {
        errh->error(
            "Error while parsing MatchMap: |%s| is not a valid position (< 0)",
            nextWord.c_str());
        return -1;
    }

    try {
        mRuleMatcher.delRule(static_cast<std::size_t>(position));

    } catch (const std::exception &e) {
        errh->error(
            "Error while parsing MatchMap: |%s| is not a valid position",
            nextWord.c_str());
        return -1;
    }

    return 0;
}

int UPFRouter::wh_MatchMap_clear(const String &, void *, ErrorHandler *errh) {
    try {
        mRuleMatcher.clearRules();

    } catch (const std::exception &e) {
        errh->error("Error while clearning MatchMap");
        return -1;
    }

    return 0;
}

int UPFRouter::wh_enableUPDChecksum(const String &str, void *,
                                    ErrorHandler *errh) {

    bool doEnableUDPChecksum = true;

    if (!BoolArg().parse(str, doEnableUDPChecksum)) {
        errh->error("Error while parsing enableudpchecksum: |%s| is not a "
                    "valid true/false value",
                    str.c_str());
        return -1;
    }

    mGTPEncapSink.enableUDPChecksum(doEnableUDPChecksum);
    return 0;
}

int UPFRouter::wh_enableUnknownTrafficDump(const String &str, void *,
                                           ErrorHandler *errh) {

    bool doEnableUnknownTrafficDump = true;

    if (!BoolArg().parse(str, doEnableUnknownTrafficDump)) {
        errh->error("Error while parsing enableunknowntrafficdump: |%s| is not "
                    "a valid true/false value",
                    str.c_str());
        return -1;
    }

    mGTPEncapSink.enableUDPChecksum(doEnableUnknownTrafficDump);
    return 0;
}

// clang-format off
CLICK_ENDDECLS
EXPORT_ELEMENT(UPFRouter)
// clang-format on
