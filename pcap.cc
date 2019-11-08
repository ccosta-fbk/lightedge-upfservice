/*
 * pcap.{cc,hh} -- Click element for reading/writing from/to .pcap files
 */

// clang-format off
// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
#include <click/standard/scheduleinfo.hh>
// clang-format on

#include "pcap.hh"

#include <click/error.hh>
#include <click/args.hh>
#include <click/router.hh>

// clang-format off
CLICK_DECLS
// clang-format on

/////////////////////////
// UPFRouterPcapReader //
/////////////////////////

int UPFRouterPcapReader::configure(Vector<String> &conf, ErrorHandler *errh) {

    if (Args(conf, this, errh)
            .read_mp("FILENAME", StringArg(), mFilename)
            .read_p("REPEATS", mRepeats)
            .complete() < 0) {
        errh->error("Error while parsing arguments!");
        return -1;
    }

    return 0;
}

int UPFRouterPcapReader::initialize(ErrorHandler *errh) {
    std::string fileName(mFilename.c_str());
    try {
        errh->message("Reading from file %s (repeats: %u)", fileName.c_str(),
                      mRepeats);
        mEthReader =
            std::make_unique<NetworkLib::PcapEthReader>(fileName, mRepeats);
    } catch (std::exception &e) {
        errh->error("%s", e.what());
        return -1;
    }

    if (output_is_push(0)) {
        ScheduleInfo::join_scheduler(this, &mTask, errh);
    }

    mActive = true;

    return 0;
}

WritablePacket *UPFRouterPcapReader::doRead() {

    if (!mEthReader->packetAvailable()) {
        router()->please_stop_driver();
        return nullptr;
    }

    // Prepare a packet
    const uint32_t pcap_snaplen = mEthReader->getSnapLen();

    WritablePacket *p =
        Packet::make(0, // No headroom
                     (const unsigned char *)0, pcap_snaplen, 60);
    if (!p) {
        router()->please_stop_driver();
        return nullptr;
    }

    try {

        // Get a BufferWritableView on the packet buffer
        NetworkLib::BufferWritableView bufferWritableView =
            NetworkLib::BufferWritableView::makeNonOwningBufferWritableView(
                p->data(), p->length());
        // Read in the pcap record
        NetworkLib::BufferWritableView ethData =
            mEthReader->getEthPacket(bufferWritableView);

        const uint32_t record_len = ethData.size();

        // Shrink the packet buffer to the record length
        p->take(pcap_snaplen - record_len);

    } catch (std::exception &e) {
        p->kill();
        router()->please_stop_driver();
        return nullptr;
    }

    // That's it.
    return p;
}

Packet *UPFRouterPcapReader::pull(int) {
    WritablePacket *p = doRead();
    return p;
}

bool UPFRouterPcapReader::run_task(Task *) {
    if (!mActive) {
        return false;
    }

    WritablePacket *p = doRead();

    if (p) {
        output(0).push(p);
    }

    mTask.fast_reschedule();
    return (p != nullptr);
}

//////////////////////
// UPFRouterPcapWriter //
//////////////////////

int UPFRouterPcapWriter::configure(Vector<String> &conf, ErrorHandler *errh) {
    String encap_type("ETHER");

    if (Args(conf, this, errh)
            .read_mp("FILENAME", StringArg(), mFilename)
            .read_p("ENCAP", WordArg(), encap_type)
            .complete() < 0) {
        errh->error("Error while parsing arguments!");
        return -1;
    }

    if (encap_type == "ETHER") {
        mWriteIPv4 = false;
    } else if (encap_type == "IP") {
        mWriteIPv4 = true;
    } else {
        errh->error("bad encapsulation type");
        return -1;
    }

    return 0;
}

int UPFRouterPcapWriter::initialize(ErrorHandler *errh) {
    std::string fileName(mFilename.c_str());
    try {
        errh->message("Writing to file %s", fileName.c_str());
        mEthWriter = std::make_unique<NetworkLib::PcapEthWriterPlus>(fileName);
    } catch (std::exception &e) {
        errh->error("%s", e.what());
        return -1;
    }

    if (input_is_pull(0)) {
        ScheduleInfo::join_scheduler(this, &mTask, errh);
    }

    mActive = true;

    return 0;
}

void UPFRouterPcapWriter::doWrite(Packet *p) {
    if (p == nullptr) {
        // No packet to write
        return;
    }

    try {

        // Get a BufferView on the packet buffer
        NetworkLib::BufferView bufferView =
            NetworkLib::BufferView::makeNonOwningBufferView(p->data(),
                                                            p->length());

        if (mWriteIPv4) {
            // Write out the data as IPv4
            mEthWriter->consumeIPv4Packet(bufferView);
        } else {
            // Write out the data as Ethernet
            mEthWriter->consumeEthPacket(bufferView);
        }

    } catch (std::exception &e) {
        click_chatter(
            "*** UPFRouterPcapWriter:doWrite(Packet *): caught exception: %s",
            e.what());
    }
}

void UPFRouterPcapWriter::push(int, Packet *p) {
    doWrite(p);

    // In any case, drop the packet once it's written.
    if (p) {
        p->kill();
    }
}

Packet *UPFRouterPcapWriter::pull(int) {
    Packet *p = input(0).pull();
    if (p) {
        doWrite(p);
    } else {
        router()->please_stop_driver();
    }

    return p;
}

bool UPFRouterPcapWriter::run_task(Task *) {
    if (!mActive) {
        return false;
    }

    Packet *p = input(0).pull();
    if (p) {
        doWrite(p);
        p->kill();
    }

    mTask.fast_reschedule();
    return (p != nullptr);
}

// clang-format off
CLICK_ENDDECLS
EXPORT_ELEMENT(UPFRouterPcapReader)
EXPORT_ELEMENT(UPFRouterPcapWriter)
// clang-format on
