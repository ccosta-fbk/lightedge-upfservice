require(package "lvnfs2"); ControlSocket("TCP", 7777);

upfr :: UPFRouter()

kt :: KernelTun(ADDR 10.0.0.2/24, DEVNAME tun0);

s_client :: Socket("UDP", ADDR REMOTE_ADDR, PORT 5555);

s_server :: Socket("UDP", ADDR 0.0.0.0, PORT 5555);

ktgw :: KernelTun(ADDR 10.90.90.1/24, DEVNAME tun1);


kt
//        -> Print("from kt[0] to [0]CheckIPHeader", MAXLENGTH 0)
        -> CheckIPHeader()
        -> IPReassembler()
        -> [0]upfr;

upfr[0]
       -> Print("from upfr[0] to [0]kt", MAXLENGTH 0)
       -> CheckIPHeader()
       -> IPFragmenter(1500, VERBOSE true)
       -> kt;


s_server
//        -> Print("from s_server[0] to [0]CheckIPHeader", MAXLENGTH 0)
        -> CheckIPHeader()
//        -> Print("from CheckIPHeader[0] to [0]Print", MAXLENGTH 0)
        -> IPReassembler()
//        -> Print("from Print[0] to [1]upfr", MAXLENGTH 9000)
        -> [1]upfr;

upfr[1]
//        -> Print("from upfr[1] to [0]s_client", MAXLENGTH 9000)
        -> CheckIPHeader()
        -> IPFragmenter(1500, VERBOSE true)
        -> CheckIPHeader()
        -> s_client;


ktgw
//        -> Print("from ktgw[0] to [2]upfr", MAXLENGTH 0)
        -> CheckIPHeader()
        -> IPReassembler()
        -> [2]upfr;

upfr[2]
//        -> Print("from upfr[2] to [0]ktgw", MAXLENGTH 0)
        -> CheckIPHeader()
        -> IPFragmenter(1500, VERBOSE true)
        -> CheckIPHeader()
        -> ktgw;

