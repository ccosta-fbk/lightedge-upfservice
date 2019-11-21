require(package "upf"); ControlSocket("TCP", 7777);

upfr :: UPFRouter()

kt :: KernelTun(ADDR 10.0.0.2/24, DEVNAME tun0);

s_client :: Socket("UDP", ADDR REMOTE_ADDR, PORT 5555);

s_server :: Socket("UDP", ADDR 0.0.0.0, PORT 5555);

ktgw :: KernelTun(ADDR 10.90.90.1/24, DEVNAME tun1);


kt
        -> CheckIPHeader()
        -> IPReassembler()
        -> [0]upfr;

upfr[0]
       -> Print("from upfr[0] to [0]kt", MAXLENGTH 0)
       -> CheckIPHeader()
       -> IPFragmenter(1500, VERBOSE true)
       -> kt;


s_server
        -> CheckIPHeader()
        -> IPReassembler()
        -> [1]upfr;

upfr[1]
        -> CheckIPHeader()
        -> IPFragmenter(1500, VERBOSE true)
        -> CheckIPHeader()
        -> s_client;


ktgw
        -> CheckIPHeader()
        -> IPReassembler()
        -> [2]upfr;

upfr[2]
        -> CheckIPHeader()
        -> IPFragmenter(1500, VERBOSE true)
        -> CheckIPHeader()
        -> ktgw;

