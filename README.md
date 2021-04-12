# Sipline

Simple SIP package sniffer writtin in plain C. The aim of this application is to watch incomming traffic on the nic and send out a ping message to your target host if an [SIP](https://en.wikipedia.org/wiki/Session_Initiation_Protocol) `INVITE` occur.

Because the `INVITE` signals an incommming call, the remote server listening for the ping request can react on this event, for example playing a tone. This would allow us to build a external bell for your [VoIP](https://en.wikipedia.org/wiki/Voice_over_IP) telefon.

The project is memory optimized and should run on any linux based router with at least 8MB main memory.
For capturing, [libpcap](https://www.tcpdump.org/) is utilized and for the parsing [libosip2](https://www.gnu.org/software/osip/). Because [libcurl](https://curl.se/libcurl/) is quite heavy, we have implemented your own ping service via [pthread](https://man7.org/linux/man-pages/man7/pthreads.7.html) and [tcp](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) sockets.

# Preperation

You will need following packages on your system:

* [cmake](https://cmake.org/)
* [libpcap](https://www.tcpdump.org/)
* [libosip2](https://www.gnu.org/software/osip/)

If you are on a x86 host, you should be able to install everything except libosip2 via your favourite package manager.
You can also try to install the libs by installing curl and tcpdump. For debian distros, please install the `-dev`
packages too, RHEL are `-devel`.

For MIPS arch, which is this repo designed, you can either compile the libs from source, which is quite complicated.
Simplier is to get [entware](https://github.com/Entware/Entware) up and running and run:

```bash
> opkg upgrade
> opkg install cmake
> opkg install libpcap
# > opkg install libosip2
```

Please find here a tutorial how to get [entware](https://github.com/Entware/Entware) up and running
on [DD-WRT](https://dd-wrt.com/) [here](https://wiki.dd-wrt.com/wiki/index.php/Installing_Entware).

Unfortunately [libosip2](https://www.gnu.org/software/osip/) is not yet available to install
via [opkg](https://en.wikipedia.org/wiki/Opkg), maybe I will try to add it later. However, feel free to compile it from
source as shown in the `INSTALL` file. I did the compilation directly on the router, because it's not that huge. Ensure
if you do no the router to set the correct install `prefix` and install first `gcc` via `opkg install gcc`.

```bash
> git clone git://git.savannah.gnu.org/osip.git
> cd osip
> ./configure
> make
> make install --prefix /opt/
```

Please check that all the header files are present on the system as well as the libraries. For
example [DD-WRT](https://dd-wrt.com/) router stores everything into /opt/ subdir. It should look similar to this one
here:

```bash
# header files
> root@DD-WRT:/# ls opt/includepcap/
bluetooth.h       compiler-tests.h  ipnet.h           pcap-inttypes.h   socket.h
bpf.h             dlt.h             namedb.h          pcap.h            usb.h
can_socketcan.h   funcattrs.h       nflog.h           sll.h             vlan.h

> root@DD-WRT:/# ls opt/include/osip2/
osip.h         osip_condv.h   osip_dialog.h  osip_fifo.h    osip_mt.h      osip_time.h

> root@DD-WRT:/# ls opt/includeosipparser2/
headers         osip_const.h    osip_list.h     osip_message.h  osip_port.h     sdp_message.h
osip_body.h     osip_headers.h  osip_md5.h      osip_parser.h   osip_uri.h

# libraries
> root@DD-WRT:/opt/include# ls /opt/lib/ | grep 'pcap\|sip'
...
libosip2.a
libosip2.la
libosip2.so
libosip2.so.14
libosip2.so.14.0.0
libosipparser2.a
libosipparser2.la
libosipparser2.so
libosipparser2.so.14
libosipparser2.so.14.0.0
libpcap.so
libpcap.so.1
libpcap.so.1.9.1
...
```

# Configuration

Currently all the configuration is done via the header file `./include/sipline.h`.

```c
// BPF filter expression for SIP messages -> port may vary
#define BPF_SIP_FILTER "(port 6050) and (udp)"

// Backend Server connection info
// please use IP address, we have not implemented host name resolution yet
#define PING_HOST "127.0.0.1"
#define PING_PORT 2711
#define PING_QUERY "bing/bell"
```

Please just check if the PORT is correct for your SIP provider. Seems like 6050 is more exotic, but works for me. Also
define the target host, we will send a JSON like the one below to this endpoint.

```json
{
  "type": 1,
  "from": "andreas.karner[at]student.tugraz.at",
  "to": "tooQuitePhone"
}
```

# Installation

After installing all the libs, the hard stuff is done. Just clone and build the app.

```bash
> git clone https://github.com/whati001/sipline
> mkdir -p build && cd build
> cmake ..
> make
```

All done.

# Open Stuff

Current only pcap file analysis is supported. This is mainly due to the fact that I have no access to the SIP traffic
yet. But live sniffing feature get added shortly.

