# Sipline

Simple plain C SIP package sniffer designed to run on routers. The main aim of this project is to compile and run this
simple application on linux routers with ssh/telnet access.

The code is not really very modular designed yet, but this is right now just a POC version. We sniff
via [libpcap](https://www.tcpdump.org/) the [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) traffic and
filter just for `INVITE`, `CANCEL` and `TAKEOFF` answers (not yet implemented). So we know precisely when the phone is
ringing. For filtering the [SIP](https://en.wikipedia.org/wiki/Session_Initiation_Protocol)
traffic, [libosip2](https://www.gnu.org/software/osip/) is used.

We send this information to an HTTP/S API endpoint via [libcurl](https://curl.se/libcurl/).

Maybe you have already observed what the script is used for -> to build a external bell
for [VoIP](https://en.wikipedia.org/wiki/Voice_over_IP) phones.

# Preperation

You will need following packages on your system:

* [cmake](https://cmake.org/)
* [libpcap](https://www.tcpdump.org/)
* [libosip2](https://www.gnu.org/software/osip/)
* [libcurl](https://curl.se/libcurl/)

If you are on a x86 host, you should be able to install everything except libosip2 via your favourite package manager.
You can also try to install the libs by installing curl and tcpdump. For debian distros, please install the `-dev`
packages too, RHEL are `-devel`.

For MIPS arch, which is this repo designed, you can either compile the libs from source, which is quite complicated.
Simplier is to get [entware](https://github.com/Entware/Entware) up and running and run:

```bash
> opkg upgrade
> opkg install cmake
> opkg install libcurl
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
> root@DD-WRT:/# ls opt/include/curl/
curl.h           easy.h           multi.h          stdcheaders.h    typecheck-gcc.h
curlver.h        mprintf.h        options.h        system.h         urlapi.h

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
> root@DD-WRT:/opt/include# ls /opt/lib/ | grep 'curl\|pcap\|sip'
...
libcurl.so
libcurl.so.4
libcurl.so.4.6.0
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
#define
BPF_SIP_FILTER "(port 6050) and (udp)"
// define API endpoint to send SIP signals to
#define
TARGET_URL "http://<host>:2711/ringBell"
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

