// Tin based pSniffer (libtin)
#include <iostream>
#include<tins/tins.h>
using namespace std;
using namespace Tins;

bool callback(const PDU &pdu) {
  const IP &ip = pdu.rfind_pdu<IP>();
  const TCP &tcp = pdu.rfind_pdu<TCP>();
  cout << ip.src_addr()<< ':' << tcp.sport()<< " ->"
       << ip.dst_addr()<< ':' << tcp.dport()<< endl;

  return 1;
}

int main() {
  // sniff on interface wlo1
  // max packet size 2000 bytes
  Sniffer sniffer ("wlo1", 2000);
  sniffer.sniff_loop(callback);
}

