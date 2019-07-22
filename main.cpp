#include <pcap.h>
#include <stdio.h>

#define EtherNext 13
#define ipNext 54
#define ipaddress 26
#define portnumber 34

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void ether(const u_char* a) {
    int cursor = 0;
    printf("D MAC : ");
    for(int i=0;i<6;i++) {
        printf("%x ",a[cursor]);
        cursor++;
    }
    printf("\n");

    printf("S MAC : ");
    for(int i=0;i < 6;i++) {
        printf("%x ",a[cursor]);
        cursor++;
    }
    printf("\n");

    u_int16_t b = a[cursor] << 8;
    u_int16_t check_ether = b + a[cursor+1];
    printf("Ehter Type Value : 0x%04x\n",check_ether);
    printf("Check Ether Type : ");
    if(check_ether == 0x0800) {
        printf("IP");
        printf("\n");
        int cursor3 = ipaddress;
        printf("S IP : ");
        for(int i=0;i < 4; i++) {
            if(i==3) {
                printf("%d",a[cursor3]);
            }
            else {
                printf("%d.",a[cursor3]);
            }
            cursor3++;
        }
        printf("\n");
        printf("D IP : ");
        for(int i=0;i < 4;i++){
            if(i==3) {
                printf("%d",a[cursor3]);
            }
            else {
                printf("%d.",a[cursor3]);
            }
            cursor3++;
        }
        printf("\n");
    }
    else if (check_ether == 0x0806) {
        printf("ARP");
    }
    else if (check_ether == 0x8100) {
        printf("VLan");
    }
    else {
        printf("NOT Found");
    }
    printf("\n");
}

void ip(const u_char* b) {
    int cursor2 = ipNext;

    printf("Protocol : ");
    printf("0x%02x\n", b[EtherNext + 10]);
    printf("Check IP Type : ");
    if (b[EtherNext + 10] == 0x06) {
        printf("TCP\n");
        printf("Start Tcp Data: %02x\n",b[cursor2]);
        printf("TCP Data : ");
        for(int i=0;i<10;i++) {
            if(b[cursor2] != 0x00) {
                printf("%02x ",b[cursor2]);
                }
            cursor2++;
            }
        printf("\n");
        int cursor4 = portnumber;
        u_int16_t first_sport = b[cursor4] << 8;
        u_int16_t sport = first_sport + b[cursor4+1];
        u_int16_t first_dport = b[cursor4+2] << 8;
        u_int16_t dport = first_dport + b[cursor4+3];

        printf("Sport : %d\n",sport);
        printf("Dport : %d\n",dport);
        }
    else if (b[EtherNext + 10] == 0x11) {
        printf("UDP");
    }
    else {
        printf("NOT Found");
    }
    printf("\n");
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    ether(packet);
    ip(packet);
  }

  pcap_close(handle);
  return 0;
}
