#include "skel.h"
#include <string.h>
#include <inttypes.h>
#include "queue.h"
#include "list.h"


//tabela de rutare
struct  route_table *routeTable;
//dimensiune tabela de rutare
int routeTableSize;
//coada pentru mesaje
queue q;


//tabela arp
struct arpEntry *arpTable;
//dimensiunea tabelei arp
int arpTableSize;

struct route_table {
    uint32_t mask;
    uint32_t nextHop;
    uint32_t prefix;
    int interface;
}__attribute__((packed));

struct arpEntry {
    __u32 ip;
    uint8_t mac[6];
};

int cmpFunc(const void *a, const void *b)
{
    uint32_t pA = htonl(( (struct route_table*) a)->prefix); //prefix prim elem
    uint32_t mA = htonl(( (struct route_table*) a)->mask);//mask prim elem
    uint32_t pB = htonl(( (struct route_table*) b)->prefix);//prefix 2-nd elem
    uint32_t mB = htonl(( (struct route_table*) b)->mask);//mask 2-nd elem

    //Daca prefixele sunt egale
    if (pA == pB)
    {
        //verifica dupa mask
        return (int)(mB - mA);
        //daca nu sunt egale verifica dupa prefix
    } else return (int)(pA - pB);
}
//cautam best match arp
struct arpEntry *get_arp_entry(__u32 ip) {
    for (int i = 0; i < arpTableSize; ++i)
    {
        if (arpTable[i].ip == ip)
            return &arpTable[i];
    }
    return NULL;
}

void createRouteTable()
{
    FILE *path;
    char line[64];
    path = fopen("rtable.txt","r");

    //initializam tabela te rutare
    routeTable = malloc(sizeof(struct route_table) * 69420);

    /*citesc linie cu linie din fisier
     si initializez tabela de rutare*/
    int i = 0;
    char* token;
    // Citeste in path caracterul "\n" si muta pointerul din path catre urmatorul caracter
    while((fscanf(path, "%[^\n]",line)) != EOF){
        // pentru ca fscanf sa nu se opreasca din citit dupa ce a atins \n
        fgetc(path);
        token = strtok(line, " ");
        routeTable[i].prefix = inet_addr(token); //setez prefix-ul
        token = strtok(NULL, " ");
        routeTable[i].nextHop = inet_addr(token);//setez ip next hop-ului
        token = strtok(NULL, " ");
        routeTable[i].mask = inet_addr(token);//setez mask-ul
        token = strtok(NULL, " ");
        routeTable[i].interface = atoi(token);//setez nr interfetei;
        i++;
    }
    //dimensiune tabela
    routeTableSize = i;
}

struct route_table *binarySearchHelper(__u32 dest_ip , int index){
    //cauta adresa cu cel mai mare mask
    while ((routeTable[index - 1].prefix == routeTable[index].prefix)
    && (index > 0 )){
        index--;
    }
    return routeTable + index;
}

struct route_table *binarySearch(int left, int right, __u32 dest_ip) {

    while (right >= left)
    {
        int middle = left + (right - left) / 2;
        //verifica daca coincide adresa cautata cu o adresa din tabel
        if ((routeTable[middle].mask & dest_ip) == routeTable[middle].prefix){
            //verifica daca mai exista adrese care coincid si alege pe cea cu mask-a mai mare
            return binarySearchHelper(htonl(dest_ip), middle);
            //typical binarySearch logic
        } else if ( (htonl(routeTable[middle].mask) & htonl(dest_ip)) > htonl(routeTable[middle].prefix) ){
            return binarySearch(middle + 1, right, dest_ip);
        } else {
            return binarySearch(left, middle - 1, dest_ip);
        }
    }
    return NULL;
};
void sendRequest(__u32 dest_ip, int interface)
{
    //creaza un packet
    packet *reply= calloc(1, sizeof(packet));
    reply->interface = interface;
    reply->len = (sizeof(struct ether_arp) + sizeof(struct ether_header));

    struct ether_arp * pEtherArp = (struct ether_arp*)(reply->payload + sizeof(struct ether_header));
    struct ether_header * pEtherHeader = (struct ether_header *)reply->payload;

    //setam adresa de broadcast 255.255.255.255
    for (int i = 0; i < 6 ; ++i) {
        pEtherArp->arp_tha[i] = 0xff;
    }
    get_interface_mac(interface,pEtherArp->arp_sha);
    char *ip_s = get_interface_ip(interface);
    struct in_addr ip ;
    inet_aton(ip_s,&ip);
    memcpy(&(pEtherArp->arp_spa),&(ip.s_addr),4);

    //set ethernet header
    get_interface_mac(interface,pEtherHeader->ether_shost);
    for (int i = 0; i < 6 ; ++i) {
        pEtherHeader->ether_dhost[i] = 0xff;
    }
    //setez campurile de arp
    pEtherArp->ea_hdr.ar_hln = 6;
    //tipul pachetului
    pEtherHeader->ether_type = htons(ETHERTYPE_ARP);
    //tip op cod reply/request
    pEtherArp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    //tip ethernet ip
    pEtherArp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    //dimensiune adresa mac
    pEtherArp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    //copiez adresa ip
    memcpy(&(pEtherArp->arp_tpa),&(dest_ip),4);
    //dimensiune adresa ip
    pEtherArp->ea_hdr.ar_pln = 4;
    //trimit mesajul
    send_packet(interface,reply);

};

void arpRequest(packet *m)
{

    struct ether_arp * pEtherArp = (struct ether_arp*)(m->payload + sizeof(struct ether_header));
    struct ether_header * pEtherHeader = (struct ether_header *)m->payload;

    //inversem adresele in headerul ethernel
    memcpy(&(pEtherHeader->ether_dhost),&(pEtherHeader->ether_shost),6);
    get_interface_mac(m->interface,pEtherHeader->ether_shost);

    int sp;
    memcpy(&(sp),&(pEtherArp->arp_tpa),4);
    //inversam adresele de protocol header arp
    memcpy(&(pEtherArp->arp_tpa),&(pEtherArp->arp_spa),4);
    memcpy(&(pEtherArp->arp_spa),&(sp),4);

    //setam adresele mac in header-ul arp
    memcpy(&(pEtherArp->arp_tha),&(pEtherHeader->ether_dhost),6);
    memcpy(&(pEtherArp->arp_sha),&(pEtherHeader->ether_shost),6);

    pEtherArp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    send_packet(m->interface,m);



};
void arpReply(packet *m){

    //adaugam in tabela ARP ip si mac primit in urma unui ArpReply
    struct ether_arp * pEtherArp = (struct ether_arp*)(m->payload + sizeof(struct ether_header));
    memcpy(&(arpTable[arpTableSize].ip),&(pEtherArp->arp_spa),4);
    memcpy(&(arpTable[arpTableSize].mac),&(pEtherArp->arp_sha),6);
    //updatam dimensiunea tabelei
    arpTableSize++;

};


void icmpChecker(packet *m, uint8_t type){
    //cream un packet nou pentru a trimite ca raspuns
    packet *reply = calloc(1, sizeof (packet));
    //copiem din mesajul initial in packet-ul de reply
    memcpy(&(reply->payload),&(m->payload),m->len);
    //setam dimensiunea packetu-ului
    reply->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    //setam interfata
    reply->interface = m->interface;

    struct ether_header * pEtherHdr = (struct ether_header *)reply->payload;
    struct iphdr *pIpHdr = (struct iphdr *)(reply->payload + sizeof(struct ether_header));
    struct icmphdr *pIcmpHdr = (struct icmphdr *)(reply->payload +sizeof(struct ether_header)
            + sizeof(struct iphdr));

    //aflam adresa interfetei
    char *ip_s = get_interface_ip(m->interface);
    struct in_addr ip ;
    inet_aton(ip_s,&ip);

    //setam header-ul icmp
    pIcmpHdr->type = type;
    pIcmpHdr->checksum = 0;
    //recalculam checksum
    pIcmpHdr->checksum = ip_checksum(pIcmpHdr,sizeof(m->payload - sizeof(struct ether_header)
            - sizeof(struct iphdr)));

    // inversam adresele ip
    memcpy(&(pIpHdr->daddr),&(pIpHdr->saddr),4);
    memcpy(&(pIpHdr->saddr),&(ip.s_addr),4);

    //setam header-ul ip
    pIpHdr->ttl = 69;
    pIpHdr->version = 4;
    //setam dimensiunea
    pIpHdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    pIpHdr->id = getpid();
    //setam tipul de protocol
    pIpHdr->protocol = IPPROTO_ICMP;
    pIpHdr->ihl = 5;
    pIpHdr->check = 0;
    //recalculam checksum
    pIpHdr->check = ip_checksum(pIpHdr, sizeof(struct iphdr));


    memcpy(&(pEtherHdr->ether_dhost),&(pEtherHdr->ether_shost),6);
    get_interface_mac(m->interface,pEtherHdr->ether_shost);

    //Trimitem packet-ul de raspuns
    send_packet(m->interface,reply);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout,NULL,_IONBF,0);
    packet m;
    // Citim tabela de rutare
    createRouteTable();
    // Citim tabela arp
    //createArpTable();
    arpTable = malloc(sizeof(struct arpEntry) * 12);
    arpTableSize = 0;
    //sortare table O(n log n)
    qsort(routeTable,routeTableSize, sizeof(struct route_table),cmpFunc);

    q = queue_create();
    int rc;
    init();
    while (1) {

        rc = get_packet(&m);
        DIE(rc < 0, "get_message");
        /* Students will write code here */
        struct ether_header *pEtherHeader = (struct ether_header *)m.payload;
        struct ether_arp * pArpHeader = (struct ether_arp *) (m.payload + sizeof(struct ether_header));
        struct iphdr *pIpHeader = (struct iphdr *)(m.payload + sizeof(struct ether_header));
        struct icmphdr *pIcmpHeader = (struct icmphdr *)(m.payload + sizeof(struct ether_header)
                + sizeof(struct iphdr));

        //verificam daca este un packet arp
        if ( htons(pEtherHeader->ether_type) == ETHERTYPE_ARP )
        {
            //verificam daca este un arp reply
            if( pArpHeader->ea_hdr.ar_op == htons(ARPOP_REPLY))
            {
                arpReply(&m);
                //trimite mesaje daca sunt in coada de asteptare
                while (!queue_empty(q)){
                    //scoatem din coada mesaj
                    packet *end = (packet*)queue_deq(q);
                   struct iphdr *ipH = (struct iphdr *)(end->payload + sizeof(struct ether_header));
                   struct ether_header *pEther = (struct ether_header *)end->payload;

                   //decrementam ttl-ul
                    ipH->ttl--;
                   //gasim next ho
                   struct route_table *n = binarySearch(0, routeTableSize, ipH->daddr);
                   //calculam checksum-ul
                   ipH->check = 0;
                   ipH->check = ip_checksum(ipH, sizeof(struct iphdr));
                    //gasim adresa de nexthop
                   struct arpEntry *e = get_arp_entry(n->nextHop);
                   //gasim adresa mac
                   get_interface_mac(n->interface, pEther->ether_shost);
                   //setam adresa mac a next hop-ului
                   memcpy(pEther->ether_dhost, e->mac, sizeof(e->mac));

                   //trimitem pachetul
                   send_packet(n->interface, end);

                }
            continue;
            }
            //verificam daca este un arp request
            if( pArpHeader->ea_hdr.ar_op == htons(ARPOP_REQUEST))
            {
                arpRequest(&m);
                continue;
            }

        }
        //verificam daca este un packet ip
        if( htons(pEtherHeader->ether_type) == ETHERTYPE_IP ) {
            //salvez valoarea checksum-ului veche
            __u16 oldChecksum = pIpHeader->check;
            pIpHeader->check = 0;
            //calculez noul checksum
            __u16 newChecksum = ip_checksum(pIpHeader, sizeof(struct iphdr));
            //verificam checksum-ul
            if (oldChecksum != newChecksum) {
                //drop la paket
                continue;
            }
            //verificam daca nu este ttl < 1
            if (pIpHeader->ttl <= 1) {
                //Trimitem un packet icmp_time_exceeded
                icmpChecker(&m, ICMP_TIME_EXCEEDED);
                //drop la pachet
                continue;
            }
            struct route_table *next = binarySearch(0, routeTableSize, pIpHeader->daddr);
            //Verificam daca am gasit adresa in tabel
            if (next == NULL) {
                //trimitem un paket icmp_dest_unreachable
                icmpChecker(&m, ICMP_DEST_UNREACH);
                //drop la packet
                continue;;
            }
            //alfam ip-ul interfetei
            char *ip = get_interface_ip(m.interface);
            struct in_addr intIp;
            inet_aton(ip, &intIp);

            if (pIpHeader->daddr == intIp.s_addr) {
                /*verificam daca adresa ping-ului este adresa interfetei
                de pe care am trimis */
                if (pIpHeader->protocol == IPPROTO_ICMP) {
                    //verificam daca este un paket ICMP
                    if (pIcmpHeader->type == ICMP_ECHO) {
                        //verificam daca este un paket ICMP de tipul ECHO_REPLYY
                        icmpChecker(&m, ICMP_ECHOREPLY);
                    }
                }
                //drop la packet
                continue;
            }

            //Cautam in next hop-ul in tabela
            struct arpEntry *entry = get_arp_entry(next->nextHop);
            //Verificam daca avem un entry valid
            if (entry == NULL) {
                //cream copie packet
                packet * r = calloc (1, sizeof(packet));
                memcpy(r->payload,m.payload,m.len);
                r->len = m.len;
                r->interface = m.interface;
                //punem in coada mesajul
                queue_enq(q,r);
                //trimitem un arp request
                sendRequest(next->nextHop, next->interface);
                continue;
            }
            //decrementam ttl-ul
            pIpHeader->ttl--;
            //recalculam checksum-ul
            pIpHeader->check = ip_checksum(pIpHeader, sizeof(struct iphdr));
            //aflam adresa mac a bestroute-ului
            get_interface_mac(next->interface, pEtherHeader->ether_shost);
            //setam adresa mac a next hop-ului
            memcpy(pEtherHeader->ether_dhost, entry->mac, sizeof(entry->mac));

            //trimitem pachetul
            send_packet(next->interface, &m);
        }
    }
    free(routeTable);
    free(arpTable);
}