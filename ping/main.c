//
//  main.c
//  ping
//

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef struct {
    uint8_t  icmpe_type;
    uint8_t  icmpe_code;
    uint16_t icmpe_csum;
    uint16_t icmpe_id;
    uint16_t icmpe_seq;
} icmp_echo_t;

static uint16_t checksum( void *buf, int len )
{
    unsigned sum;
    
    for ( sum = 0; len > 1; buf += 2, len -= 2 )
        sum += *((uint16_t *)buf);
    if ( len > 0 )
        sum += *((uint8_t *)buf);
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    
    return ~sum;
}

int main(int argc, const char * argv[])
{
    /* Open a socket to send echo. */
    printf( "Open socket.\n" );
    int s = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    if ( s == -1 ) {
        perror( NULL );
        exit( EXIT_FAILURE );
    }
    
    /* Build ICMP header. */
    printf( "Build ICMP header.\n" );
    char bout[256];
    icmp_echo_t *icmpe;
    icmpe = (icmp_echo_t *)bout;
    icmpe->icmpe_type = ICMP_ECHO;
    icmpe->icmpe_code = 0;
    icmpe->icmpe_id = htons( 0x01 );
    icmpe->icmpe_seq = htons( 0x02 );
    icmpe->icmpe_csum = checksum( bout, sizeof( *icmpe ) );
    
    /* Send ICMP echo. */
    printf( "Send ICMP echo.\n" );
    struct sockaddr_in addr1;
    addr1.sin_family = AF_INET;
    addr1.sin_addr.s_addr = inet_addr( "216.58.220.174" );
    addr1.sin_len = sizeof( addr1 );
    if ( sendto( s, bout, sizeof( *icmpe ), 0, (struct sockaddr *)&addr1, sizeof( addr1 ) ) == -1 ) {
        perror( NULL );
        exit( EXIT_FAILURE );
    }
    
    /* Receive ICMP echo reply */
    printf( "Receive data.\n" );
    char bin[256];
    struct sockaddr_storage addr2;
    socklen_t addr2_len;
    if ( recvfrom( s, bin, sizeof( bin ), 0, (struct sockaddr *)&addr2, &addr2_len ) == -1 ) {
        perror( NULL );
        exit( EXIT_FAILURE );
    }
    
    /* Analyse received reply */
    printf( "Analyse received data.\n" );
    struct ip *ip;
    struct icmp *icmp;
    ip = (struct ip *)bin;
    icmp = (struct icmp *)(bin + (ip->ip_hl * 4));
    printf( "Source IP address is %s.\n", inet_ntoa( ip->ip_src ) );
    printf( "Destination IP address is %s.\n", inet_ntoa( ip->ip_dst ) );
    if ( icmp->icmp_type == ICMP_ECHOREPLY )
        printf( "Received is ICMP ECHO REPLY.\n" );
    else
        printf( "Received is ICMP %d.\n", icmp->icmp_type );
    printf( "ICMP ECHO REPLY's identifier is %d.\n", ntohs( icmp->icmp_hun.ih_idseq.icd_id ) );
    printf( "ICMP ECHO REPLY's sequence number is %d.\n", ntohs( icmp->icmp_hun.ih_idseq.icd_seq ) );

    return 0;
}
