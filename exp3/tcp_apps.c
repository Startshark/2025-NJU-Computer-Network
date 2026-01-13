#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
#include <stdio.h>
#include <string.h>


// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	FILE *fp = fopen("server-output.dat", "w");
	if (!fp) {
		log(ERROR, "cannot open file for writing");
		exit(1);
	}

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	// sleep(5);

	char buf[1001];
	int len;
	while ((len = tcp_sock_read(csk, buf, 1000)) > 0) {
		buf[len] = '\0';
		fputs(buf, fp);
	}

	log(DEBUG, "now close the connection.");
	tcp_sock_close(csk);
	fclose(fp);
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();
	FILE *fp = fopen("client-input.dat", "r");
	if (!fp) {
		log(ERROR, "cannot open file for reading");
		exit(1);
	}


	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}
	
	
	char buf[1001];
	int cnt = 0;
	int bytes_read;
	
	while(1){ //fgets(buf, 1000, fp) != NULL
		bytes_read = fread(buf, 1, 1000, fp); //一次发送的字符数越小，越有可能出现乱序
		if (bytes_read <= 0) break;
		buf[bytes_read] = '\0';
		tcp_sock_write(tsk, buf, bytes_read);
		cnt++;
		//sleep(1);
	}

	sleep(2);
	fclose(fp);


	tcp_sock_close(tsk);

	return NULL;
}




// void remove_ack_data(struct tcp_sock *tsk, int ack_num){
// 	tcp_unset_retrans_timer(tsk);
// 	struct send_packet *pos, *q;
// 	list_for_each_entry_safe(pos, q, &tsk->send_buf, list){
// 		struct tcphdr *tcp = packet_to_tcp_hdr(pos->packet);
// 		struct iphdr *ip = packet_to_ip_hdr(pos->packet);
// 		if (ack_num >= ntohl(tcp->seq)){
// 			tsk->snd_wnd += (ntohs(ip->tot_len) - IP_HDR_SIZE(ip) - TCP_HDR_SIZE(tcp));
// 			free(pos->packet);
// 			list_delete_entry(&pos->list);
// 		}
// 	}
// 	if (!list_empty(&tsk->send_buf)){
// 		tcp_set_retrans_timer(tsk);
// 	}
// }
