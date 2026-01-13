#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}

// init tcp hash table and tcp timer
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);
	init_list_head(&tsk->send_buf);
	init_list_head(&tsk->rcv_ofo_buf);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
void free_tcp_sock(struct tcp_sock *tsk)
{
	tsk->ref_cnt -= 1;
	if(tsk->ref_cnt <= 0){
		free_ring_buffer(tsk->rcv_buf);
		free_wait_struct(tsk->wait_connect);
		free_wait_struct(tsk->wait_accept);
		free_wait_struct(tsk->wait_recv);
		free_wait_struct(tsk->wait_send);
		pthread_mutex_destroy(&tsk->sk_lock);
		pthread_mutex_destroy(&tsk->rcv_buf_lock);
		pthread_mutex_destroy(&tsk->send_buf_lock);
		free(tsk);
	}
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	int hash = tcp_hash_function(saddr, daddr, sport, dport);
	struct list_head *list = &tcp_established_sock_table[hash];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list){
		if(tsk->sk_sip == saddr && tsk->sk_dip == daddr && tsk->sk_sport == sport && tsk->sk_dport == dport){
			return tsk;
		}
	}
	return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
	int hash = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_listen_sock_table[hash];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list){
		if(tsk->sk_sport == sport && tsk->state == TCP_LISTEN){
			return tsk;
		}
	}
	return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);

	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	tsk->ref_cnt += 1;

	return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, bind_hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;

	return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		log(DEBUG, IP_FMT":%hu free.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport);
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;

	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	tsk->sk_dip = ntohl(skaddr->ip);
	tsk->sk_dport = ntohs(skaddr->port);
	rt_entry_t *rt = longest_prefix_match(tsk->sk_dip);
	if(!rt){
		log(ERROR, "No route to host");
		return -1;
	}
	tsk->sk_sip = rt->iface->ip;
	tsk->sk_sport = tcp_get_port();
	if(tsk->sk_sport == 0){
		log(ERROR, "No available port");
		return -1;
	}
	tcp_set_state(tsk, TCP_SYN_SENT);
	if(tcp_hash(tsk) < 0){
		log(ERROR, "Hash failed");
		return -1;
	}
	pthread_mutex_lock(&tsk->sk_lock);
	tcp_send_control_packet(tsk, TCP_SYN);
	pthread_mutex_unlock(&tsk->sk_lock);
	sleep_on(tsk->wait_connect);
	if(tsk->state != TCP_ESTABLISHED){
		log(ERROR, "Connection failed");
		return -1;
	}
	return 0;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	if(tsk->state != TCP_CLOSED){
		log(ERROR, "tcp_sock_listen: socket not in CLOSED state.");
		return -1;
	}
	tsk->backlog = backlog;
	tsk->accept_backlog = 0;
	tcp_set_state(tsk, TCP_LISTEN);
	if(tcp_hash(tsk) < 0){
		log(ERROR, "tcp_sock_listen: failed to hash socket");
		tcp_set_state(tsk, TCP_CLOSED);
		return -1;
	}
	return 0;
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
	if(tsk->state != TCP_LISTEN){
		log(ERROR, "tcp_sock_accept: socket not in LISTEN state.");
		return NULL;
	}
	while(list_empty(&tsk->accept_queue)){
		sleep_on(tsk->wait_accept);
	}
	struct tcp_sock *new_tsk = tcp_sock_accept_dequeue(tsk);
	if (new_tsk->state != TCP_ESTABLISHED) {
        log(ERROR, "tcp_sock_accept: dequeued socket not established");
        free_tcp_sock(new_tsk);
        return NULL;
    }
	return new_tsk;
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk)
{
	if(!tsk) return;
	switch(tsk->state){
		case TCP_ESTABLISHED:
			tcp_set_state(tsk, TCP_FIN_WAIT_1);
			//log(DEBUG, "snd_nxt: %d", tsk->snd_nxt);
			pthread_mutex_lock(&tsk->sk_lock);
			log(DEBUG, "get lock in tcp_sock_close, case: established");
			tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
			log(DEBUG, "unlock in tcp_sock_close, case: established");
			pthread_mutex_unlock(&tsk->sk_lock);
			break;
		case TCP_CLOSE_WAIT:
			tcp_set_state(tsk, TCP_LAST_ACK);
			pthread_mutex_lock(&tsk->sk_lock);
			log(DEBUG, "get lock in tcp_sock_close, case: close_wait");
			tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
			log(DEBUG, "unlock in tcp_sock_close, case: close_wait");
			pthread_mutex_unlock(&tsk->sk_lock);
			break;
		case TCP_LISTEN:
			// 实验中不涉及
			log(ERROR, "should not be here.");
			break;
		default:
			break;
	}
	return;
}

// 返回值：0表示读到流结尾，对方关闭连接，-1表示读取失败，正数表示读取到的字节数
int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
	if(tsk->state != TCP_CLOSE_WAIT && tsk->state != TCP_ESTABLISHED){
		return -1;
	}
	pthread_mutex_lock(&tsk->rcv_buf_lock);
	if(tsk->state == TCP_CLOSE_WAIT && ring_buffer_empty(tsk->rcv_buf)){
		//log(DEBUG, "No data to read");
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		return 0;
	}
	while(ring_buffer_empty(tsk->rcv_buf)){
		//log(DEBUG, "No data in buffer");
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		sleep_on(tsk->wait_recv);
		pthread_mutex_lock(&tsk->rcv_buf_lock);
		if(tsk->state == TCP_CLOSE_WAIT && ring_buffer_empty(tsk->rcv_buf)){
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			return 0;
		}
	}
	int rlen = read_ring_buffer(tsk->rcv_buf, buf, len);
	tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
	pthread_mutex_unlock(&tsk->rcv_buf_lock);
	return rlen;
}

// 返回值：-1表示出现错误；正值表示写入的数据长度
static int number = 0;
int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len){
	if(tsk->state != TCP_ESTABLISHED && tsk->state != TCP_CLOSE_WAIT){
		return -1;
	}
	int send_len = 0;
	int left_len = len;
	char *pos = buf;
	while(left_len > 0){
		int data_len = min(left_len, 1460);
		/*while(tsk->snd_wnd <= 0 || tsk->snd_nxt - tsk->snd_una >= tsk->snd_wnd){
			log(DEBUG, "%d %d %d", tsk->snd_nxt, tsk->snd_una, tsk->snd_wnd);
			sleep_on(tsk->wait_send);
		}*/
		int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + data_len;
		char *packet = malloc(pkt_size);
		char *data = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
		memcpy(data, pos, data_len);
		pthread_mutex_lock(&tsk->sk_lock);
		//pthread_mutex_lock(&tsk->send_buf_lock); 我猜后面需要加
		while(!tcp_tx_window_test(tsk)){
			//log(DEBUG, "wait for window in tcp_sock_write");
			pthread_mutex_unlock(&tsk->sk_lock);
			sleep_on(tsk->wait_send);
			pthread_mutex_lock(&tsk->sk_lock);
		}
		tcp_send_packet(tsk, packet, pkt_size);
		number ++;
		log(DEBUG, "send packet %d, snd_wnd=%d, snd_una=%d, snd_nxt=%d", number, tsk->snd_wnd, tsk->snd_una, tsk->snd_nxt);
		//pthread_mutex_unlock(&tsk->send_buf_lock); 我猜后面需要加
		pthread_mutex_unlock(&tsk->sk_lock);
		//free(packet); 我怀疑ip_send_packet会free
		pos += data_len;
		left_len -= data_len;
		send_len += data_len;
	}
	return send_len;
}


/*
创建send_buffer_entry加入send_buf尾部

注意上锁，后面不再强调。
*/
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len){
	struct send_buffer_entry *entry = malloc(sizeof(struct send_buffer_entry));
	entry->packet = malloc(len);
	memcpy(entry->packet, packet, len);
	entry->len = len;
	pthread_mutex_lock(&tsk->send_buf_lock);
	list_add_tail(&entry->list, &tsk->send_buf);
	pthread_mutex_unlock(&tsk->send_buf_lock);
	log(DEBUG, "send_buffer_add_packet: %d", tsk->snd_nxt);
}

/*
基于收到的ACK包，遍历发送队列，将已经接收的数据包从队列中移除

提取报文的tcp头可以使用packet_to_tcp_hdr，注意报文中的字段是大端序
*/
int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack){
	pthread_mutex_lock(&tsk->send_buf_lock);
	int count = 0;
	struct send_buffer_entry *entry, *tmp;
	if(list_empty(&tsk->send_buf)){
		pthread_mutex_unlock(&tsk->send_buf_lock);
		return 0;
	}
	list_for_each_entry_safe(entry, tmp, &tsk->send_buf, list){
		struct tcphdr *tcp = packet_to_tcp_hdr(entry->packet);
		u32 seq = ntohl(tcp->seq);
		int data_len = entry->len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;
		u32 seq_end = seq + data_len;
		if(less_or_equal_32b(seq_end, ack)){
			list_delete_entry(&entry->list);
			free(entry->packet);
			free(entry);
			count++;
		}else{
			break;
		}
	}
	pthread_mutex_unlock(&tsk->send_buf_lock);
	return count;
}

/*
获取重传队列第一个包，修改ack号和checksum并通过ip_send_packet发送。

注意不要更新snd_nxt之类的参数，这是一个独立的重传报文。
*/
int tcp_retrans_send_buffer(struct tcp_sock *tsk){
	pthread_mutex_lock(&tsk->send_buf_lock);
	if(list_empty(&tsk->send_buf)){
		pthread_mutex_unlock(&tsk->send_buf_lock);
		return 0;
	}
	struct send_buffer_entry *entry = list_entry(tsk->send_buf.next, struct send_buffer_entry, list);
	struct iphdr *ip = packet_to_ip_hdr(entry->packet);
	struct tcphdr *tcp = packet_to_tcp_hdr(entry->packet);
	u32 old_ack = ntohl(tcp->ack);
	tcp->ack = htonl(tsk->rcv_nxt);
	tcp->rwnd = htons(tsk->rcv_wnd);
	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);
	char* packet = malloc(entry->len);
	memcpy(packet, entry->packet, entry->len);
	pthread_mutex_unlock(&tsk->send_buf_lock);
	ip_send_packet(packet, entry->len);
	log(DEBUG, "重传数据包：seq=%d, old_ack=%d, new_ack=%d", ntohl(tcp->seq), old_ack, tsk->rcv_nxt);
	return 1;
}


/*
1. 创建recv_ofo_buf_entry
2. 用list_for_each_entry_safe遍历rcv_ofo_buf，将表项插入合适的位置。如果发现了重复数据包，则丢弃当前数据。
3. 调用tcp_move_recv_ofo_buffer执行报文上送
*/
int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb){
	if(cb->pl_len <= 0) return 0;
	struct recv_ofo_buf_entry *entry = malloc(sizeof(struct recv_ofo_buf_entry));
	entry->packet = malloc(cb->pl_len);
	memcpy(entry->packet, cb->payload, cb->pl_len);
	entry->len = cb->pl_len;
	entry->seq = cb->seq;
	entry->seq_end = cb->seq_end;
	int flag = 0;
	if(list_empty(&tsk->rcv_ofo_buf)){
		list_add_head(&entry->list, &tsk->rcv_ofo_buf);
	}else{
		struct recv_ofo_buf_entry *pos, *tmp;
		list_for_each_entry_safe(pos, tmp, &tsk->rcv_ofo_buf, list){
			if(less_or_equal_32b(entry->seq_end, pos->seq)){
				list_add_tail(&entry->list, &pos->list);
				flag = 1;
				break;
			}else if(less_or_equal_32b(pos->seq_end, entry->seq)){
				continue;
			}else{
				if(entry->seq == pos->seq && entry->seq_end == pos->seq_end){
					log(DEBUG, "tcp_recv_ofo_buffer_add_packet: duplicate packet");
					free(entry->packet);
					free(entry);
					return 0;
				}else{
					log(DEBUG, "出现了部分重叠的包，seq=%d, seq_end=%d, pos->seq=%d, pos->seq_end=%d", entry->seq, entry->seq_end, pos->seq, pos->seq_end);
					break;
				}
			}
		}
		if(flag == 0){
			list_add_tail(&entry->list, &tsk->rcv_ofo_buf);
		}
	}
	tcp_send_control_packet(tsk, TCP_ACK);
	pthread_mutex_lock(&tsk->rcv_buf_lock);
	tcp_move_recv_ofo_buffer(tsk);
	pthread_mutex_unlock(&tsk->rcv_buf_lock);
	return 1;
}

/*
遍历rcv_ofo_buf，将所有有序的（序列号等于tsk->rcv_nxt）的报文送入接收队列（tsk->rcv_buf）
更新rcv_nxt, rcv_wnd并唤醒接收线程(wait_recv)

如果接收队列已满，应当退出函数，而非等待。
*/
int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk){
	struct recv_ofo_buf_entry *entry, *tmp;
	int count = 0;
	int number = 0;
	list_for_each_entry_safe(entry, tmp, &tsk->rcv_ofo_buf, list){
		if(entry->seq == tsk->rcv_nxt){
			if(ring_buffer_free(tsk->rcv_buf) < entry->len){
				log(DEBUG, "接受缓冲区空间不足，停止移动乱序报文");
				return count;
			}
			write_ring_buffer(tsk->rcv_buf, entry->packet, entry->len);
			tsk->rcv_nxt = entry->seq_end;
			tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
			//tcp_send_control_packet(tsk, TCP_ACK);
			list_delete_entry(&entry->list);
			free(entry->packet);
			free(entry);
			count++;
		}else if(less_or_equal_32b(entry->seq_end, tsk->rcv_nxt)){
			log(DEBUG, "乱序队列里有已经确认过的报文，丢弃");
			list_delete_entry(&entry->list);\
			tcp_send_control_packet(tsk, TCP_ACK);
			free(entry->packet);
			free(entry);
		}
		number++;
	}
	//log(DEBUG, "乱序队列里有%d个报文", number);
	if(count > 0){
		log(DEBUG, "从乱序队列移动了%d个报文，rcv_nxt=%d, rcv_wnd=%d", count, tsk->rcv_nxt, tsk->rcv_wnd);
		tcp_send_control_packet(tsk, TCP_ACK);
		wake_up(tsk->wait_recv);
	}
	return count;
}