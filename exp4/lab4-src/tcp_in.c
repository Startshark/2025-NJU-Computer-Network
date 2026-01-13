#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)

// 使用tsk->snd_una, tsk->snd_wnd, tsk->snd_nxt计算剩余窗口大小，如果大于等于TCP_MSS，则返回1，否则返回0
int tcp_tx_window_test(struct tcp_sock *tsk){
	u32 remain = tsk->snd_una + tsk->snd_wnd - tsk->snd_nxt;
	return less_or_equal_32b(TCP_MSS, remain);
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)

static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	int bef = tcp_tx_window_test(tsk);
	tsk->snd_una = cb->ack;
	tsk->adv_wnd = cb->rwnd;
	// tsk->cwnd = 0x7f7f7f7f;
	tsk->snd_wnd = less_than_32b(tsk->adv_wnd, tsk->cwnd) ? tsk->adv_wnd : tsk->cwnd;
	if(tsk->snd_wnd < TCP_MSS){
		tcp_set_persist_timer(tsk);
	}else{
		tcp_unset_persist_timer(tsk);
	}
	int aft = tcp_tx_window_test(tsk);
	if(bef == 0 && aft == 1){
		wake_up(tsk->wait_send);
	}
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

// static inline void tcp_rcv_data_packet(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet){
// 	pthread_mutex_lock(&tsk->rcv_buf->rw_lock);
// 	write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
// 	tsk->rcv_wnd -= cb->pl_len;
// 	pthread_mutex_unlock(&tsk->rcv_buf->rw_lock);
// 	wake_up(tsk->wait_recv);
// }


#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}


// void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
// {	
// 	if (cb->flags & TCP_SYN){
// 		struct tcp_sock *child = alloc_tcp_sock();
// 		// child->peer.ip = cb->saddr;
// 		// child->peer.port = cb->sport;
// 		// child->local.ip = cb->daddr;
// 		// child->local.port = cb->dport;
// 		child->sk_sip   = cb->daddr;
// 		child->sk_dip   = cb->saddr;
// 		child->sk_sport = cb->dport;
// 		child->sk_dport = cb->sport;
// 		child->parent = tsk;
// 		child->rcv_nxt = cb->seq_end;
// 		child->iss = tcp_new_iss();
// 		child->snd_nxt = child->iss;
// 		struct sock_addr skaddr = {htonl(child->sk_sip), htons(child->sk_sport)};
// 		tcp_sock_bind(child, &skaddr);
// 		tcp_set_state(child, TCP_SYN_RECV);
// 		list_add_tail(&child->list, &tsk->listen_queue);
// 		tcp_send_control_packet(child, TCP_SYN | TCP_ACK);
// 		tcp_hash(child);
// 	}
// 	else {
// 		tcp_send_reset(cb);
// 	}
// }

// void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
// {
// 	tcp_send_reset(cb);
// }

// void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
// {
// 	if (cb->flags & (TCP_SYN | TCP_ACK)){
// 		tsk->rcv_nxt = cb->seq_end;
// 		tsk->snd_una = cb->ack;
// 		tcp_send_control_packet(tsk, TCP_ACK);
// 		tcp_set_state(tsk, TCP_ESTABLISHED);
// 		wake_up(tsk->wait_connect);
// 	}
// 	else {
// 		tcp_send_reset(cb);
// 	}
// }

// void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
// {
// 	if (cb->flags & TCP_ACK){
// 		remove_ack_data(tsk, cb->ack);
// 		tcp_sock_accept_enqueue(tsk);
// 		wake_up(tsk->parent->wait_accept);
// 	}
// 	else {
// 		tcp_send_reset(cb);
// 	}
// }


// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// int state = tsk->state;
	// if (state == TCP_CLOSED) {
	// 	tcp_state_closed(tsk, cb, packet);
	// 	return ;
	// }
	// if (state == TCP_LISTEN) {
	// 	tcp_state_listen(tsk, cb, packet);
	// 	return ;
	// }
	// if (state == TCP_SYN_SENT) {
	// 	tcp_state_syn_sent(tsk, cb, packet);
	// 	return ;
	// }
	// if (!is_tcp_seq_valid(tsk, cb)) {
	// 	log(ERROR, "tcp_process(): received packet with invalid seq, drop it.");
	// 	return ;
	// }
	// if (cb->flags & TCP_RST) {
	// 	tcp_set_state(tsk, TCP_CLOSED);
	// 	tcp_unhash(tsk);
	// 	return ;
	// }
	// if (cb->flags & TCP_SYN) {
	// 	tcp_send_reset(cb);
	// 	tcp_set_state(tsk, TCP_CLOSED);
	// 	return ;
	// }
	// if (!(cb->flags & TCP_ACK)) {
	// 	tcp_send_reset(cb);
	// 	log(ERROR, "tcp_process(): TCP_ACK is not set.");
	// 	return ;
	// }

	// if (state == TCP_ESTABLISHED && (cb->flags == (TCP_PSH | TCP_ACK))){
	// 	printf("received tcp packet PSH | ACK\n");
	// 	tcp_rcv_data_packet(tsk, cb, packet);
	// 	tcp_send_control_packet(tsk, TCP_ACK);
	// 	return;
	// }

	// tsk->snd_una = cb->ack;
	// tsk->rcv_nxt = cb->seq_end;
	// if ((state == TCP_SYN_RECV) && (cb->ack == tsk->snd_nxt))
	// 	tcp_state_syn_recv(tsk, cb, packet);
	// if ((state == TCP_FIN_WAIT_1) && (cb->ack == tsk->snd_nxt)) {
	// 	tcp_set_state(tsk, TCP_FIN_WAIT_2);
	// 	tcp_send_control_packet(tsk, TCP_ACK);
	// }
	// if ((state == TCP_FIN_WAIT_2) && (cb->flags & (TCP_ACK | TCP_FIN))) {
	// 	tcp_set_state(tsk, TCP_TIME_WAIT);
	// 	tcp_set_timewait_timer(tsk);
	// 	tcp_send_control_packet(tsk, TCP_ACK | TCP_FIN);
	// }
	// if ((state == TCP_ESTABLISHED) && (cb->flags & TCP_FIN)) {
	// 	tcp_set_state(tsk, TCP_CLOSE_WAIT);
	// 	tcp_send_control_packet(tsk, TCP_ACK);
	// }

	// if ((state == TCP_CLOSE_WAIT) && (cb->flags | (TCP_ACK|TCP_FIN))){
	// 	tcp_set_state(tsk, TCP_LAST_ACK);
	// 	tcp_send_control_packet(tsk, TCP_ACK |TCP_FIN);
	// }

	// if ((state == TCP_LAST_ACK) && (cb->ack == tsk->snd_nxt))
	// 	tcp_set_state(tsk, TCP_CLOSED);
	// if (state == TCP_ESTABLISHED && cb->flags == TCP_ACK){
	// 	printf("tcp_sock received ACK packet.\n");
	// 	tcp_send_control_packet(tsk, TCP_ACK);
	// }
	if (cb->flags == TCP_RST) {
		tcp_unset_retrans_timer(tsk);
		tcp_set_state(tsk, TCP_CLOSED);
		wake_up(tsk->wait_connect);
		wake_up(tsk->wait_recv);
		wake_up(tsk->wait_send);
		wake_up(tsk->wait_accept);
		tcp_unhash(tsk);
		return;
	}
	switch (tsk->state) {
		case TCP_LISTEN:
			if (cb->flags == TCP_SYN) {
				struct tcp_sock *child = alloc_tcp_sock();

				child->parent = tsk;
				child->rcv_wnd = tsk->rcv_wnd;
				
				child->sk_sip = cb->daddr;
				child->sk_dip = cb->saddr;
				child->sk_sport = cb->dport;
				child->sk_dport = cb->sport;

				child->iss = tcp_new_iss();
				child->snd_nxt = child->iss + 1;
				child->rcv_nxt = cb->seq + 1;

				tcp_set_state(child, TCP_SYN_RECV);
				tcp_hash(child);
				tcp_send_control_packet(child, TCP_SYN|TCP_ACK);
			}
			break;
		case TCP_SYN_SENT:
			if (cb->flags == (TCP_SYN | TCP_ACK)) {
				tcp_update_send_buffer(tsk, cb->ack);
				if (cb->ack == tsk->snd_nxt) {
					tsk->rcv_nxt = cb->seq + 1;
					// tsk->snd_una = cb->ack;
					tcp_update_window_safe(tsk, cb);
					tcp_unset_retrans_timer(tsk);
					tcp_set_state(tsk, TCP_ESTABLISHED);
					tcp_update_window_safe(tsk, cb);
					tcp_send_control_packet(tsk, TCP_ACK);
					wake_up(tsk->wait_connect);
				}
				else {
					log(ERROR, "TCP_SYN_SENT received packet with invalid ack, drop it.");
				}
			}
			break;
		case TCP_SYN_RECV:
			if (cb->flags == TCP_ACK) {
				tcp_update_send_buffer(tsk, cb->ack);
				if (cb->ack == tsk->snd_nxt) {
					tcp_update_window_safe(tsk, cb);
					tcp_unset_retrans_timer(tsk);
					// tsk->snd_una = cb->ack;
					tcp_set_state(tsk, TCP_ESTABLISHED);
					if (tsk->parent) {
						tcp_sock_accept_enqueue(tsk);
						wake_up(tsk->parent->wait_accept);
					}
				} else {
					log(ERROR, "TCP_SYN_RECV received packet with invalid ack, drop it.");
				}
			}
			break;
		case TCP_ESTABLISHED:
			if (cb->flags == (TCP_FIN | TCP_ACK) || cb->flags == (TCP_FIN | TCP_ACK | TCP_PSH)) {
				if(tsk->rcv_nxt != cb->seq){
					log(DEBUG, "发生了手册中的情况，直接丢弃");
					break;
				}
				tsk->rcv_nxt = cb->seq_end;
				tcp_update_window_safe(tsk, cb);
				tcp_update_send_buffer(tsk, cb->ack);
				tcp_update_retrans_timer(tsk);
				if(cb->pl_len > 0){
					int res = tcp_recv_ofo_buffer_add_packet(tsk, cb);
				}
				// tsk->rcv_nxt = cb->seq_end;
				tcp_set_state(tsk, TCP_CLOSE_WAIT);
				tcp_send_control_packet(tsk, TCP_ACK);
				wake_up(tsk->wait_recv);
			} else if (cb->flags == (TCP_PSH | TCP_ACK) || cb->flags == TCP_ACK) {
				tcp_update_window_safe(tsk, cb);
				tcp_update_send_buffer(tsk, cb->ack);
				tcp_update_retrans_timer(tsk);
				if (cb->pl_len > 0) {
					int res = tcp_recv_ofo_buffer_add_packet(tsk, cb);
				} else {
					log(DEBUG, "收到ACK包，snd_una: %d, snd_nxt: %d, snd_wnd: %d", tsk->snd_una, tsk->snd_nxt, tsk->snd_wnd);
				}
			}
			else{
				log(ERROR, "TCP_ESTABLISHED received packet with invalid flags %d, drop it.", cb->flags);
			}
			break;
		case TCP_LAST_ACK:
			if(cb->flags == TCP_ACK){
				tcp_update_send_buffer(tsk, cb->ack);
				if (cb->ack == tsk->snd_nxt) {
					tcp_update_window_safe(tsk, cb);
					tcp_unset_retrans_timer(tsk);
					tcp_set_state(tsk, TCP_CLOSED);
					tcp_unhash(tsk);
				}
			} else {
				log(ERROR, "TCP_LAST_ACK received packet with invalid flags, drop it.");
			}
			break;
		case TCP_FIN_WAIT_1:
			if (cb->flags == TCP_ACK) {
				tcp_update_send_buffer(tsk, cb->ack);
				if (cb->ack == tsk->snd_nxt) {
					tcp_update_window_safe(tsk, cb);
					tcp_set_state(tsk, TCP_FIN_WAIT_2);
				}
			} else if (cb->flags == (TCP_ACK | TCP_FIN)) {
				tcp_update_send_buffer(tsk, cb->ack);
				if (cb->ack == tsk->snd_nxt) {
					tcp_update_window_safe(tsk, cb);
					tsk->rcv_nxt = cb->seq_end;
					tcp_unset_retrans_timer(tsk);
					tcp_set_state(tsk, TCP_TIME_WAIT);
					tcp_send_control_packet(tsk, TCP_ACK);
					tcp_set_timewait_timer(tsk);
				}
				else {
					log(ERROR, "ack %d, snd_nxt %d.", cb->ack, tsk->snd_nxt);
				}
			}
			else {
				log(ERROR, "TCP_FIN_WAIT_1 received packet with invalid flags, drop it.");
			}
			break;
		case TCP_FIN_WAIT_2:
			if (cb->flags == (TCP_FIN | TCP_ACK)) {
				tcp_update_send_buffer(tsk, cb->ack);
				tsk->rcv_nxt = cb->seq_end;
				tcp_update_window_safe(tsk, cb);
				tcp_unset_retrans_timer(tsk);
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_timewait_timer(tsk);
			}
			else {
				log(ERROR, "TCP_FIN_WAIT_2 received packet with invalid flags, drop it.");
			}
			break;
		default:
			log(ERROR, "UNDEFINED state %s", tcp_state_str[tsk->state]);
			break;
	}
}

void process_data_packet(struct tcp_sock *tsk, struct tcp_cb *cb){
	if(less_or_equal_32b(cb->seq_end, tsk->rcv_nxt)){
		log(DEBUG, "收包情况一，收到了之前确认过的报文");
		tcp_send_control_packet(tsk, TCP_ACK);
	}else if(tsk->rcv_nxt == cb->seq){
		log(DEBUG, "收包情况二，刚好是自己希望收到的报文");
		log(DEBUG, "rcv_nxt: %d, seq: %d, seq_end: %d", tsk->rcv_nxt, cb->seq, cb->seq_end);
		pthread_mutex_lock(&tsk->rcv_buf_lock);
		write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
		tsk->rcv_nxt = cb->seq_end;
		tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
		tcp_send_control_packet(tsk, TCP_ACK);
		wake_up(tsk->wait_recv);
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
	}else if(less_than_32b(tsk->rcv_nxt, cb->seq)){
		log(DEBUG, "收包情况三，乱序报文");

	}else{
		log(ERROR, "should not be here.");
	}
}


// 更新拥塞窗口cwnd,慢启动阈值ssthresh等参数.
static inline void tcp_update_cwnd_on_new_ack(struct tcp_sock *tsk)
{
	if (tsk->cwnd < tsk->ssthresh) {
		tsk->cwnd += TCP_MSS;
		log(DEBUG, "慢启动，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
	} else {
		tsk->cwnd += (TCP_MSS * TCP_MSS) / tsk->cwnd;
		log(DEBUG, "拥塞避免，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
	}
}

void tcp_congestion_control(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet){
	if(tsk->c_state == TCP_CA_LOSS){
		tsk->ssthresh = tsk->cwnd / 2;
		if (tsk->ssthresh < TCP_MSS)
			tsk->ssthresh = TCP_MSS;
		tsk->cwnd = TCP_MSS;
		tsk->dup_ack_cnt = 0;
		tsk->c_state = TCP_CA_OPEN;
		log(DEBUG, "超时重传，进入慢启动，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
		return;
	}

	int new_ack = less_than_32b(tsk->snd_una, cb->ack);

	switch (tsk->c_state){
		case TCP_CA_OPEN:
			if(new_ack){
				tsk->dup_ack_cnt = 0;
				tcp_update_cwnd_on_new_ack(tsk);
			} else if(cb->ack == tsk->snd_una && tsk->snd_una < tsk->snd_nxt){
				tsk->dup_ack_cnt++;
				if (tsk->dup_ack_cnt >= 3) {
					tsk->ssthresh = tsk->cwnd / 2;
					if (tsk->ssthresh < TCP_MSS)
						tsk->ssthresh = TCP_MSS;
					tsk->recovery_point = tsk->snd_nxt;
					tsk->cwnd = tsk->ssthresh + 3 * TCP_MSS;
					tsk->c_state = TCP_CA_RECOVERY;
					log(DEBUG, "3个重复ACK，进入快恢复，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
					tcp_retrans_send_buffer(tsk);
				} else {
					tsk->c_state = TCP_CA_DISORDER;
					log(DEBUG, "进入乱序状态，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
				}
			} else {
				log(DEBUG, "收到已确认ACK，无效");
			}
			break;
		case TCP_CA_DISORDER:
			if(new_ack){
				tsk->c_state = TCP_CA_OPEN;
				tsk->dup_ack_cnt = 0;
				tcp_update_cwnd_on_new_ack(tsk);
			} else if(cb->ack == tsk->snd_una){
				tsk->dup_ack_cnt++;
				if(tsk->dup_ack_cnt >= 3){
					tsk->ssthresh = tsk->cwnd / 2;
					if (tsk->ssthresh < TCP_MSS)
						tsk->ssthresh = TCP_MSS;
					tsk->recovery_point = tsk->snd_nxt;
					tsk->cwnd = tsk->ssthresh + 3 * TCP_MSS;
					tsk->c_state = TCP_CA_RECOVERY;
					log(DEBUG, "3个重复ACK，进入快恢复，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
					tcp_retrans_send_buffer(tsk);
				}
			} else {
				log(DEBUG, "收到已确认ACK，无效");
			}
			break;
		case TCP_CA_RECOVERY:
			if(new_ack){
				if(less_or_equal_32b(tsk->recovery_point, cb->ack)){
					tsk->cwnd = tsk->ssthresh;
					tsk->c_state = TCP_CA_OPEN;
					tsk->dup_ack_cnt = 0;
					log(DEBUG, "从快恢复恢复到拥塞避免，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
				} else {
					// Partial ACK
					tsk->cwnd = tsk->ssthresh;
					tsk->c_state = TCP_CA_OPEN;
					tsk->dup_ack_cnt = 0;
					log(DEBUG, "部分ACK，从快恢复恢复到拥塞避免，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
				}
			} else if(cb->ack == tsk->snd_una){
				tsk->cwnd += TCP_MSS;
				log(DEBUG, "快恢复收到重复ACK，cwnd: %d, ssthresh: %d", tsk->cwnd, tsk->ssthresh);
			} else {
				log(DEBUG, "收到已确认ACK，无效");
			}
			break;
		default:
			log(ERROR, "unhandled congestion control state %d", tsk->c_state);
			break;
	}
	tsk->snd_wnd = less_than_32b(tsk->adv_wnd, tsk->cwnd) ? tsk->adv_wnd : tsk->cwnd;
}
