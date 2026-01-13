#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include "log.h"
#include <stdio.h>
#include <unistd.h>

#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)
static struct list_head timer_list[3];
static pthread_mutex_t timer_list_lock; // 添加锁

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// struct tcp_timer *t, *tmp;
	// struct tcp_sock *tsk;

	// list_for_each_entry_safe(t, tmp, &timer_list, list) {
	// 	t->timeout -= TCP_TIMER_SCAN_INTERVAL;
	// 	if (t->timeout <= 0) {
	// 		list_delete_entry(&t->list);
	// 		tsk = timewait_to_tcp_sock(t);
	// 		if (!tsk->parent) tcp_bind_unhash(tsk);
	// 		tcp_set_state(tsk, TCP_CLOSED);
	// 		free_tcp_sock(tsk);
	// 	}
	// 	else if(tsk->timeout <= 0 && )
	// }
	struct tcp_sock *tsk, *tmp;
	if(list_empty(&timer_list[0]) && list_empty(&timer_list[1]) && list_empty(&timer_list[2])){
		return;
	}
	list_for_each_entry_safe(tsk, tmp, &timer_list[0], timewait.list){
		if(tsk->timewait.type == 0 && tsk->timewait.enable == 1){
			if(tsk->timewait.timeout > TCP_TIMEWAIT_TIMEOUT){
				tcp_unset_retrans_timer_no_lock(tsk);
				tcp_set_state(tsk, TCP_CLOSED);

				list_delete_entry(&tsk->timewait.list);
				tcp_unhash(tsk);
			}
			else {
				tsk->timewait.timeout += TCP_TIMER_SCAN_INTERVAL;
			}
		}
	}
		list_for_each_entry_safe(tsk, tmp, &timer_list[1], retrans_timer.list){
		if(tsk->retrans_timer.type == 1 && tsk->retrans_timer.enable == 1){
			if(tsk->retrans_timer.timeout > 0){
				tsk->retrans_timer.timeout -= TCP_TIMER_SCAN_INTERVAL;
			}else{
				if(tsk->retrans_timer.retran_times >= 3){
					log(DEBUG, "重传次数超过3次，关闭连接");
					list_delete_entry(&tsk->retrans_timer.list);
					pthread_mutex_unlock(&timer_list_lock);
					pthread_mutex_lock(&tsk->sk_lock);
					tcp_send_reset(tsk);
					tcp_unset_retrans_timer_no_lock(tsk);
					tcp_set_state(tsk, TCP_CLOSED);
					wake_up(tsk->wait_send);
					wake_up(tsk->wait_recv);
					wake_up(tsk->wait_accept);
					wake_up(tsk->wait_connect);
					pthread_mutex_unlock(&tsk->sk_lock); //这里有点奇怪
					tcp_unhash(tsk);
					pthread_mutex_lock(&timer_list_lock);
				}else{
					tsk->retrans_timer.retran_times += 1;
					log(DEBUG, "重传超时，进行第%d次重传", tsk->retrans_timer.retran_times);
					tcp_retrans_send_buffer(tsk); //等待你的实现
					tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL * (tsk->retrans_timer.retran_times + 1);
					log(DEBUG, "已经重传");
				}
			}
		}
	}
	list_for_each_entry_safe(tsk, tmp, &timer_list[2], persist_timer.list){
		if(tsk->persist_timer.type == 2 && tsk->persist_timer.enable == 1){
			if(tsk->persist_timer.timeout > 0){
				tsk->persist_timer.timeout -= TCP_TIMER_SCAN_INTERVAL;
			}else{
				if(tsk->state != TCP_ESTABLISHED){
					log(DEBUG, "tcp 连接已关闭");
					tsk->persist_timer.enable = 0;
					list_delete_entry(&tsk->persist_timer.list);
					free_tcp_sock(tsk);
				}else if(tsk->snd_wnd < TCP_MSS){
					log(DEBUG, "发送窗口过小，发送探测报文");
					tcp_send_probe_packet(tsk);
					tsk->persist_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
				}
			}
		}
	}

}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// struct tcp_timer *t = &tsk->timewait;
	// t->type = 0;
	// t->timeout = TCP_TIMEWAIT_TIMEOUT;
	// list_add_tail(&t->list, &timer_list);
	// tsk->ref_cnt++;
	tsk->timewait.type = 0;
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = 0;
	pthread_mutex_lock(&timer_list_lock);
	list_add_tail(&tsk->timewait.list, &timer_list[0]);
	pthread_mutex_unlock(&timer_list_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list[0]);
	init_list_head(&timer_list[1]);
	init_list_head(&timer_list[2]);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		pthread_mutex_lock(&timer_list_lock);
		tcp_scan_timer_list();
		pthread_mutex_unlock(&timer_list_lock);
	}

	return NULL;
}

// void tcp_set_retrans_timer(struct tcp_sock *tsk){
// 	struct tcp_timer *timer = &tsk->retrans_timer;

// 	timer->type = 1;
// 	timer->timeout = TCP_RETRANS_INTERVAL_INITIAL;
// 	timer->retrans_number = 0;

// 	list_add_tail(&timer->list, &timer_list);
// }

// void tcp_unset_retrans_timer(struct tcp_sock *tsk){
// 	list_delete_entry(&tsk->retrans_timer.list);
// }


/*
1. 如果已经启用，则更新超时时间为当前的RTO后退出
2. 创建定时器，设置各个成员变量，初始RTO为TCP_RETRANS_INTERVAL_INITIAL。
3. 增加tsk的引用计数，将定时器加入timer_list末尾
*/
void tcp_set_retrans_timer(struct tcp_sock *tsk){
	if(tsk->retrans_timer.enable == 1){
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		return;
	}
	tsk->retrans_timer.type = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.retran_times = 0;
	tsk->ref_cnt += 1;
	pthread_mutex_lock(&timer_list_lock);
	list_add_tail(&tsk->retrans_timer.list, &timer_list[1]);
	pthread_mutex_unlock(&timer_list_lock);
	log(DEBUG, "设置重传定时器");
}

/*
1. 如果已经禁用，不做任何事
2. 调用free_tcp_sock减少tsk引用计数，并从链表中移除timer
*/
void tcp_unset_retrans_timer(struct tcp_sock *tsk){
	if(tsk->retrans_timer.enable == 0) return;
	tsk->retrans_timer.enable = 0;
	free_tcp_sock(tsk);
	pthread_mutex_lock(&timer_list_lock);
	list_delete_entry(&tsk->retrans_timer.list);
	pthread_mutex_unlock(&timer_list_lock);
	log(DEBUG, "禁用重传定时器");
}

void tcp_unset_retrans_timer_no_lock(struct tcp_sock *tsk){
	if(tsk->retrans_timer.enable == 0) return;
	tsk->retrans_timer.enable = 0;
	free_tcp_sock(tsk);
	list_delete_entry(&tsk->retrans_timer.list);
	log(DEBUG, "禁用重传定时器");
}


/*
1. 确认定时器是启用状态
2. 如果发送队列为空，则删除定时器，并且唤醒发送数据的进程。否则重置计时器，包括timeout和重传计数。

注意调用这个函数之前，需要完成对发送队列的更新。
*/
void tcp_update_retrans_timer(struct tcp_sock *tsk){
	if(tsk->retrans_timer.enable == 0) return;
	pthread_mutex_lock(&tsk->send_buf_lock);
	if(list_empty(&tsk->send_buf)){
		tcp_unset_retrans_timer(tsk);
		wake_up(tsk->wait_send);
		log(DEBUG, "发送队列为空，删除重传定时器");
	}else{
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		tsk->retrans_timer.retran_times = 0;
		log(DEBUG, "重置重传定时器");
	}
	pthread_mutex_unlock(&tsk->send_buf_lock);
}

void tcp_set_persist_timer(struct tcp_sock *tsk){
	if(tsk->persist_timer.enable == 1){
		tsk->persist_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		return;
	}
	tsk->persist_timer.type = 2;
	tsk->persist_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->persist_timer.enable = 1;
	tsk->ref_cnt += 1;
	pthread_mutex_lock(&timer_list_lock);
	list_add_tail(&tsk->persist_timer.list, &timer_list[2]);
	pthread_mutex_unlock(&timer_list_lock);
	log(DEBUG, "设置persist定时器");
}

void tcp_unset_persist_timer(struct tcp_sock *tsk){
	if(tsk->persist_timer.enable == 0) return;
	tsk->persist_timer.enable = 0;
	free_tcp_sock(tsk);
	pthread_mutex_lock(&timer_list_lock);
	list_delete_entry(&tsk->persist_timer.list);
	pthread_mutex_unlock(&timer_list_lock);
	log(DEBUG, "禁用persist定时器");
}
