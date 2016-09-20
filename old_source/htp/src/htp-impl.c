#include "htp-impl.h"

void htp_close(struct sock* sk, long timeout){
}

int htp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	return 0;
}

int htp_disconnect(struct sock *sk, int flags){
	return 0;
}

struct sock* htp_accept(struct sock *sk, int flags, int *err){
	return 0;
}

int htp_ioctl(struct sock *sk, int cmd, unsigned long arg){
	return 0;
}


int htp_init_sock(struct sock *sk){
	return 0;
}

void htp_destroy(struct sock *sk){
}

void htp_shutdown(struct sock *sk, int how){
}

int	htp_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen){
	return 0;
}

int	htp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *option){
	return 0;
}

int htp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len){
	return 0;
}

int htp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len){
	return 0;
}

//extern int			htp_sendpage(struct sock *sk, struct page *page, int offset, size_t size, int flags);
int htp_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	return 0;
}

//extern int			htp_backlog_rcv(struct sock *sk, struct sk_buff *skb);
//extern void			htp_release_cb(struct sock *sk);
void htp_hash(struct sock *sk){

}

void htp_unhash(struct sock *sk){
}

void htp_rehash(struct sock *sk){
}

int htp_get_port(struct sock *sk, unsigned short snum){
	return 0;
}

void htp_clear_sk(struct sock *sk, int size){
}


/*	struct proto_ops	*/
int	htp_ops_release(struct socket *sock){
	return 0;
}

int htp_ops_bind(struct socket *sock, struct sockaddr *myaddr, int sockaddr_len){
	return 0;
}

int	htp_ops_connect(struct socket *sock, struct sockaddr *vaddr, int sockaddr_len, int flags){
	return 0;
}

int	htp_ops_socketpair(struct socket *sock1, struct socket *sock2){
	return 0;
}

int htp_ops_accept(struct socket *sock, struct socket *newsock, int flags){
	return 0;
}

int	htp_ops_getname(struct socket *sock, struct sockaddr *addr, int *sockaddr_len, int peer){
	return 0;
}

unsigned int htp_ops_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait){
	return 0;
}

int htp_ops_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg){
	return 0;
}

int	htp_ops_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len, int flags){
	return 0;
}

int	htp_ops_mmap(struct file *file, struct socket *sock, struct vm_area_struct * vma){
	return 0;
}

ssize_t	htp_ops_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags){
	return 0;
}

ssize_t	htp_ops_splice_read(struct socket *sock,  loff_t *ppos, struct pipe_inode_info *pipe, size_t len, unsigned int flags){
	return 0;
}

int htp_ops_set_peek_off(struct sock *sk, int val){
	return 0;
}

int	htp_create_socket(struct net *net, struct socket *sock, int protocol, int kern){

	count++;
	
	printk(KERN_ALERT "htp_create_socket called %d, kernel = %d", count, kern);
	struct sock* sk;
	
	sk = sk_alloc(net, PF_HTP, GFP_KERNEL, &htp_proto);
	if (!sk){
		printk(KERN_ALERT "htp_create_socket failed");
		return -ENOMEM;
	}
	
	sock_init_data(sock, sk);
	/*	this is simply a number to distinguish this socket type again other possible types in the family
		as we have only one socket type of this family, can be set to 0
	 */
	sk->sk_protocol = 0;
	sock->ops = &htp_proto_ops;
	sock->state = SS_UNCONNECTED;
	
	//additional socket init
	
	printk(KERN_ALERT "htp_create_socket success");
	
	return 0;
}





