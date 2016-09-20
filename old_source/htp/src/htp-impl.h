#ifndef __HTP_IMPL_HEADERS__
#define __HTP_IMPL_HEADERS__
	

	#include <linux/net.h>
	#include <linux/types.h>
	#include <net/inet_sock.h>
	
	 //use this protocol to alias HTP, in hope that the system doesn't implement it yet
	#define AF_HTP				AF_PHONET
	#define PF_HTP				PF_PHONET
	#define HTP_PROTOCOL_NAME 	"HTP"
	
	struct sock;
	struct socket;
	struct net;
	struct msghdr;
	struct file;
	struct pipe_inode_info;
	struct poll_table_struct;
	struct vm_area_struct;
	struct page;
	
	static int count=0;

	/*	struct proto */
	extern void				htp_close(struct sock* sk, long timeout);
	extern int				htp_connect(struct sock* sk, struct sockaddr* uaddr, int addr_len);
	extern int				htp_disconnect(struct sock* sk, int flags);
	extern struct sock*		htp_accept(struct sock* sk, int flags, int* err);
	extern int				htp_ioctl(struct sock* sk, int cmd, unsigned long arg);
	extern int				htp_init_sock(struct sock* sk);
	extern void				htp_destroy(struct sock* sk);
	extern void				htp_shutdown(struct sock* sk, int how);
	extern int				htp_setsockopt(struct sock* sk, int level, int optname, char* __user optval, unsigned int optlen);
	extern int				htp_getsockopt(struct sock* sk, int level, int optname, char* __user optval, int* __user option);

	extern int				htp_sendmsg(struct sock* sk, struct msghdr* msg, size_t len);
	extern int				htp_recvmsg(struct sock* sk, struct msghdr* msg, size_t len, int noblock, int flags, int* addr_len);
	//extern int			htp_sendpage(struct sock* sk, struct page *page, int offset, size_t size, int flags);
	extern int				htp_bind(struct sock* sk, struct sockaddr* uaddr, int addr_len);
	//extern int			htp_backlog_rcv(struct sock* sk, struct sk_buff* skb);
	//extern void			htp_release_cb(struct sock* sk);
	extern void				htp_hash(struct sock* sk);
	extern void				htp_unhash(struct sock* sk);
	extern void				htp_rehash(struct sock* sk);
	extern int				htp_get_port(struct sock* sk, unsigned short snum);
	extern void				htp_clear_sk(struct sock* sk, int size);

	/*	struct proto_ops	*/
	extern int				htp_ops_release(struct socket* sock);
	extern int				htp_ops_bind(struct socket* sock, struct sockaddr* myaddr, int sockaddr_len);
	extern int				htp_ops_connect(struct socket* sock, struct sockaddr* vaddr, int sockaddr_len, int flags);
	extern int				htp_ops_socketpair(struct socket* sock1, struct socket* sock2);
	extern int				htp_ops_accept(struct socket* sock, struct socket* newsock, int flags);
	extern int				htp_ops_getname(struct socket* sock, struct sockaddr* addr, int *sockaddr_len, int peer);
	extern unsigned int		htp_ops_poll(struct file *file, struct socket* sock, struct poll_table_struct* wait);
	extern int				htp_ops_ioctl(struct socket* sock, unsigned int cmd, unsigned long arg);

	extern int				htp_ops_recvmsg(struct socket* sock, struct msghdr* m, size_t total_len, int flags);
	extern int				htp_ops_mmap(struct file* file, struct socket* sock, struct vm_area_struct* vma);
	extern ssize_t			htp_ops_sendpage(struct socket* sock, struct page* page, int offset, size_t size, int flags);
	extern ssize_t			htp_ops_splice_read(struct socket* sock,  loff_t* ppos, struct pipe_inode_info* pipe, size_t len, unsigned int flags);
	extern int				htp_ops_set_peek_off(struct sock* sk, int val);

	extern int				htp_create_socket(struct net* net, struct socket* sock, int protocol, int kern);

	

	struct htp_sock {
		struct inet_sock isk;
		/* custom new-socket implementation*/
	};

	static struct proto htp_proto = {
		.close = htp_close,
		.connect = htp_connect,
		.disconnect = htp_disconnect,
		.accept = htp_accept,
		.ioctl = htp_ioctl,
		.init = htp_init_sock,
		.shutdown = htp_shutdown,
		.setsockopt = htp_setsockopt,
		.getsockopt = htp_getsockopt,
		.sendmsg = htp_sendmsg,
		.recvmsg = htp_recvmsg,
		.unhash = htp_unhash,
		.get_port = htp_get_port,
		//.enter_memory_pressure = htp_enter_memory_pressure,
		//.sockets_allocated = &sockets_allocated,
		//.memory_allocated = &memory_allocated,
		//.memory_pressure = &memory_pressure,
		//.orphan_count = &orphan_count,
		//.sysctl_mem = sysctl_tcp_mem,
		//.sysctl_wmem = sysctl_tcp_wmem,
		//.sysctl_rmem = sysctl_tcp_rmem,
		.max_header = 0,
		.obj_size = sizeof(struct htp_sock),
		.owner = THIS_MODULE,
		.name = HTP_PROTOCOL_NAME,
	};

	static struct proto_ops htp_proto_ops = {
		.family = PF_INET,
		.owner = THIS_MODULE,
		.release = htp_ops_release,
		.bind = htp_ops_bind,
		.connect = htp_ops_connect,
		.socketpair = sock_no_socketpair,
		.accept = htp_ops_accept,
		.getname = htp_ops_getname,
		.poll = htp_ops_poll,
		.ioctl = htp_ops_ioctl,
		//.listen = htp_inet_listen,
		//.shutdown = htp_ops_shutdown,
		//.setsockopt = htp_ops_setsockopt,
		//.getsockopt = htp_ops_getsockopt,
		//.sendmsg = htp_ops_sendmsg,
		//.recvmsg = htp_ops_recvmsg,
	};

	static struct net_proto_family 	htp_proto_family = {
		.family = AF_HTP, //by modifying 
		.create = htp_create_socket,
		.owner = THIS_MODULE,
	};

#endif
