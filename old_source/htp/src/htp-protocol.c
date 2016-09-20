
#include "htp-impl.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

//MODULE_LICENCE("GPL");

//extern struct net_proto_family htp_proto_family;
//extern struct proto_ops htp_proto_ops;

static int proto_register_status;
static int sock_register_status;

/*	INIT MODULE	*/
static int __init htp_init(void){
	//register new protocol to kernel's protocol stack
	proto_register_status = proto_register(&htp_proto, 1);	
	if (proto_register_status!=0)
		goto register_fail;

	//register new socket to kernel

	sock_register_status = sock_register(&htp_proto_family);
	if (sock_register_status!=0)
		goto register_fail;
			
	//init 4 static message queue??
	
	goto register_success;
	
	register_fail:
		printk(KERN_ALERT "HTP registering failed.\n");
		return proto_register_status | sock_register_status;
	
	register_success:
		printk(KERN_ALERT "HTP registered to kernel. Start listening.\n");
		return proto_register_status | sock_register_status;
}

/*	EXIT MODULE	*/
static void __exit htp_exit(void){
	
	//unregister socket
	if (sock_register_status==0){
		sock_unregister(AF_HTP);
	}
	//unregister proto
	if (proto_register_status==0){
		proto_unregister(&htp_proto);
	}
	
	printk(KERN_ALERT "HTP unregistered. Module exit.\n");
}

module_init(htp_init);
module_exit(htp_exit);

