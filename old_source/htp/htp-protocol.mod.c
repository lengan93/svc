#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x2ab9dba5, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x96ebc7f0, __VMLINUX_SYMBOL_STR(sock_init_data) },
	{ 0x6bbd621f, __VMLINUX_SYMBOL_STR(sock_no_socketpair) },
	{ 0xd63ab38, __VMLINUX_SYMBOL_STR(sk_alloc) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x19406908, __VMLINUX_SYMBOL_STR(proto_register) },
	{ 0xde152605, __VMLINUX_SYMBOL_STR(sock_register) },
	{ 0x4b1984f0, __VMLINUX_SYMBOL_STR(proto_unregister) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x62737e1d, __VMLINUX_SYMBOL_STR(sock_unregister) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

