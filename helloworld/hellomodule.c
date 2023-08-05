/*helloworld.c*/
#include <linux/module.h>    //指针模块机制的关键
#include <linux/kernel.h>   
#include <linux/init.h>  

//模块初始化的编译修饰符  __init  执行完就回收内存
static int __init hello_init(void)
{
        printk("Hello World.\n");
        return 0;
}

//模块的退出和
static void hello_exit(void)
{
        printk("Bye Bye.\n");
}
 
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");