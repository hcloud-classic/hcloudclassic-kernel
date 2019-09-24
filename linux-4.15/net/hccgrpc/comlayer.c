#include <linux/kernel.h>
#include <linux/tipc.h>

int comlayer_init(void) {

    printk(KERN_INFO "HCC: comlayer_init");
    return 0;
}