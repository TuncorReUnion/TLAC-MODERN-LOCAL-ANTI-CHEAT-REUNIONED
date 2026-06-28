#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/timer.h>


static int check_system_integrity(void) {
    struct file *f;
    char *buffer;
    loff_t pos = 0;
    int found = 0;
    ssize_t bytes;

    f = filp_open("/proc/modules", O_RDONLY, 0);
    if (IS_ERR(f))
    {
        printk(KERN_ERR "TLAC: /proc/modules açılamadı.\n");
        return -1;
    }

    buffer = kmalloc(4096, GFP_KERNEL);
    if (!buffer)
    {
        filp_close(f, NULL);
        return -ENOMEM;
    }

    bytes = kernel_read(f, buffer, 4096, &pos);
    if (bytes > 0)
    {
        buffer[bytes] = '\0';
        if (strstr(buffer, "rootkit") || strstr(buffer, "suspicious"))
        {
            printk(KERN_WARNING "TLAC: Şüpheli modül bulundu!\n");
            found = 1;
        }
    }

    kfree(buffer);
    filp_close(f, NULL);
    return found;
}

static int tlac_status_show(struct seq_file *m, void *v)
{
    int integrity = check_system_integrity();
    seq_printf(m, "Sistem Bütünlüğü: %s\n", integrity == 0 ? "TEMİZ" : "ŞÜPHELİ");
    return 0;
}

static int tlac_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, tlac_status_show, NULL);
}

static const struct proc_ops tlac_status_proc_ops =
{
    .proc_open = tlac_status_open,
    .proc_read = seq_read,
    .proc_release = single_release,
};

static struct timer_list tlac_timer;
static void tlac_timer_callback(struct timer_list *t)
{
    printk(KERN_INFO "TLAC: Periyodik sistem kontrolü başlatılıyor...\n");
    check_system_integrity();
    mod_timer(&tlac_timer, jiffies + (3 * 60 * 60 * HZ));
}

// Modül başlatma fonksiyonu
static int __init tlac_init(void)
{
    printk(KERN_INFO "TLAC Kernel Module: Başlatıldı.\n");

    proc_create("tlac_status", 0444, NULL, &tlac_status_proc_ops);

    timer_setup(&tlac_timer, tlac_timer_callback, 0);
    mod_timer(&tlac_timer, jiffies + (3 * 60 * 60 * HZ));

    check_system_integrity();
    return 0;
}

static void __exit tlac_exit(void)
{
    timer_shutdown_sync(&tlac_timer);
    remove_proc_entry("tlac_status", NULL);
    printk(KERN_INFO "TLAC Kernel Module: Kaldırıldı.\n");
}

module_init(tlac_init);
module_exit(tlac_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TuncorReUnion");
MODULE_DESCRIPTION("TLAC Kernel Module - Sistem bütünlüğü kontrolü");
