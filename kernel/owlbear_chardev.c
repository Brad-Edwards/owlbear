// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_chardev.c - Character device for daemon communication
 *
 * Provides /dev/owlbear for the userspace daemon to:
 *   - read() events from the kernel ring buffer (blocking)
 *   - ioctl() to set target PID, enforcement mode, query status
 *
 * Only one consumer (daemon) should open the device at a time.
 * Multiple opens are allowed but all readers share the same ring buffer,
 * which means events may be split across readers unpredictably.
 */

#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

#include "owlbear_common.h"

/* Forward declarations */
static int     owl_dev_open(struct inode *inode, struct file *file);
static int     owl_dev_release(struct inode *inode, struct file *file);
static ssize_t owl_dev_read(struct file *file, char __user *buf,
			    size_t count, loff_t *pos);
static unsigned int owl_dev_poll(struct file *file, poll_table *wait);
static long    owl_dev_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg);

static const struct file_operations owl_fops = {
	.owner          = THIS_MODULE,
	.open           = owl_dev_open,
	.release        = owl_dev_release,
	.read           = owl_dev_read,
	.poll           = owl_dev_poll,
	.unlocked_ioctl = owl_dev_ioctl,
};

/* -------------------------------------------------------------------------
 * Device lifecycle
 * ----------------------------------------------------------------------- */

static int owl_dev_open(struct inode *inode, struct file *file)
{
	pr_debug("owlbear: device opened by pid %d\n", current->pid);
	return 0;
}

static int owl_dev_release(struct inode *inode, struct file *file)
{
	pr_debug("owlbear: device closed by pid %d\n", current->pid);
	return 0;
}

/* -------------------------------------------------------------------------
 * read() — blocking event consumption
 *
 * The daemon calls read() to receive events. Each read returns exactly
 * one struct owlbear_event (128 bytes). If no events are available,
 * the call blocks until an event arrives (or a signal interrupts).
 *
 * The buffer must be at least sizeof(struct owlbear_event) bytes.
 * Partial reads are not supported — if the buffer is too small,
 * -EINVAL is returned.
 * ----------------------------------------------------------------------- */

static ssize_t owl_dev_read(struct file *file, char __user *buf,
			    size_t count, loff_t *pos)
{
	struct owlbear_event event;
	int ret;

	if (count < sizeof(event))
		return -EINVAL;

	if (!owl.ring)
		return -EIO;

	/* Block until an event is available or we're interrupted */
	if (file->f_flags & O_NONBLOCK) {
		ret = ring_consume(owl.ring, &event);
		if (ret == -EAGAIN)
			return -EAGAIN;
	} else {
		ret = wait_event_interruptible(owl.wait_queue,
					       ring_available(owl.ring) > 0);
		if (ret)
			return -ERESTARTSYS;

		ret = ring_consume(owl.ring, &event);
		if (ret)
			return -EIO; /* Should not happen after wake */
	}

	if (copy_to_user(buf, &event, sizeof(event)))
		return -EFAULT;

	return sizeof(event);
}

/* -------------------------------------------------------------------------
 * poll() — allows daemon to use epoll/select on the device fd
 * ----------------------------------------------------------------------- */

static unsigned int owl_dev_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(file, &owl.wait_queue, wait);

	if (owl.ring && ring_available(owl.ring) > 0)
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

/* -------------------------------------------------------------------------
 * ioctl() — control interface
 * ----------------------------------------------------------------------- */

static long owl_dev_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case OWL_IOC_SET_TARGET: {
		__u32 pid;

		if (copy_from_user(&pid, uarg, sizeof(pid)))
			return -EFAULT;

		/* Basic validation: PID 0 means "clear", otherwise must be > 0 */
		if (pid > PID_MAX_LIMIT)
			return -EINVAL;

		spin_lock(&owl.target_lock);
		owl.target_pid = (pid_t)pid;
		spin_unlock(&owl.target_lock);

		pr_info("owlbear: target PID set to %u\n", pid);
		return 0;
	}

	case OWL_IOC_CLEAR_TARGET: {
		spin_lock(&owl.target_lock);
		owl.target_pid = 0;
		spin_unlock(&owl.target_lock);

		pr_info("owlbear: target PID cleared\n");
		return 0;
	}

	case OWL_IOC_GET_STATUS: {
		struct owl_status status = {};

		spin_lock(&owl.target_lock);
		status.target_pid = (__u32)owl.target_pid;
		spin_unlock(&owl.target_lock);

		status.enforce_mode = owl.enforce;
		status.events_generated = (u32)atomic_read(&owl.events_total);
		status.events_dropped = owl.ring ?
			(u32)atomic_read(&owl.ring->dropped) : 0;
		status.kmod_version = OWL_KMOD_VERSION;

		if (copy_to_user(uarg, &status, sizeof(status)))
			return -EFAULT;

		return 0;
	}

	case OWL_IOC_SET_MODE: {
		__u32 mode;

		if (copy_from_user(&mode, uarg, sizeof(mode)))
			return -EFAULT;

		if (mode > 1)
			return -EINVAL;

		owl.enforce = mode;
		pr_info("owlbear: enforcement mode set to %s\n",
			mode ? "block" : "observe");
		return 0;
	}

	default:
		return -ENOTTY;
	}
}

/* -------------------------------------------------------------------------
 * Subsystem init/exit
 * ----------------------------------------------------------------------- */

int owl_chardev_init(void)
{
	int ret;

	/* Register character device with dynamic major number */
	owl.major = register_chrdev(0, OWL_DEVICE_NAME, &owl_fops);
	if (owl.major < 0) {
		pr_err("owlbear: failed to register chrdev: %d\n", owl.major);
		return owl.major;
	}

	/* Create device class */
	/*
	 * class_create() signature changed in 6.4:
	 *   <6.4: class_create(THIS_MODULE, name)
	 *   >=6.4: class_create(name)
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	owl.dev_class = class_create(OWL_DEVICE_NAME);
#else
	owl.dev_class = class_create(THIS_MODULE, OWL_DEVICE_NAME);
#endif
	if (IS_ERR(owl.dev_class)) {
		ret = PTR_ERR(owl.dev_class);
		pr_err("owlbear: failed to create device class: %d\n", ret);
		goto err_chrdev;
	}

	/* Create device node (/dev/owlbear) */
	owl.dev_device = device_create(owl.dev_class, NULL,
				       MKDEV(owl.major, 0),
				       NULL, OWL_DEVICE_NAME);
	if (IS_ERR(owl.dev_device)) {
		ret = PTR_ERR(owl.dev_device);
		pr_err("owlbear: failed to create device: %d\n", ret);
		goto err_class;
	}

	pr_info("owlbear: chardev registered at /dev/%s (major %d)\n",
		OWL_DEVICE_NAME, owl.major);

	return 0;

err_class:
	class_destroy(owl.dev_class);
	owl.dev_class = NULL;
err_chrdev:
	unregister_chrdev(owl.major, OWL_DEVICE_NAME);
	owl.major = 0;
	return ret;
}

void owl_chardev_exit(void)
{
	if (owl.dev_device) {
		device_destroy(owl.dev_class, MKDEV(owl.major, 0));
		owl.dev_device = NULL;
	}

	if (owl.dev_class) {
		class_destroy(owl.dev_class);
		owl.dev_class = NULL;
	}

	if (owl.major > 0) {
		unregister_chrdev(owl.major, OWL_DEVICE_NAME);
		owl.major = 0;
	}

	pr_info("owlbear: chardev unregistered\n");
}
