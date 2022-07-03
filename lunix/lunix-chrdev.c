/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * Nikitas Tsinnas
 * Nikolaos Pagonas
 */

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */

struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;

	WARN_ON(!(sensor = state->sensor));

	if (state->buf_timestamp != sensor->msr_data[state->type]->last_update)
		return 1;

	return 0;
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;

	WARN_ON(!(sensor = state->sensor));

	int type = state->type;
	uint32_t data;
	uint32_t timestamp;

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */

	spin_lock(&sensor->lock);

	data = sensor->msr_data[type]->values[0];
	timestamp = sensor->msr_data[type]->last_update;

	spin_unlock(&sensor->lock);

	/*
	 * Any new data available?
	 */

	if (state->buf_timestamp == timestamp)
		return -EAGAIN;

	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */

	long lookup_value;

	switch (type) {
		case BATT:
			lookup_value = lookup_voltage[data];
			break;
		case TEMP:
			lookup_value = lookup_temperature[data];
			break;
		case LIGHT:
			lookup_value = lookup_light[data];
			break;
	}

	int integer_part = lookup_value / 1000;
	int decimal_part = lookup_value > 0 ? lookup_value % 1000 : -lookup_value % 1000;

	state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%d.%d\n", integer_part, decimal_part);
	state->buf_timestamp = timestamp;

	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret;

	ret = -ENODEV;

	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */

	unsigned int minor = iminor(inode);

	/* Allocate a new Lunix character device private state structure */

	struct lunix_chrdev_state_struct *state;
	state = (struct lunix_chrdev_state_struct *) kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);

	/* Fill all fields of lunix_chrdev_state_struct */
	state->type = minor & 7; /* ...xxx & ...111, τα 3 LSB */
	state->sensor = &lunix_sensors[minor >> 3]; /* xxx... -> xxx, we "forget" 3 LSB */
	state->buf_lim = 0;
	state->buf_data[0] = '\0'; 
	state->buf_timestamp = 0;
	sema_init(&state->lock, 1);

	filp->private_data = state;
out:
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Technically not implemented */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	if (down_interruptible(&state->lock))
		return -ERESTARTSYS;

	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* The process needs to sleep */
			
			up(&state->lock);

			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
				return -ERESTARTSYS;

			if (down_interruptible(&state->lock))
				return -ERESTARTSYS;
		}
	}

	/* Determine the number of cached bytes to copy to userspace */
	int bytes_left = state->buf_lim - *f_pos;

	cnt = min(cnt, bytes_left);

	if (copy_to_user(usrbuf, state->buf_data, cnt)) {
		ret = -EFAULT;
		goto out;
	}

	*f_pos += cnt;
	ret = cnt;

	/* Auto-rewind on EOF mode? */

	if (*f_pos == state->buf_lim)
		*f_pos = 0;

out:
	up(&state->lock);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	/* Technically not implemented */
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = {
    .owner = THIS_MODULE,
    .open = lunix_chrdev_open,
    .release = lunix_chrdev_release,
    .read = lunix_chrdev_read,
    .unlocked_ioctl = lunix_chrdev_ioctl,
    .mmap = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements /
	 * sensor) beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;

	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	/* initializing character device */

	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");
	if (ret < 0) {
		/* failed to register region */
		goto out;
	}
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	if (ret < 0) {
		/* failed to add character device */
		goto out_with_chrdev_region;
	}
	/* completed successfully */
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);

	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
}
