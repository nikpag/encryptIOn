/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 * Nikos Pagonas <nikospagonas00@gmail.com>
 * Nikitas Tsinnas <nikitsin2000@gmail.com>
 *
 */
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/wait.h>

#include "crypto-chrdev.h"
#include "crypto.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */

struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode, return the crypto device
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);

	list_for_each_entry(crdev, &crdrvdata.devs, list)
	{
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int num_out, num_in;
	unsigned int len;

	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct virtqueue *vq;

	struct scatterlist
	    syscall_type_sg,
	    host_fd_sg,
	    *sgs[2];

	unsigned int *syscall_type;
	int *host_fd; 

	unsigned long flags;

	num_out = 0;
	num_in = 0;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1; 

	ret = -ENODEV;

	if ((ret = nonseekable_open(inode, filp)) < 0) {
		goto out;
	}

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", iminor(inode));
		ret = -ENODEV;
		goto out;
	}

	vq = crdev->vq;

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto out;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the
	 * file descriptor from the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	spin_lock_irqsave(&crdev->lock, flags); 

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
				&syscall_type_sg, GFP_ATOMIC);

	virtqueue_kick(vq);

	while (virtqueue_get_buf(vq, &len) == NULL)
		; /* do nothing */

	spin_unlock_irqrestore(&crdev->lock, flags);

	/* If host failed to open() return -ENODEV. */
	if (crof->host_fd < 0) {
		debug("Host failed to open the crypto device");
		ret = -ENODEV;
		goto out;
	}

	debug("Host opened /dev/crypto file with fd = %d", crof->host_fd); /* change msg */
out:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;

	unsigned int *syscall_type;

	struct scatterlist
	    syscall_type_sg,
	    host_fd_sg,
	    *sgs[2];

	unsigned int len, num_out, num_in;
	unsigned long flags;
	int err;

	num_out = 0;
	num_in = 0;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;

	spin_lock_irqsave(&crdev->lock, flags);

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
				&syscall_type_sg, GFP_ATOMIC);

	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(vq, &len) == NULL)
		; /* do nothing */

	spin_unlock_irqrestore(&crdev->lock, flags);

	debug("Host closed /dev/crypto with fd = %d\n", crof->host_fd);

	kfree(crof);
	debug("Leaving");
	return ret;
}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	int i;
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;

	struct virtqueue *vq = crdev->vq;

	struct scatterlist
	    syscall_type_sg,
	    host_fd_sg,
	    ioctl_cmd_sg,
	    session_key_sg,
	    session_op_sg,
	    host_return_val_sg,
	    ses_id_sg,
	    crypt_op_sg,
	    src_sg,
	    iv_sg,
	    dst_sg,
	    *sgs[12];

	unsigned int num_out, num_in, len;

	unsigned int *syscall_type = NULL;
	int *host_fd = NULL;
	unsigned int *ioctl_cmd = NULL;
	unsigned char *session_key = NULL;
	struct session_op *session_op = NULL;
	int *host_return_val = kmalloc(sizeof(*host_return_val), GFP_KERNEL);
	u32 *ses_id = NULL;
	struct crypt_op *crypt_op = NULL;
	unsigned char *src = NULL;
	unsigned char *iv = NULL;
	unsigned char *dst = NULL;
	unsigned char *saved_key = NULL;

	char bytes;
	unsigned long flags;

	num_out = 0;
	num_in = 0;
	*host_return_val = -1;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;

	/**
	 *  These are common to all ioctl commands.
	 **/

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
		case CIOCGSESSION:
			debug("CIOCGSESSION");

			ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
			*ioctl_cmd = VIRTIO_CRYPTODEV_SYSCALL_IOCTL_CIOCGSESSION;

			session_op = kzalloc(sizeof(*session_op), GFP_KERNEL);
			if (copy_from_user(session_op, (struct session_op *)arg, sizeof(*session_op))) {
				debug("Copy session_op from user failed");
				ret = -EFAULT;
				goto out;
			}

			session_key = kzalloc(session_op->keylen, GFP_KERNEL);
			if (copy_from_user(session_key, session_op->key, session_op->keylen)) {
				debug("Copy session_key from user failed");
				ret = -EFAULT;
				goto out;
			}

			saved_key = session_op->key; 
			session_op->key = session_key;

			sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
			sgs[num_out++] = &ioctl_cmd_sg;
			sg_init_one(&session_key_sg, session_key, session_op->keylen);
			sgs[num_out++] = &session_key_sg;

			sg_init_one(&session_op_sg, session_op, sizeof(*session_op));
			sgs[num_out + num_in++] = &session_op_sg;
			sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
			sgs[num_out + num_in++] = &host_return_val_sg;

			break;

		case CIOCFSESSION:
			debug("CIOCFSESSION");

			ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
			*ioctl_cmd = VIRTIO_CRYPTODEV_SYSCALL_IOCTL_CIOCFSESSION;

			ses_id = kmalloc(sizeof(ses_id), GFP_KERNEL);
			if (copy_from_user(ses_id, (uint32_t *)arg, sizeof(*ses_id))) {
				debug("Copy ses_id from user failed");
				ret = -EFAULT;
				goto out;
			}

			sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
			sgs[num_out++] = &ioctl_cmd_sg;
			sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
			sgs[num_out++] = &ses_id_sg;

			sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
			sgs[num_out + num_in++] = &host_return_val_sg;

			break;
		case CIOCCRYPT:
			debug("CIOCCRYPT");

			ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
			*ioctl_cmd = VIRTIO_CRYPTODEV_SYSCALL_IOCTL_CIOCCRYPT;

			crypt_op = kmalloc(sizeof(*crypt_op), GFP_KERNEL);
			if (copy_from_user(crypt_op, (struct crypt_op *)arg, sizeof(*crypt_op))) {
				debug("Copy crypt_op from user failed");
				ret = -EFAULT;
				goto out;
			}

			src = kzalloc(crypt_op->len, GFP_KERNEL);
			if (copy_from_user(src, crypt_op->src, crypt_op->len)) {
				debug("Copy src from user failed");
				ret = -EFAULT;
				goto out;
			}

			iv = kzalloc(EALG_MAX_BLOCK_LEN, GFP_KERNEL);
			if (copy_from_user(iv, crypt_op->iv, EALG_MAX_BLOCK_LEN)) {
				debug("Copy iv from user failed");
				ret = -EFAULT;
				goto out;
			}

			dst = kzalloc(crypt_op->len, GFP_KERNEL);

			sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
			sgs[num_out++] = &ioctl_cmd_sg;
			sg_init_one(&crypt_op_sg, crypt_op, sizeof(*crypt_op));
			sgs[num_out++] = &crypt_op_sg;
			sg_init_one(&src_sg, src, crypt_op->len);
			sgs[num_out++] = &src_sg;
			sg_init_one(&iv_sg, iv, EALG_MAX_BLOCK_LEN);
			sgs[num_out++] = &iv_sg;

			sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
			sgs[num_out + num_in++] = &host_return_val_sg;
			sg_init_one(&dst_sg, dst, crypt_op->len);
			sgs[num_out + num_in++] = &dst_sg;

			break;

		default:
			debug("Unsupported ioctl command");
			break;
	}

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? Lock ?? */

	spin_lock_irqsave(&crdev->lock, flags);

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);

	virtqueue_kick(vq);

	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;

	spin_unlock_irqrestore(&crdev->lock, flags);

	switch (cmd) {
		case CIOCGSESSION:
			session_op->key = saved_key;
			if (copy_to_user((struct session_op *)arg, session_op, sizeof(*session_op))) {
				debug("Copy to user failed");
				ret = -EFAULT;
				goto out;
			}
			break;
		case CIOCFSESSION:
			if (copy_to_user((uint32_t *)arg, ses_id, sizeof(*ses_id))) {
				debug("Copy to user failed");
				ret = -EFAULT;
				goto out;
			}
			break;
		case CIOCCRYPT:
			if (copy_to_user(((struct crypt_op *)arg)->dst, dst, crypt_op->len)) {
				debug("Copy to user failed");
				ret = -EFAULT;
				goto out;
			}
			break;

		default:
			debug("Unsupported ioctl command (2nd)");
			break;
	}

	ret = *host_return_val;

out:
	kfree(host_return_val);
	kfree(syscall_type);
	kfree(ioctl_cmd);
	kfree(session_op);
	kfree(session_key);
	kfree(ses_id);
	kfree(crypt_op);
	kfree(src);
	kfree(iv);
	kfree(dst);

	debug("Leaving ioctl with ret value %ld", ret);

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = {
    .owner = THIS_MODULE,
    .open = crypto_chrdev_open,
    .release = crypto_chrdev_release,
    .read = crypto_chrdev_read,
    .unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("Initializing character device...");

	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);

	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}

	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);

	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
