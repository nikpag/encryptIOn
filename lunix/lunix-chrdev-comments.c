/*
 * notes.c
 *
 * Notes for lunix-chrdev.c
 *
 * Nikolaos Pagonas
 * Nikitas Tsinnas
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Συναρτήσεις:
 * 
 * lunix_chrdev_state_needs_refresh --> done
 * lunix_chrdev_state_update --> done
 * lunix_chrdev_open --> done
 * lunix_chrdev_release --> done
 * lunix_chrdev_ioctl --> done
 * lunix_chrdev_read --> done
 * lunix_chrdev_mmap --> done
 * lunix_chrdev_init --> done
 * lunix_chrdev_destroy --> done
 */

/*
 * Global data
 */

/*
 * Q: Τι είναι το struct cdev;
 * A: cdev είναι το internal structure που χρησιμοποιεί ο πυρήνας 
 * για να αναπαραστήσει τις συσκευές χαρακτήρων.
 */
struct cdev lunix_chrdev_cdev;

/* 
 * Q: Γιατί οι συναρτήσεις ορίζονται ως static; 
 * A: Γιατί έτσι περιορίζουμε το scope της συνάρτησης 
 * ώστε να είναι εμφανής μόνο από το αρχείο στο οποίο βρίσκεται.
 */

/* 
 * Q: Τι κάνει η lunix_chrdev_state_needs_refresh;
 * A: Κάνει ένα γρήγορο τσεκ (χωρίς κλειδώματα) για να δει αν το chrdev state
 * χρειάζεται να ανανεωθεί με νέες μετρήσεις.
 */

/* 
 * Q: Τι είναι το lunix_chrdev_state_struct;
 * A: Αντιπροσωπεύει το private state για ένα ανοιχτό ειδικό αρχείο.
 */

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	/*
	 * Q: Τι είναι το lunix_sensor_struct;
	 * A: Είναι ένα struct που αντιπροσωπεύει έναν αισθητήρα 
	 * και περιέχει σελίδες που κρατάνε τις πιο πρόσφατες μετρήσεις που έχουν ληφθεί.
	 */
	struct lunix_sensor_struct *sensor;	
	/*
	 * Q: Τι σημαίνει WARN_ON;
	 * A: Αν ισχύει η συνθήκη του WARN_ON, τότε αυτό πετάει ένα backtrace στο kernel log. 
	 */
	WARN_ON(!(sensor = state->sensor));
	
	/* ? --> done */
	if(state->buf_timestamp != sensor->msr_data[state->type]->last_update)
		return 1;

	return 0;  
}

/*
 * Q: Τι κάνει η lunix_chrdev_state_update;
 * A: Ανανεώνει την κατάσταση του character device, 
 * ανάλογα με τα δεδομένα που στέλνει ο αισθητήρας.
 * Προσοχή στα κλειδώματα.
 */

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;

	WARN_ON(!(sensor = state->sensor));
	
	/*
	 * Q: Τι κάνει το debug;
	 * A: Το debug είναι σαν την printk αλλά τυπώνει και το όνομα της συνάρτησης.
	 */
	debug("leaving\n"); 

	/* 
	 * Q: Ποια είναι η διεπαφή του spinlock;
	 * A: 
	 * 
	 * Initialization: 
	 * 		spinlock_t my_lock = SPIN_LOCK_UNLOCKED; (compile time)
	 * 		void spin_lock_init(spinlock_t *lock); (runtime)
	 * 
	 * Entering a critical section:
	 * 		void spin_lock(spinlock_t *lock);
	 * 
	 * Exiting a critical section:
	 *  	void spin_unlock(spinlock_t *lock);   
	 */

	int type = state->type;
	uint32_t data;
	uint32_t timestamp; 

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */

	/* ? --> done */
	spin_lock(&sensor->lock);

	data = sensor->msr_data[type]->values[0];
	timestamp = sensor->msr_data[type]->last_update;

	spin_unlock(&sensor->lock);

	/* Why use spinlocks? See LDD3, p. 119 */

	/*
	 * Any new data available?
	 */
	
	/* ? --> done */
	if(state->buf_timestamp == timestamp)
		return -EAGAIN;
	
	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */

	/* ? --> done */
	long lookup_value;	

	switch(type) {
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

	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

/*
 * Q: Τι είναι τα struct file_operations, struct file και struct inode;
 * A: Το file_operations έχει τις μεθόδους του driver,
 * το file αναπαριστά ένα ανοιχτό αρχείο 
 * και το inode αναπαριστά ένα αρχείο στον δίσκο.
 */

/* 
 * Q: Ποια είναι τα πεδία της δομής file που μας ενδιαφέρουν;
 * A: 
 * 		mode_t f_mode;
 * 			Τα bits του πεδίου f_mode καθορίζουν το είδους της πρόσβασης που επιτρέπεται να
 * 			έχει η διεργασία στο ανοιχτό αρχείο. Για παράδειγμα, αν το αρχείο έχει ανοιχτεί για 
 * 			ανάγνωση, το bit FMODE_READ θα είναι 1 και η παράσταση f_mode & FMODE_READ θα είναι 
 * 			μη μηδενική.
 * 		
 * 		loff_t f_pos;
 * 			Στο πεδίο αυτό αποθηκεύεται η τρέχουσα θέση του δείκτη ανάγνωσης/εγγραφής. Ο 
 * 			τύπος loff_t είναι μια τιμή εύρους 64bit (long long στην ορολογία του gcc). Ο 
 * 			οδηγός μπορεί να διαβάσει την τιμή αυτή αν χρειάζεται να μάθει την τρέχουσα θέση.
 * 			Η μέθοδος llseek (δεν ορίζεται στην δική μας περίπτωση), αναλαμβάνει να ανανεώνει
 * 			την τιμή f_pos. Οι μέθοδοι read και write πρέπει να την ανανεώνουν όταν 
 * 			μεταφέρουν δεδομένα.
 * 
 * 		unsigned short f_flags;
 * 			Τα flags αυτά καθορίζουν κάποιες άλλες ιδιότητες πρόσβασης, όπως O_RDONLY,
 * 			O_NONBLOCK και O_SYNC. Ένας οδηγός ελέγχει συνήθως για το flag των nonblocking 
 * 			λειτουργιών, ενώ τα άλλα σπάνια χρησιμοποιούνται. Όλα τα flags ορίζονται στο
 * 			<linux/fcntl.h>
 * 
 * 		struct file_operations *f_op; 
 * 			Αυτό είναι το πεδίο της δομής file που επιτρέπει την αντιστοίχιση του ανοιχτού 
 * 			αρχείου με συγκεκριμένη δομή file_operations, άρα και με συγκεκριμένο οδηγό 
 * 			συσκευής. Ο πυρήνας αρχικοποιεί τον δείκτη αυτό κατά το άνοιγμα και τον ακολουθεί
 * 			όποτε χρειάζεται να καλέσει κάποια συνάρτηση για να εκτελέσει κάποια λειτουργία πάνω 
 * 			στο ανοιχτό αρχείο. 
 * 
 * 			Δεν προβλέπεται να χρησιμοποιηθεί άμεσα από τον οδηγό συσκευής μας.
 * 
 * 		void *private_data;
 * 			Η κλήση συστήματος open() θέτει τον δείκτη αυτό σε NULL πριν την κλήση της μεθόδου 
 * 			open του οδηγού. Ο οδηγός είναι ελεύθερος να κάνει χρήση του δείκτη αυτού όπως θεωρεί 
 * 			καλύτερο, ακόμα και να τον αγνοήσει εντελώς. Χρησιμοποιείται συνήθως ώστε να 
 * 			αντιστοιχιστεί το ανοιχτό αρχείο σε ιδιωτικές δομές δεδομένων του οδηγού συσκευής.
 * 			Ο δείκτης μπορεί να χρησιμοποιηθεί ώστε να δείχνει σε δεσμευμένα δεδομένα, αλλά 
 * 			αυτά πρέπει να απελευθερωθούν από τη μέθοδο release πριν ο πυρήνας καταστρέψει τη
 * 			δομή file. Ο δείκτης private_data είναι ένας πολύ χρήσιμος τρόπος για να κρατάμε 
 * 			πληροφορίες για την κατάσταση της συσκευής (state information) ανάμεσα στις διάφορες 
 * 			κλήσεις συστήματος. 
 * 
 * 			Στην περίπτωση που εξετάζουμε, θα χρησιμοποιείται ώστε να δείχνει σε δομή τύπου
 * 			lunix_chrdev_state_struct, η οποία περιγράφει την τρέχουσα κατάσταση της συσκευής.
 */

/*
 * Q: Τι κάνει η lunix_chrdev_open;
 * A: Η lunix_chrdev_open είναι η πρώτη μέθοδος που εκτελείται, ακριβώς όταν ανοίγουμε το αρχείο.
 */

/* 
 * Αυτή η συνάρτηση δεν χρειάζεται να οριστεί. Εμείς όμως θα την ορίζουμε,
 * επειδή θέλουμε να ενημερώνεται ο οδηγός για το άνοιγμα της συσκευής, 
 * ώστε να μας δίνεται η ευκαιρία να κάνουμε αρχικοποιήσεις σε δομές δεδομένων
 * του οδηγού.
 * 
 * Με χρήση των μακροεντολών:
 * 
 * unsigned int iminor(struct inode *inode);
 * unsigned int imajor(struct inode *inode);
 * 
 * μπορούμε να ανακτήσουμε τον major και minor number του αρχείου, ώστε το ανοιχτό
 * αρχείο που θα προκύψει να αφορά συγκεκριμένο αισθητήρα και μέτρηση του δικτύου.
 * 
 * Στην περίπτωση που εξετάζουμε, η open οφείλει να δεσμεύει χώρο για την δομή τύπου
 * lunix_chrdev_state_struct που περιγράφει την τρέχουσα κατάσταση της συσκευής,
 * και να τη συνδέει με τη δομή file μέσω του δείκτη private_data.
 */
static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? --> done? */

	/*
	 * Q: Τι σκοπό έχει το ret;
	 * A: Το ret έχει σκοπό να κρατάει την επιστρεφόμενη τιμή της συνάρτησης.
	 * Συνήθως θα γυρίσουμε ret (και όχι 0) αν έχει γίνει κάποιο σφάλμα. 
	 */
	int ret;

	debug("entering\n");

	/* 
	 * Q: Τι σημαίνει ENODEV; 
	 * A: Σημαίνει ότι η συσκευή USB δεν υπάρχει στο σύστημα/έχει φύγει.
	 */
	ret = -ENODEV;

	/* 
	 * Q: Τι κάνει η nonseekable_open();
	 * A: Χρησιμοποιείται όταν η συσκευή που ανοίγουμε δεν έχει νόημα να υποστηρίξει
	 * την llseek (όπως η σειριακή θύρα ttyS0 στην περίπτωσή μας). Επειδή η llseek 
	 * ορίζεται by default, με την nonseekable_open ενημερώνουμε 
	 * τον πυρήνα ότι η συσκευή δεν υποστηρίζει llseek.
	 */
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */

	unsigned int minor = iminor(inode);

	/* Allocate a new Lunix character device private state structure */
	
	/* ? -> done */
	struct lunix_chrdev_state_struct* state;
	state = (struct lunix_chrdev_state_struct*) kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);
	
	/* Fill all fields of lunix_chrdev_state_struct */
	state->type = minor & 7; /* ...xxx & ...111, τα 3 LSB */ 
	state->sensor = &lunix_sensors[minor >> 3]; /* xxx... -> xxx, "ξεχνάμε" τα 3 LSB */ 
	state->buf_lim = 0; 
	state->buf_timestamp = 0; 
	sema_init(&state->lock, 1);

	filp->private_data = state;
out:
	debug("leaving, with ret = %d\n", ret);
	return ret; 
}

/*
 * Q: Τι κάνει η lunix_chrdev_release;
 * A: Καλείται όταν το file/filp structure γίνεται release.
 * Αυτό δεν γίνεται κάθε φορά που κάνουμε close. Αντίθετα, γίνεται όταν
 * όλα τα copies έχουν κλείσει (copies μπορούν να δημιουργηθούν με fork/dup).
 */

/*
 * Αυτή η μέθοδος καλείται όταν όλα τα copies ενός αρχείου έχουν κλείσει,
 * οπότε καταστρέφεται η αντίστοιχη δομή file. Ενώ και πάλι δεν χρειάζεται να οριστεί,
 * εμείς την ορίζουμε ώστε να ενημερωνόμαστε όταν το πρόγραμμα που είχε ανοίξει
 * τη συσκευή μας κλείσει το ανοιχτό αρχείο και να απελευθερώνουμε τους αντίστοιχους πόρους 
 * (δεσμευμένη μνήμη).
 */
static int lunix_chrdev_release(struct inode *inode, struct file *filp) 
{
	/* ? --> done */
	kfree(filp->private_data);
	return 0;
}

/* 
 * Q: Τι κάνει η lunix_chrdev_ioctl;
 * A: Προσφέρει έναν τρόπο για να κληθούν device-specific commands.
 */

/* 
 * Q: Τι είναι οι παράμετροι cmd και arg;
 * A: Το cmd αντιστοιχεί στο command που θέλουμε να περάσουμε στο ioctl, 
 * ενώ το arg είναι τα ορίσματα που θέλουμε να χρησιμοποιήσουμε.
 */

/*
 * Στην περίπτωσή μας ουσιαστικά δεν την ορίζουμε.
 */ 
static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* 
	 * Why? --> Γιατί ουσιαστικά δεν υλοποιούμε την ioctl, οπότε σύμφωνα με τον οδηγό
	 * πρέπει να επιστρέφουμε -EINVAL.
	 */

	/* 
	 * Q: Τι σημαίνει EINVAL; 
	 * A: EINVAL σημαίνει Εrror: INVALid argument.
	 */
	return -EINVAL; 
}

/*
 * Q: Τι κάνει η lunix_chrdev_read;
 * A: Λαμβάνει δεδομένα από την συσκευή.
 */

/* 
 * Q: Τι σημαίνει __user;
 * A: __user είναι ένα annotation το οποίο δηλώνει ότι ο pointer 
 * είναι ένα user-space address που δεν μπορεί να γίνει κατευθείαν dereference.
 * Δεν έχει επίδραση στο compilation, αλλά χρησιμοποιείται από εξωτερικό checking software
 * για να βρεθούν τυχόν λάθη σχετικά με την διαχείριση των user-space addresses.
 */

/*
 * Q: Τι είναι το f_pos;
 * A: Το f_pos είναι η τωρινή θέση ανάγνωσης. 
 * Ο driver μπορεί να την διαβάζει αλλά κανονικά δεν επιτρέπεται να την γράφει.
 */

/*
 * Η μέθοδος αυτή είναι η καρδιά της υλοποίησης. Χρειάζεται να λαμβάνει δεδομένα από τους sensor
 * buffers, να φροντίζει για την σωστή μορφοποίησή τους και να τα περνά στον χώρο χρήστη. Δείτε και
 * την αντίστοιχη υλοποίηση στο ldd3.
 * 
 * Χρήσιμες θα φανούν οι συναρτήσεις copy_from_user() και copy_to_user(),
 * οι οποίες κάνουν ασφαλή αντιγραφή δεδομένων. Περισσότερα στην σελ. 64 του ldd3.
 * 
 * Επίσης, ένα από τα σημαντικότερα προβλήματα είναι τι θα συμβαίνει
 * όταν δεν υπάρχουν διαθέσιμα δεδομένα μετρήσεων και κάποια διεργασία 
 * εκτελέσει την κλήση συστήματος read(). Ο οδηγός θα πρέπει να κοιμίζε
 * την διεργασία, και αυτή θα πρέπει να μετακινείται σε χωριστή ουρά διεργασιών,
 * ανάλογα με τον αισθητήρα απ' όπου περιμένει να φτάσουν δεδομένα.
 * 
 * Αντίστοιχα όταν κάποιος αισθητήρας αποστείλει μετρήσεις θα πρέπει όσες διεργασίες
 * κοιμόντουσαν περιμένοντας αποτελέσματα να ξυπνούν.
 * 
 * Ο κώδικας του πυρήνα ορίζει τον τύπο wait_queue_head_t για να περιγράψει μια ουρά
 * αναμονής διεργασιών. Για κάθε αισθητήρα χρησιμοποιείται μια τέτοια ουρά.
 * 
 * Όταν η read() διαπιστώσει ότι δεν υπάρχουν νέα δεδομένα και η διαδικασία πρέπει να κοιμηθεί, χρησιμοποιεί
 * την κλήση wait_event_interruptible() ώστε η τρέχουσα διεργασία να μπλοκάρει στην ανάλογη ουρά.
 * Ανατρέξτε και στη σελ. 153 του ldd3.
 */
static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	/* Lock? --> done */
	if (down_interruptible(&state->lock))
		return -ERESTARTSYS;
	
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		/* 
		 * Q: Τι σημαίνει EAGAIN;
		 * A: ΕAGAIN σημαίνει "Resource temporarily unavailable".
		 * Αυτό σημαίνει ότι αν ξανακληθεί η ίδια ρουτίνα μπορεί να πετύχει την επόμενη φορά.
		 */

		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* ? --> done */
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
			up(&state->lock);

			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state))) 
				return -ERESTARTSYS;

			if (down_interruptible(&state->lock)) 
				return -ERESTARTSYS;
		}
	}

	/* End of file */
	/* ? --> done */
	
	/* Determine the number of cached bytes to copy to userspace */
	/* ? --> done */
	int bytes_left = state->buf_lim - *f_pos;

	cnt = min(cnt, bytes_left);

	if (copy_to_user(usrbuf, state->buf_data, cnt)) {
		ret = -EFAULT;
		goto out;
	}

	*f_pos += cnt;
	ret = cnt;

	/* Auto-rewind on EOF mode? */
	/* ? --> done */
	if (*f_pos == state->buf_lim)
		*f_pos = 0;

out:
	/* Unlock? */
	up(&state->lock);
	return ret;
}

/*
 * Q: Τι κάνει η lunix_chrdev_mmap;
 * A: Αιτείται ένα mapping του device memory στον χώρο μνήμης μιας διεργασίας.
 */

/*
 * Q: Τι είναι το vm_area_struct;
 * A: Κάθε φορά που καλείται η mmap, δημιουργείται ένα vm_area_struct 
 * που αντιπροσωπεύει την αντιστοίχιση.
 */

/*
 * Στην περίπτωσή μας ουσιαστικά δεν την ορίζουμε.
 */
static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	/* 
	 * Πάλι ουσιαστικά δεν υλοποιούμε την mmap,
	 * οπότε επιστρέφουμε -EINVAL.
	 */
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
    .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

/* 
 * Q: Τι κάνει η lunix_chrdev_init;
 * A: Κάνει initialize τον driver.
 */
int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	/*
	 * Q: Τι κάνει το dev_t;
	 * A: Το dev_t κρατάει τα major και minor device numbers.
	 */
	dev_t dev_no;

	/* 
	 * Q: Γιατί shift κατά 3 bits αριστερά;
	 * A: Σύμφωνα με τον οδηγό: Τα 3 λιγότερο σημαντικά bits κάθε minor number 
	 * καθορίζουν το είδος της μέτρησης, ενώ τα υπόλοιπα τον αριθμό του αισθητήρα
	 * Έτσι η τιμή του minor number προκύπτει ως minor = αισθητήρας * 8 + μέτρηση.
	 */
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3; 
	
	debug("initializing character device\n");
	/*
	 * Q: Τι κάνει το cdev_init;
	 * A: Κάνει initialize το cdev structure, και κάνει τον δείκτη fops να δείχνει στο 
	 * file_operations που μας ενδιαφέρει.
	 */
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	/*
	 * Q: Τι κάνει το MKDEV;
	 * A: Το MKDEV είναι ένα macro που παίρνει ως είσοδο τα major και minor 
	 * numbers και επιστρέφει ένα dev_t data item.
	 */

	/*
	 * Q: Τι είναι το LUNIX_CHRDEV_MAJOR;
	 * A: Είναι μία σταθερά ίση με 60, και αποτελεί το major number της συσκευής μας.
	 * Είναι δεσμευμένο για τοπική/πειραματική χρήση.
	 */

	/*
	 * Q: Γιατί minor = 0; Δεν θα έπρεπε minor = αισθητήρας * 8 + μέτρηση;
	 * A: Όχι, διότι το dev_no απλά ορίζει την αρχή. 
	 */
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0); 
	/* ? --> done */
	/* register_chrdev_region? --> done */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/* ? --> done */
	/* cdev_add? --> done */	
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt); 
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region; 
	}
	debug("completed successfully\n");
	return 0;

/*
 * Q: Τι σημαίνουν τα labels out_with_chrdev_region και out;
 * A: out --> Δεν κατάφερα να κάνω register κάποιο region από major/minor numbers
 * out_with_chrdev_region --> Κατάφερα να κάνω register κάποιο region, αλλά δεν μπόρεσα
 * να κάνω cdev_add.
 */
out_with_chrdev_region:
	/* 
	 * Q: Τι κάνει η unregister_chrdev_region;
	 * A: Κάνει την ανάποδη δουλειά της register_chrdev_region,
	 * δηλαδή κάνει free το range των device numbers όταν δεν είναι πλέον υπό χρήση.
	 */
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

/* 
 * Q: Τι κάνει η lunix_chrdev_destroy;
 * A: Καλείται όταν το module γίνεται exit, και "καταστρέφει" τον driver. 
 */
void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/*
	 * Q: Τι κάνει η cdev_del;
	 * A: Κάνει remove ένα char device από το σύστημα. 
	 * Προφανώς δεν πρέπει να το ξανακάνουμε access από εδώ και στο εξής.
	 */
	cdev_del(&lunix_chrdev_cdev); 
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
