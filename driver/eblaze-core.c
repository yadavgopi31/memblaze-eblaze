
#include "eblaze-core.h"

const char *driver_version = "00.00.0001 (Compiled on "__DATE__" "__TIME__")";

static struct char_edev_map *ce_table[MAX_NR_EDEV];
static spinlock_t cet_lock;
static uint8_t nr_cet_ents = 0;
static struct class *eblaze_class;
static int eblaze_char_major;

static struct workqueue_struct *eblaze_workqueue;
struct kmem_cache *cmd_pool;
struct semaphore cmd_limiter;

int eblaze_int_interval = 0x0c00100;

DEFINE_PER_CPU(unsigned long, enter_jiffies);

#ifdef EBLAZE_TFD_INTERFACE
extern int32_t is_badblock(struct eblaze_lun *lun, uint32_t block_id);
extern int32_t mark_badblock(struct eblaze_lun *lun, uint32_t block_id);
extern void print_badblock(uint32_t tetris_id, struct eblaze_device *edev);
extern int32_t tfd_do_async_io(struct tfd_mtd_request *req);

#ifdef EBLAZE_TFD_ERR_INJECT
extern bool ERR_INJECT_META_READ_EIO;
extern bool ERR_INJECT_META_READ_NOT_EIO;
extern bool ERR_INJECT_DATA_READ_EIO;
extern bool ERR_INJECT_DATA_READ_NOT_EIO;
extern bool ERR_INJECT_WRITE;
extern bool ERR_INJECT_ERASE;

extern bool ERR_INJECT_TIMEOUT_READ;
extern bool ERR_INJECT_TIMEOUT_WRITE;
extern bool ERR_INJECT_TIMEOUT_ERASE;
extern bool ERR_INJECT_TIMEOUT_READ_OOB;
extern bool ERR_INJECT_TIMEOUT_WRITE_OOB;
extern bool ERR_INJECT_TIMEOUT_CHK_BADBLOCK;
extern bool ERR_INJECT_TIMEOUT_MARK_BADBLOCK;
#endif

#endif

int edev_init_pci(struct eblaze_device *edev, struct pci_dev *pdev)
{
	resource_size_t start, len;
	int dac;
	int cap;
	uint16_t value;
	int ret = 0;

	if ((ret = pci_enable_device(pdev)) < 0) {
		printk(KERN_ERR "eblaze: Unable to enable PCI device\n");
		goto clean1;
	}

	printk(KERN_INFO "Enabled PCI device\n");

	if (!(ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) &&
	    !(ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64)))) {
		DPRINTK(ERR, "Set 64 bits DMA MASK");
		dac = 1;
	} else if (!(ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) &&
		   !(ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32)))) {
		DPRINTK(ERR, "Set 32 bits DMA MASK");
		dac = 0;
	} else {
		printk("eblaze: no suitable DMA available\n");
		goto clean1;
	}

	start = pci_resource_start(pdev, 0);
	len = pci_resource_len(pdev, 0);
	if (!request_mem_region(start, len, "EBLAZE_FPGA")) {
		printk(KERN_WARNING "eblaze: can't request iomem (0x%lx).\n",
		       (unsigned long)start);
		ret = -EBUSY;
		goto clean1;
	}

	if ((edev->reg_base = ioremap_nocache(start, len)) == NULL) {
		ret = -ENOMEM;
		printk(KERN_ERR "eblaze: ioremap_nocache failed\n");
		goto clean2;
	}

	pcie_set_readrq(pdev, 512);
	cap = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!cap) {
		ret = -EINVAL;
		goto clean3;
	}

	ret = pci_read_config_word(pdev, cap + PCI_EXP_LNKSTA, &value);
	if (ret) {
		goto clean3;
	}

	edev->pcie_link_width = (value & PCI_EXP_LNKSTA_NLW) >> 4;
	ret = pci_read_config_word(pdev, cap + PCI_EXP_FLAGS, &value);
	if (ret) {
		goto clean3;
	}

	edev->pcie_link_gen = value & PCI_EXP_FLAGS_VERS;
	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);
	pci_set_drvdata(pdev, edev);

	return 0;

clean3:
	iounmap(edev->reg_base);
clean2:
	release_mem_region(start, len);
clean1:
	pci_disable_device(pdev);
	return ret;
}

void edev_remove_pci(struct eblaze_device *edev, struct pci_dev *pdev)
{
	pci_clear_master(pdev);
	iounmap(edev->reg_base);
	release_mem_region(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
	pci_disable_device(pdev);
}

/* Stuff for char control device */
static struct eblaze_device *find_edev_by_minor(int minor)
{
	int i;
	struct eblaze_device *edev = NULL;

	spin_lock(&cet_lock);

	for (i = 0; i < nr_cet_ents; i++)
		if (ce_table[i]->char_minor == minor) {
			break;
		}

	if (i != nr_cet_ents) {
		edev = ce_table[i]->edev;
	}

	spin_unlock(&cet_lock);
	return edev;
}

int eblaze_char_open(struct inode *inode, struct file *file)
{
	return 0;
}

static void ioctl_erase_cb(void *priv, int unused)
{
	uint32_t block_id;
	struct eblaze_lun *lun;
	struct eblaze_cmd *cmd = (struct eblaze_cmd *)priv;

	if (cmd->status != 0) {
		lun = cmd->lun;
		block_id = (cmd->start_fpage - (lun->lun_id << LUN_SHIFT)) >> BLOCK_SHIFT;
		DPRINTK(ERR, "status:%u, lun_id:%u, block_id:%u\n",
			cmd->status, lun->lun_id, block_id);
	}
}

int eblaze_ioctl_erase(struct eblaze_device *edev, struct user_erase_info *uei)
{
	struct eblaze_lun *lun;
	struct eblaze_cmd *cmd;

	DPRINTK(DEBUG, "lun_id:%d start_block:%u, nr_blocks:%u\n",
		uei->lun_id, uei->start_block, uei->nr_blocks);

	lun = edev->luns[uei->lun_id];
#ifdef EBLAZE_TFD_INTERFACE
	if (is_badblock(lun, uei->start_block) == 1)
		return 0;
#endif

	cmd = eb_alloc_cmd(lun);
	cmd->op = CMD_ERASE;
	cmd->start_fpage = (uei->start_block << BLOCK_SHIFT) + (uei->lun_id << LUN_SHIFT);
	cmd->nr_pages = uei->nr_blocks;
	cmd->callback = ioctl_erase_cb;
	if (eb_insert_cmd(cmd, lun))
		eb_schedule_submit_work(lun);

	return 0;
}

void ioctl_rw_cb(void *priv, int status)
{
	int i, j;
	struct eblaze_cmd *cmd = (struct eblaze_cmd *)priv;
	struct ioctl_rw_io *rw_io = (struct ioctl_rw_io *)cmd->cmd_private;
	uint8_t *v;

	DPRINTK(DEBUG, "lun %u start_page:%u nr_pages:%u rw:%u\n",
		rw_io->lun->lun_id, rw_io->start_page, rw_io->nr_pages, rw_io->is_write);

	if (status != 0) {
		DPRINTK(DEBUG, "cmd status:%u\n", status);
		goto clean;
	}

	if (rw_io->is_write == false) {
		for (j = 0; j < rw_io->nr_sg; j++) {
			if (rw_io->data[j] != 0) {
				DPRINTK(DEBUG, "check pages:%u\n", rw_io->pages[j]);
				v = (uint8_t *)rw_io->data[j];
				for (i = 0; i < PAGE_SIZE * rw_io->pages[j]; i++) {
					if (*(v + i) != 0x33)
						DPRINTK(ERR, "IBD mismatch lun %u start_page:%u [%x], i:%d, j:%d\n",
							rw_io->lun->lun_id, rw_io->start_page, *(v + i),
							i, j);

					DPRINTK(DEBUG, "%x ", *(v + i));
					break;
				}
				DPRINTK(DEBUG, "\n");
			}
		}

		if (rw_io->oob_data != 0) {
			v = (uint8_t *)rw_io->oob_data;

			for (i = 0; i < 16 * rw_io->nr_pages; i++) {
				if (*(v + i) != 0x44)
					DPRINTK(ERR, "OBD mismatch eblaze_lun %u start_page:%u [%x]\n",
						rw_io->lun->lun_id, rw_io->start_page, *(v + i));
				break;
			}
		}
	}

clean:
	for (j = 0; j < rw_io->nr_sg; j++) {
		if (rw_io->data[j] != 0) {
			DPRINTK(DEBUG, "order:%u\n", rw_io->order[j]);
			__free_pages(virt_to_page(rw_io->data[j]), rw_io->order[j]);
		}
	}

	if (rw_io->oob_data != 0) {
		DPRINTK(DEBUG, "oob order:%u\n", get_order(16 * rw_io->nr_pages));
		__free_pages(virt_to_page(rw_io->oob_data), get_order(16 * rw_io->nr_pages));
	}

	kfree(rw_io);
}

/* async rw */
int eblaze_ioctl_rw(struct eblaze_device *edev, struct user_rw_info *urwi)
{
	return 0;
}

#ifdef EBLAZE_TFD_INTERFACE
static int32_t ioctl_rw_tfd_cb(struct tfd_mtd_request *req)
{
	DPRINTK(DEBUG, "retlen:%d\n", req->retlen);
	complete(req->wait);

	return 0;
}

/* sync rw */
int eblaze_ioctl_tfd_rw(struct eblaze_device *edev, struct user_rw_info *urwi)
{
	int i;
	int ret = 0;
	uint32_t retlen;
	struct eblaze_lun *lun;
	struct tfd_mtd *mtd;
	unsigned long data, obd_data;
	u32 obd_len;
	uint16_t nr_pages_left, nr_pages_slice;
	struct tfd_mtd_request *req;
	unsigned long copy_pos = 0;
	struct completion waiter;
	bool is_write;

	DPRINTK(DEBUG, "lun_id:%d op:%d start_page:%u nr_pages:%u obd_len:%u need_copy:%u\n",
		urwi->lun_id, urwi->type, urwi->start_page, urwi->nr_pages,
		urwi->obd_len, urwi->need_copy);

	obd_len = urwi->obd_len;
	lun = edev->luns[urwi->lun_id];
	if (is_badblock(lun, (urwi->start_page >> BLOCK_SHIFT) + 1) == 1) {
		DPRINTK(ERR, "badblock\n");
		return IOCTL_BADBLOCK_RET;
	}

	if (urwi->type == MTD_REQUEST_READ || urwi->type == MTD_REQUEST_READ_OOB)
		is_write = false;
	else if (urwi->type == MTD_REQUEST_WRITE || urwi->type == MTD_REQUEST_WRITE_OOB)
		is_write = true;
	else {
		DPRINTK(ERR, "unknowed operation:%d\n", urwi->type);
		return -1;
	}

	while ((req = kzalloc(sizeof(struct tfd_mtd_request), GFP_KERNEL)) == NULL)
		;
	while ((mtd = kzalloc(sizeof(struct tfd_mtd), GFP_KERNEL)) == NULL)
		;
	req->tfd_mtd = mtd;
	req->tfd_mtd->mtd.priv = lun;
	req->type = urwi->type;
	req->offset = urwi->start_page * PAGE_SIZE;
	req->len = urwi->nr_pages * PAGE_SIZE;
	req->callbk = ioctl_rw_tfd_cb;

	if (req->type != MTD_REQUEST_READ_OOB) {
		nr_pages_left = urwi->nr_pages;
		req->nr_datasg = (nr_pages_left + IOCTL_RW_SLICE - 1) / IOCTL_RW_SLICE;
		sg_init_table(req->databuf, req->nr_datasg);
		i = 0;
		copy_pos = 0;
		while (i < req->nr_datasg) {
			if (nr_pages_left >= IOCTL_RW_SLICE) {
				nr_pages_slice = IOCTL_RW_SLICE;
				nr_pages_left -= IOCTL_RW_SLICE;
			} else {
				nr_pages_slice = nr_pages_left;
				nr_pages_left = 0;
			}

			data = __get_free_pages(GFP_KERNEL, get_order(nr_pages_slice * PAGE_SIZE));
			if (data == 0) {
				DPRINTK(ERR, "ibd __get_free_pages error\n");
				ret = -ENOMEM;
				goto clean_ibd;
			}

			sg_set_page(&req->databuf[i], virt_to_page(data), nr_pages_slice * PAGE_SIZE, 0);
			i++;

			if (is_write == true && urwi->need_copy == true) {
				if (copy_from_user((void *)data, (void __user *)urwi->ibd_addr + copy_pos, nr_pages_slice * PAGE_SIZE)) {
					ret = -EFAULT;
					goto clean_ibd;
				}

				copy_pos += nr_pages_slice * PAGE_SIZE;
			} else if (is_write == true && urwi->need_copy == false) {
				memset((void *)data, 0x33, nr_pages_slice * PAGE_SIZE);
			} else {
				memset((void *)data, 0, nr_pages_slice * PAGE_SIZE);
			}
		}
	}

	if (obd_len) {
		req->nr_oobsg = 1;
		req->ooblen = obd_len;
		obd_data = __get_free_pages(GFP_KERNEL, get_order(obd_len));
		if (obd_data == 0) {
			DPRINTK(ERR, "obd __get_free_pages error\n");
			ret = -ENOMEM;
			goto clean_ibd;

		}

		sg_init_table(req->oobbuf, 1);
		sg_set_page(&req->oobbuf[0], virt_to_page(obd_data), obd_len, 0);

		if (is_write == true && urwi->need_copy == true) {
			if (copy_from_user((void *)obd_data, (void __user *)urwi->obd_addr, obd_len)) {
				ret = -EFAULT;
				goto clean_obd;
			}
		} else if (is_write == true && urwi->need_copy == false) {
			memset((void *)obd_data, 0x44, obd_len);
		} else {
			memset((void *)obd_data, 0, obd_len);
		}
	}

	req->wait = &waiter;
	init_completion(req->wait);
	tfd_do_async_io(req);
	wait_for_completion_timeout(req->wait, HZ * BBE_IO_TIMEOUT);
	if (req->retlen != req->len || req->ooblen != obd_len) {
		DPRINTK(ERR, "req return failed, retlen\n");
		ret = -EIO;
	}

	/* Copy to user */
	if (is_write == false && urwi->need_copy && ret == 0) {
		if (req->type != MTD_REQUEST_READ_OOB) {
			i = 0;
			copy_pos = 0;
			nr_pages_left = urwi->nr_pages;
			while (i < req->nr_datasg) {
				if (nr_pages_left >= IOCTL_RW_SLICE) {
					nr_pages_slice = IOCTL_RW_SLICE;
					nr_pages_left -= IOCTL_RW_SLICE;
				} else {
					nr_pages_slice = nr_pages_left;
					nr_pages_left = 0;
				}

				retlen = copy_to_user(urwi->ibd_addr + copy_pos, sg_virt(&req->databuf[i]), nr_pages_slice * PAGE_SIZE);
				if (retlen) {
					DPRINTK(ERR, "copy to user error, nr_slice:%u, retlen:%u\n", nr_pages_slice, retlen);
					ret = -EFAULT;
					goto clean_obd;
				}
				copy_pos += nr_pages_slice * PAGE_SIZE;
				i++;
			}
		}

		if (obd_len) {
			retlen = copy_to_user(urwi->obd_addr, sg_virt(&req->oobbuf[0]), obd_len);
			if (retlen) {
				DPRINTK(ERR, "copy to user error, retlen:%u\n", retlen);
				ret = -EFAULT;
				goto clean_obd;
			}
		}
	}

clean_obd:
	if (req->nr_oobsg != 0) {
		if (req->oobbuf[0].length) {
			DPRINTK(DEBUG, "oob order:%u\n", get_order(req->oobbuf[0].length));
			__free_pages(sg_page(&req->oobbuf[0]), get_order(req->oobbuf[0].length));
		}
	}
clean_ibd:
	if (req->nr_datasg != 0) {
		for (i = 0; i < req->nr_datasg; i++) {
			if (req->databuf[i].length) {
				DPRINTK(DEBUG, "order:%u\n", get_order(req->databuf[i].length));
				__free_pages(sg_page(&req->databuf[i]), get_order(req->databuf[i].length));
			}
		}
	}

	kfree(req->tfd_mtd);
	kfree(req);

	return ret;
}

int eblaze_ioctl_tfd_bbm(struct eblaze_device *edev, struct user_bbm_info *ubi)
{
	int ret;
	int block_id;
	struct eblaze_lun *lun;

	lun = edev->luns[ubi->lun_id];
	block_id = ubi->block_id;

	/* The block0 is transparent for user */
	block_id++;
	if (block_id >= NR_BLOCKS_PER_LUN)
		return -ERR_BBA_ILLEGAL;

	if (ubi->op == 0)
		ret = is_badblock(lun, block_id);
	else
		ret = mark_badblock(lun, block_id);

	return ret;
}
#endif

int eblaze_char_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
		      unsigned long arg)
{
	int minor;
	struct eblaze_device *edev;
	unsigned long rest_copy;
	int rc = 0;
	const struct firmware *pfw;
	struct firmware_name ffn;
	struct firmware_data *pfd;
	struct dyn_info d_info;

	minor = MINOR(inode->i_rdev);
	if ((edev = find_edev_by_minor(minor)) == NULL) {
		DPRINTK(ERR, "minor:%d can't find edev\n", minor);
		return -EINVAL;
	}

	switch (cmd) {
	case MEMCON_GET_ROM_INFO:
		down(&edev->ioctl_sem);
		if (copy_to_user((void __user *)arg, &edev->rom, sizeof(struct rom_info))) {
			rc = -CMD_ECHO_FAILED;
		}
		up(&edev->ioctl_sem);

		break;

	case MEMCON_GET_DYN_INFO:
		down(&edev->ioctl_sem);
		memset(&d_info, 0 , sizeof(struct dyn_info));
		eblaze_get_dyn_info(edev, &d_info);
		if (copy_to_user((void __user *)arg, &d_info, sizeof(struct dyn_info))) {
			rc = -CMD_ECHO_FAILED;
		}
		up(&edev->ioctl_sem);

		break;

	case MEMCON_USER_DEF:
	{
		int k;
		unsigned long timeout;
		u32 value[16] = {0};
		u32 data;

		printk("perf++\n");
		timeout = jiffies + HZ * 1;
		do {
			writel(0x7c803214, edev->reg_base + 0x5000);
			for (k = 0; k < 2; k++)
				data = readl(edev->reg_base + 0x5004);
			value[0] = (data & 0xffff);

			writel(0x7c803210, edev->reg_base + 0x5000);
			for (k = 0; k < 2; k++)
				data = readl(edev->reg_base + 0x5004);
			data &= 0xffff0000;
			data >>= 16;
			value[1] = data;

			writel(0x7c803208, edev->reg_base + 0x5000);
			for (k = 0; k < 2; k++)
				data = readl(edev->reg_base + 0x5004);
			value[3] = (data & 0xffff);
			data &= 0xffff0000;
			data >>= 16;
			value[2] = data;

			/* do read fpag counter */
			printk("%u %u %u %u ",
				value[0], value[1], value[2], value[3]);
			printk("sd:%llu sm:%llu rv:%llu cl:%llu\n",
				edev->send_io, edev->submit_io,
				edev->recv_io, edev->cmpl_io);

			udelay(200);
			if (likely(time_after_eq(jiffies, timeout))) {
				break;
			}
		} while (true);
		printk("perf--\n");
		break;
	}

	case MEMCON_BAECON:
		if (unlikely(!arg)) {
			rc = -CMD_ECHO_INVALID_PARMA;
		} else {
			if (copy_from_user(&edev->is_baecon_On, (void __user *)arg, sizeof(uint32_t))) {
				rc = -CMD_ECHO_FAILED;
			} else {
				eblaze_beacon(edev, edev->is_baecon_On != 0);
			}
		}
		break;

	case MEMCON_UPDATEFIRMWARE:
		if (copy_from_user(&ffn, (void __user *)arg, sizeof(struct firmware_name))) {
			rc = -CMD_ECHO_FAILED;
		} else {
			ffn.name[MAX_STR_LEN - 1] = 0;

			down(&edev->ioctl_sem);
			rc = request_firmware(&pfw, ffn.name, &edev->pdev->dev);
			if (!rc) {
				pfd = (struct firmware_data *)pfw->data;

				/* TODO: add more check such as model string and version string */
				if (pfw->size < (unsigned long)sizeof(struct firmware_data)
				    || pfd->length != (u32)(pfw->size - (unsigned long)(((struct firmware_data *)0)->data))) {
					DPRINTK(ERR, "Device Firmware Size Mismatch, the file %s maybe corrupt\n", ffn.name);
					rc = -CMD_ECHO_FAILED;
				} else if (pfd->magic != MAGICNUMBER) {
					DPRINTK(ERR, "Invalid MagicNumber in Device Firmware, the file %s maybe corrupt\n", ffn.name);
					rc = -CMD_ECHO_FAILED;
				} else {
					rc = eblaze_send_fw(edev , pfw->size, (char *)pfw->data);
				}

				release_firmware(pfw);
			} else {
				DPRINTK(ERR, "Cannot load firmware %s\n", ffn.name);
			}
			up(&edev->ioctl_sem);
		}

		break;

#ifdef EBLAZE_TFD_INTERFACE
	case MEMCON_TFD_RW:
                if (access_ok(VERIFY_READ, (void __user *)arg, sizeof(struct user_rw_info))) {
			struct user_rw_info urwi;

			rest_copy = copy_from_user(&urwi, (void __user *)arg, sizeof(struct user_rw_info));
			if (rest_copy) {
				rc = -EINVAL;
				break;
			}

			rc = eblaze_ioctl_tfd_rw(edev, &urwi);
		}

		break;

	case MEMCON_TFD_BBM:
                if (access_ok(VERIFY_READ, (void __user *)arg, sizeof(struct user_bbm_info))) {
			struct user_bbm_info ubi;

			rest_copy = copy_from_user(&ubi, (void __user *)arg, sizeof(struct user_bbm_info));
			if (rest_copy) {
				rc = -EINVAL;
				break;
			}

			rc = eblaze_ioctl_tfd_bbm(edev, &ubi);
		}

		break;
#endif
	case MEMCON_USER_RW:
                if (access_ok(VERIFY_READ, (void __user *)arg, sizeof(struct user_rw_info))) {
			struct user_rw_info urwi;

			rest_copy = copy_from_user(&urwi, (void __user *)arg, sizeof(struct user_rw_info));
			if (rest_copy) {
				rc = -EINVAL;
				break;
			}

			rc = eblaze_ioctl_rw(edev, &urwi);
		}

		break;

        case MEMCON_USER_ERASE:
                if (access_ok(VERIFY_READ, (void __user *)arg, sizeof(struct user_erase_info))) {
			struct user_erase_info uei;

			rest_copy = copy_from_user(&uei, (void __user *)arg, sizeof(struct user_erase_info));
			if (rest_copy) {
				rc = -EINVAL;
				break;
			}

			rc = eblaze_ioctl_erase(edev, &uei);
		}

		break;

#ifdef EBLAZE_TFD_ERR_INJECT
	case MEMCON_ERR_INJECT_META_READ_EIO:
		rest_copy = copy_from_user(&ERR_INJECT_META_READ_EIO, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_META_READ_EIO:%u\n", ERR_INJECT_META_READ_EIO);
		break;

	case MEMCON_ERR_INJECT_META_READ_NOT_EIO:
		rest_copy = copy_from_user(&ERR_INJECT_META_READ_NOT_EIO, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_META_READ_NOT_EIO:%u\n", ERR_INJECT_META_READ_NOT_EIO);
		break;

	case MEMCON_ERR_INJECT_DATA_READ_EIO:
		rest_copy = copy_from_user(&ERR_INJECT_DATA_READ_EIO, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_DATA_READ_EIO:%u\n", ERR_INJECT_DATA_READ_EIO);
		break;

	case MEMCON_ERR_INJECT_DATA_READ_NOT_EIO:
		rest_copy = copy_from_user(&ERR_INJECT_DATA_READ_NOT_EIO, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_DATA_READ_NOT_EIO:%u\n", ERR_INJECT_DATA_READ_NOT_EIO);
		break;

	case MEMCON_ERR_INJECT_WRITE:
		rest_copy = copy_from_user(&ERR_INJECT_WRITE, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_WRITE:%u\n", ERR_INJECT_WRITE);
		break;

	case MEMCON_ERR_INJECT_ERASE:
		rest_copy = copy_from_user(&ERR_INJECT_ERASE, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_ERASE:%u\n", ERR_INJECT_ERASE);
		break;

	case MEMCON_ERR_INJECT_TIMEOUT_READ:
		rest_copy = copy_from_user(&ERR_INJECT_TIMEOUT_READ, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_TIMEOUT_READ:%u\n", ERR_INJECT_TIMEOUT_READ);
		break;

	case MEMCON_ERR_INJECT_TIMEOUT_WRITE:
		rest_copy = copy_from_user(&ERR_INJECT_TIMEOUT_WRITE, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_TIMEOUT_WRITE:%u\n", ERR_INJECT_TIMEOUT_WRITE);
		break;

	case MEMCON_ERR_INJECT_TIMEOUT_ERASE:
		rest_copy = copy_from_user(&ERR_INJECT_TIMEOUT_ERASE, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_TIMEOUT_ERASE:%u\n", ERR_INJECT_TIMEOUT_ERASE);
		break;

	case MEMCON_ERR_INJECT_TIMEOUT_READ_OOB:
		rest_copy = copy_from_user(&ERR_INJECT_TIMEOUT_READ_OOB, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_TIMEOUT_READ_OOB:%u\n", ERR_INJECT_TIMEOUT_READ_OOB);
		break;

	case MEMCON_ERR_INJECT_TIMEOUT_WRITE_OOB:
		rest_copy = copy_from_user(&ERR_INJECT_TIMEOUT_WRITE_OOB, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_TIMEOUT_WRITE_OOB:%u\n", ERR_INJECT_TIMEOUT_WRITE_OOB);
		break;

	case MEMCON_ERR_INJECT_TIMEOUT_CHK_BADBLOCK:
		rest_copy = copy_from_user(&ERR_INJECT_TIMEOUT_CHK_BADBLOCK, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_TIMEOUT_CHK_BADBLOCK:%u\n", ERR_INJECT_TIMEOUT_CHK_BADBLOCK);
		break;
	case MEMCON_ERR_INJECT_TIMEOUT_MARK_BADBLOCK:
		rest_copy = copy_from_user(&ERR_INJECT_TIMEOUT_MARK_BADBLOCK, (void __user *)arg, sizeof(u32));
		if (rest_copy) {
			rc = -EFAULT;
			goto err;
		}
		DPRINTK(ERR, "ERR_INJECT_TIMEOUT_MARK_BADBLOCK:%u\n", ERR_INJECT_TIMEOUT_MARK_BADBLOCK);
		break;
#endif

	default:
		rc = -EINVAL;
		goto err;
	}

err:
	return rc;
}

static struct file_operations edev_chr_ops = {
	.owner = THIS_MODULE,
	.open = eblaze_char_open,
	.ioctl = eblaze_char_ioctl,
};

int create_edev_chrdev(struct eblaze_device *edev)
{
	char name[16];
	struct char_edev_map *cem;

	cem = (struct char_edev_map *)kzalloc(sizeof(struct char_edev_map), GFP_KERNEL);
	if (cem == NULL) {
		return -ENOMEM;
	}

	sprintf(name, "memcon%c", 'a' + edev->probe_idx);
	device_create(eblaze_class, NULL, MKDEV(eblaze_char_major, edev->probe_idx), NULL, name);
	cem->char_minor = edev->probe_idx;
	cem->edev = edev;
	spin_lock(&cet_lock);
	ce_table[nr_cet_ents++] = cem;
	spin_unlock(&cet_lock);

	DPRINTK(ERR, "memcona(minor):%d nr_cet_ents:%u\n",
		edev->probe_idx, nr_cet_ents);

	return 0;
}

void destroy_edev_chrdev(struct eblaze_device *edev)
{
	char name[16];
	struct char_edev_map *cem = NULL;
	int i;

	spin_lock(&cet_lock);
	for (i = 0; i < nr_cet_ents; i++) {
		cem = ce_table[i];

		if (cem->edev == edev) {
			break;
		}
	}

	for (; i < (nr_cet_ents - 1); i++) {
		ce_table[i] = ce_table[i + 1];
	}

	nr_cet_ents--;
	spin_unlock(&cet_lock);

	if (cem != NULL) {
		sprintf(name, "memcon%c", 'a' + edev->probe_idx);
		device_destroy(eblaze_class, MKDEV(eblaze_char_major, cem->char_minor));
	}
}

static inline u32 eb_comb_cmd_sn(struct eblaze_cmd *cmd)
{
	return (u32)cmd->lun_id << 24 | (u32)cmd->cmd_id << 16 | (u32)cmd->cdb_id << 8;
}

bool eb_test_cmd_slot(struct eblaze_lun *lun)
{
	return lun->submit_cmd_bitmap != 0x7fffffff;
}

int eb_alloc_cmd_slot(struct eblaze_lun *lun)
{
	int slot;

	slot = find_first_zero_bit(&lun->submit_cmd_bitmap, MAX_CMDS_PER_LUN);
	if (slot != MAX_CMDS_PER_LUN) {
		__set_bit(slot, &lun->submit_cmd_bitmap);
	}

	return slot;
}

int eb_reclaim_cmd_slot(int slot, struct eblaze_lun *lun)
{
	BUG_ON(slot < 0 || slot >= MAX_CMDS_PER_LUN);
	BUG_ON(!test_bit(slot, &lun->submit_cmd_bitmap));

	__clear_bit(slot, &lun->submit_cmd_bitmap);
	lun->cmd_slots[slot] = NULL;

	return 0;
}

struct eblaze_cmd *eb_alloc_cmd(struct eblaze_lun *lun)
{
	struct eblaze_cmd *cmd;

#ifdef PERF_OPT
	eb_atomic_inc(&lun->edev->send_io);
	eb_atomic_inc(&lun->edev->pending_io);
	eb_atomic_inc(&lun->send_io);
#endif

	if (down_interruptible(&cmd_limiter))
		return NULL;

	cmd = kmem_cache_alloc(cmd_pool, GFP_KERNEL);
	if (cmd == NULL)
		return NULL;
	memset(cmd, 0, sizeof(struct eblaze_cmd));
	cmd->lun = lun;
	cmd->lun_id = lun->lun_id;

#ifdef PERF_OPT
	do_gettimeofday(&cmd->tv);
	cmd->submit_delay = cmd->tv.tv_usec;
#endif

	return cmd;
}

void eb_free_cmd(struct eblaze_cmd *cmd)
{
#ifdef PERF_OPT
	eb_atomic_inc(&cmd->lun->edev->cmpl_io);
	eb_atomic_dec(&cmd->lun->edev->wait_io);
	do_gettimeofday(&cmd->tv);
	cmd->complete_delay = cmd->tv.tv_usec - cmd->complete_delay;
	DPRINTK(DEBUG, "Delay %d, %d, %d\n",
		cmd->submit_delay, cmd->hardware_delay, cmd->complete_delay);
#endif
	kmem_cache_free(cmd_pool, cmd);
	up(&cmd_limiter);
}

bool eb_insert_cmd(struct eblaze_cmd *cmd, struct eblaze_lun *lun)
{
	bool is_queueempty;

	spin_lock(&lun->submit_list_lock);
	is_queueempty = list_empty(&lun->submit_list);
	list_add_tail(&cmd->node, &lun->submit_list);
	spin_unlock(&lun->submit_list_lock);

	return is_queueempty;
}

static struct eblaze_cmd *eb_fetch_cmd(struct eblaze_lun *lun)
{
	int slot;
	struct eblaze_cmd *cmd = NULL;

	if (eb_test_cmd_slot(lun)) {
		spin_lock(&lun->submit_list_lock);
		if (!list_empty(&lun->submit_list)) {
			cmd = list_first_entry(&lun->submit_list, struct eblaze_cmd, node);
			list_del_init(&cmd->node);
		}
		spin_unlock(&lun->submit_list_lock);

		if (cmd != NULL) {
			slot = eb_alloc_cmd_slot(lun);
			BUG_ON(slot ==  MAX_CMDS_PER_LUN);
			BUG_ON(lun->cmd_slots[slot] != NULL);
			lun->cmd_slots[slot] = cmd;
			cmd->cmd_id = slot;
		}
	}
	return cmd;
}

int eb_get_cdb_slot(struct eblaze_lun *lun)
{
	int cdb_id;

	/*
	 * The submit worker will always run in a single mode,
	 * it no need lock.
	 * It don't need care the read ptr becasue if cmd can be alloced,
	 * the dma cmd buffer will always has empty slot.
	 */
	cdb_id = lun->write_idx;
	lun->write_idx += 1;
	lun->write_idx %= MAX_SLOTS_PER_LUN;

	return cdb_id;
}

static void eb_trigger_cdb(struct eblaze_lun *lun)
{
	dma_addr_t wptr;

	/*
	 * The submit worker will always run in a single mode, it means
	 * the trigger will always update one cdb one time.
	 */
	wptr = lun->cdbs_dma_addr + sizeof(struct eblaze_cdb) * lun->write_idx;
	writel(wptr & DMA_ADDR_LOW_MASK, lun->edev->reg_base + REG_CDB_WPTR_BASE + lun->lun_id * 8);
}

static void eb_cmpl_work(struct eblaze_lun* lun)
{
	int slot;
	unsigned long cmpl_bitmap;
	struct eblaze_cmd *cmd;
	struct eblaze_device *edev = lun->edev;

	cmpl_bitmap = eb_atomic_xchg(&lun->cmpl_cmd_bitmap, 0);
	while (cmpl_bitmap) {
		slot = find_first_bit(&cmpl_bitmap, MAX_CMDS_PER_LUN);
		BUG_ON(slot == MAX_CMDS_PER_LUN);

		__clear_bit(slot, &cmpl_bitmap);
		cmd = lun->cmd_slots[slot];
		if (unlikely(cmd->nr_pages > INLINE_MAX_PAGE_NUM)) {
			dma_unmap_single(&edev->pdev->dev, lun->big_sgl_addrs[cmd->cmd_id],
					 lun->big_sgl_order[cmd->cmd_id] * PAGE_SIZE, DMA_TO_DEVICE);
			free_pages(lun->big_sgls[cmd->cmd_id], lun->big_sgl_order[cmd->cmd_id]);
		}

		if (cmd->nr_orig_ibd_sg != 0) {
			dma_unmap_sg(&edev->pdev->dev, cmd->ibd_sg, cmd->nr_orig_ibd_sg,
				     cmd->op == CMD_READ ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
		}

		if (cmd->nr_orig_obd_sg != 0) {
			dma_unmap_sg(&edev->pdev->dev, cmd->obd_sg, cmd->nr_orig_obd_sg,
				     cmd->op == CMD_READ ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
		}

		cmd->callback(cmd, cmd->status);
		eb_free_cmd(cmd);
		eb_reclaim_cmd_slot(slot, lun);
	}
}

static void eb_submit_work(struct eblaze_lun *lun)
{
	struct eblaze_cmd *cmd;
	struct scatterlist *sl, *sg;
	struct eblaze_device *edev;
	struct eblaze_sgl_elem *sge;
	struct eblaze_cdb *cdb;
	struct eblaze_cdb tmpcdb;
	dma_addr_t dma_addr;
	int segs, nr_ibd_sg, nr_obd_sg;
	int i;
	unsigned int len, max_seg_size;
	uint32_t sgl_size = 0;
	int order = 0;
	unsigned long sgl_addr, sgl_obd_addr;
	dma_addr_t dma_sgl_addr, dma_sgl_obd_addr;
	bool ringcursor_changed = false;
	
	DPRINTK(DEBUG, "++\n");
	edev = lun->edev;
	while (true) {
		cmd = eb_fetch_cmd(lun);
		if (cmd == NULL) {
			if (ringcursor_changed)
				eb_trigger_cdb(lun);
			return;
		}
		ringcursor_changed = true;

		DPRINTK(DEBUG, "S:%u L:%u\n", cmd->start_fpage, cmd->nr_pages);

		cmd->cdb_id = eb_get_cdb_slot(lun);
		cdb = &lun->cdbs[cmd->cdb_id];
		max_seg_size = edev->max_segment_size;

		/* Just use cmd_id for index the sgl table */
		if (likely(cmd->nr_pages <= INLINE_MAX_PAGE_NUM)) {
			sgl_size = 4096;
			sgl_addr = lun->double_sgls[cmd->cmd_id];
			dma_sgl_addr = lun->sgl_addrs[cmd->cmd_id];
			sgl_obd_addr = sgl_addr + INLINE_IBD_SGL_MAX_SIZE;
			dma_sgl_obd_addr = dma_sgl_addr + INLINE_IBD_SGL_MAX_SIZE;
		} else {
			/* The last page is for obd */
			sgl_size = ALIGN(cmd->nr_pages * sizeof(struct eblaze_sgl_elem) + PAGE_SIZE, PAGE_SIZE);
			order = get_order(sgl_size);
			lun->big_sgl_order[cmd->cmd_id] = order;
			while ((lun->big_sgls[cmd->cmd_id] = __get_free_pages(GFP_KERNEL, order)) == 0) {
				DPRINTK(ERR, "Get free pages for big sgl failed\n");
			}
			lun->big_sgl_addrs[cmd->cmd_id] = dma_map_single(&edev->pdev->dev, (void *)lun->big_sgls[cmd->cmd_id],
								       sgl_size, DMA_TO_DEVICE);

			/* The last page is for obd */
			sgl_addr = lun->big_sgls[cmd->cmd_id];
			dma_sgl_addr = lun->big_sgl_addrs[cmd->cmd_id];
			sgl_obd_addr = sgl_addr + sgl_size - PAGE_SIZE;
			dma_sgl_obd_addr = dma_sgl_addr + sgl_size - PAGE_SIZE;
		}

		sge = (struct eblaze_sgl_elem *)sgl_addr;
		nr_ibd_sg = 0;
		sl = (struct scatterlist *)cmd->ibd_sg;
		segs = cmd->nr_ibd_sg;
		if (sl && segs != 0) {
			for_each_sg(sl, sg, segs, i) {
				dma_addr = sg_dma_address(sg);
				sge->addr.low = dma_addr & DMA_ADDR_LOW_MASK;
				sge->addr.high = dma_addr >> DMA_ADDR_HIGH_SHIFT;

				if ((len = sg_dma_len(sg)) > max_seg_size) {
					sge->len = (max_seg_size >> DMA_LEN_SHIFT);
					do {
						sge++;
						dma_addr += max_seg_size;
						len -= max_seg_size;
						sge->addr.low = dma_addr & DMA_ADDR_LOW_MASK;
						sge->addr.high = dma_addr >> DMA_ADDR_HIGH_SHIFT;
						sge->len = (min(len, max_seg_size) >> DMA_LEN_SHIFT);
						nr_ibd_sg++;
					} while (len > max_seg_size);
				} else {
					sge->len = (sg_dma_len(sg) >> DMA_LEN_SHIFT);
				}

				sge++;
				nr_ibd_sg++;
			}
			cmd->nr_ibd_sg = nr_ibd_sg;
		}

		sge = (struct eblaze_sgl_elem *)sgl_obd_addr;
		nr_obd_sg = 0;
		sl = (struct scatterlist *)cmd->obd_sg;
		segs = cmd->nr_obd_sg;
		if (sl && segs != 0) {
			for_each_sg(sl, sg, segs, i) {
				dma_addr = sg_dma_address(sg);
				sge->addr.low = dma_addr & DMA_ADDR_LOW_MASK;
				sge->addr.high = dma_addr >> DMA_ADDR_HIGH_SHIFT;

				if ((len = sg_dma_len(sg)) > max_seg_size) {
					sge->len = (max_seg_size >> DMA_LEN_SHIFT);
					do {
						sge++;
						dma_addr += max_seg_size;
						len -= max_seg_size;
						sge->addr.low = dma_addr & DMA_ADDR_LOW_MASK;
						sge->addr.high = dma_addr >> DMA_ADDR_HIGH_SHIFT;
						sge->len = (min(len, max_seg_size) >> DMA_LEN_SHIFT);
						nr_obd_sg++;
					} while (len > max_seg_size);
				} else {
					sge->len = (sg_dma_len(sg) >> DMA_LEN_SHIFT);
				}

				sge++;
				nr_obd_sg++;
			}
			cmd->nr_obd_sg = nr_obd_sg;
		}

		memset(&tmpcdb, 0, sizeof(tmpcdb));
		tmpcdb.op = cmd->op;
		tmpcdb.start_fpage = cmd->start_fpage;
		tmpcdb.nr_pages = cmd->nr_pages;


		if (cmd->nr_ibd_sg) {
			tmpcdb.ibd_sg_addr.low = dma_sgl_addr & DMA_ADDR_LOW_MASK;
			tmpcdb.ibd_sg_addr.high = dma_sgl_addr >> DMA_ADDR_HIGH_SHIFT;
			tmpcdb.nr_ibd_sg = cmd->nr_ibd_sg;
		}

		if (cmd->nr_obd_sg) {
			tmpcdb.obd_sg_addr.low = dma_sgl_obd_addr & DMA_ADDR_LOW_MASK;
			tmpcdb.obd_sg_addr.high = dma_sgl_obd_addr >> DMA_ADDR_HIGH_SHIFT;
			tmpcdb.nr_obd_sg = cmd->nr_obd_sg;
		}

		/* TODO: remove tmpcdb */
		tmpcdb.indicators = eb_comb_cmd_sn(cmd);
		*(cdb) = tmpcdb;

		DPRINTK(DEBUG, "start_fpages:%u nr_pages:%u op:%u\n",
			cdb->start_fpage, cdb->nr_pages, cdb->op);
		DPRINTK(DEBUG, "IBD nr_sg:%u dma_low:%x dma_high:%x\n",
			cdb->nr_ibd_sg, cdb->ibd_sg_addr.low, cdb->ibd_sg_addr.high);
		DPRINTK(DEBUG, "OBD nr_sg:%u dma_low:%x dma_high:%x\n",
			cdb->nr_obd_sg, cdb->obd_sg_addr.low, cdb->obd_sg_addr.high);
		DPRINTK(DEBUG, "cmd_id:%u cdb_id:%u\n", cmd->cmd_id, cmd->cdb_id);

		dma_addr = lun->cdbs_dma_addr + sizeof(struct eblaze_cdb) * cmd->cmd_id;
		dma_sync_single_for_device(&edev->pdev->dev, dma_addr,
					   sizeof(struct eblaze_cdb), DMA_TO_DEVICE);
		dma_sync_single_for_device(&edev->pdev->dev, dma_sgl_addr,
					   sgl_size, DMA_TO_DEVICE);
#ifdef PERF_OPT
		eb_atomic_inc(&edev->submit_io);
		eb_atomic_dec(&edev->pending_io);

		/* here is not quite accurate cuz we dont trigger cdb */
		do_gettimeofday(&cmd->tv);
		cmd->submit_delay = cmd->tv.tv_usec - cmd->submit_delay;
		cmd->hardware_delay = cmd->tv.tv_usec;
#endif
		DPRINTK(DEBUG, "wptr:%u lun:%u\n", lun->write_idx, lun->lun_id);
	}
}

void eblaze_lun_worker(struct work_struct *work)
{
	struct eblaze_lun *lun = container_of(work, struct eblaze_lun, worker);

	if (eb_atomic_inc(&lun->nest) == 1) {
		do {
			eb_cmpl_work(lun);
			eb_submit_work(lun);
		} while (eb_atomic_dec(&lun->nest) != 0);
	}
}

void eblaze_lun_worker_wrapper(struct work_struct *work)
{
	if ((unsigned long)(jiffies - get_cpu_var(enter_jiffies)) >= HZ) {
		put_cpu_var(enter_jiffies);

		schedule();

		get_cpu_var(enter_jiffies) = jiffies;
	}
	put_cpu_var(enter_jiffies);

	eblaze_lun_worker(work);
}

void eb_schedule_cmpl_work(struct eblaze_lun *lun)
{
	queue_work_on(lun->iter_cpu, eblaze_workqueue, &lun->worker);
	lun->iter_cpu = (lun->iter_cpu + 1) % num_online_cpus();
}

void eb_schedule_submit_work(struct eblaze_lun *lun)
{
	/* Call the worker directly */
	eblaze_lun_worker(&lun->worker);
}

irqreturn_t eblaze_irq_handler(int irq, void *arg)
{
	struct eblaze_device *edev = (struct eblaze_device *)arg;
	struct eblaze_lun *lun;
	struct eblaze_cmd *cmd;
	struct eblaze_cmpl_info *info;
	bool has_work = false;
	u32 status;
	u16 last_idx, cur_idx;
	u8 lun_id, cmd_id, cdb_id;
	unsigned long old;

	status = readl(edev->reg_base + REG_IRQ_STATUS_1);
	if (status & REG_IRQ_EVENT_MASK) {
		DPRINTK(DEBUG, "++\n");
		has_work = true;
		eb_atomic_or(&edev->intr_stat, (1 & edev->intr_mask));
		disable_edev_irq(edev);
		tasklet_schedule(&edev->comm_tasklet);
	}

	if (status & REG_IRQ_CPL_MASK) {
		has_work = true;
		cur_idx = (readl(edev->reg_base + REG_CMPL_WPTR) - (edev->cmpls_dma_addr & DMA_ADDR_LOW_MASK)) /
		     	   sizeof(struct eblaze_cmpl_info);
		last_idx = edev->cmpls_write_idx;
		edev->cmpls_write_idx = cur_idx;
		DPRINTK(DEBUG, "last_idx:%u, cur_idx:%u\n", last_idx, cur_idx);

		if (cur_idx != last_idx) {
			if (cur_idx > last_idx) {
				dma_sync_single_for_cpu(&edev->pdev->dev,
							edev->cmpls_dma_addr + sizeof(struct eblaze_cmpl_info) * last_idx,
							sizeof(struct eblaze_cmpl_info) * (cur_idx - last_idx),
							DMA_FROM_DEVICE);
			} else {
				dma_sync_single_for_cpu(&edev->pdev->dev,
							edev->cmpls_dma_addr + sizeof(struct eblaze_cmpl_info) * last_idx,
							sizeof(struct eblaze_cmpl_info) * (MAX_CMPLS_PER_EDEV - last_idx),
							DMA_FROM_DEVICE);
				dma_sync_single_for_cpu(&edev->pdev->dev,
							edev->cmpls_dma_addr,
							sizeof(struct eblaze_cmpl_info) * cur_idx,
							DMA_FROM_DEVICE);
			}

			while (last_idx != cur_idx) {
				info = &edev->cmpls[last_idx];
				lun_id = info->indicators >> 24;
				cmd_id = (info->indicators >> 16) & 0xff;
				cdb_id = (info->indicators >> 8) & 0xff;
				lun = edev->luns[lun_id];
				cmd = lun->cmd_slots[cmd_id];

				BUG_ON(cmd->cmd_id != cmd_id);
				BUG_ON(cmd->cdb_id != cdb_id);
				cmd->status = info->status;
				cmd->nr_ecc = info->nr_ecc;
				old = eb_atomic_or(&lun->cmpl_cmd_bitmap, 1u << cmd_id);
				if (old == 0)
					eb_schedule_cmpl_work(lun);
				serial_add(last_idx, 1, MAX_CMPLS_PER_EDEV);
#ifdef PERF_OPT
				eb_atomic_inc(&lun->edev->recv_io);
				eb_atomic_inc(&lun->edev->wait_io);
				do_gettimeofday(&cmd->tv);
				cmd->hardware_delay = cmd->tv.tv_usec - cmd->hardware_delay;
				cmd->complete_delay = cmd->tv.tv_usec;
#endif
			}

			writel((edev->cmpls_dma_addr + cur_idx * sizeof(struct eblaze_cmpl_info)) & DMA_ADDR_LOW_MASK,
				edev->reg_base + REG_CMPL_RPTR);
			edev->cmpls_read_idx = cur_idx;
		}
	}

	return IRQ_HANDLED;
}

/* Lun manage */
void destroy_edev_lun(struct eblaze_device *edev, int idx)
{
	struct eblaze_lun *lun = edev->luns[idx];
	int order;
	int i;
	BUG_ON(!lun);

	for (i = 0; i < MAX_CMDS_PER_LUN; i++) {
		dma_unmap_single(&edev->pdev->dev, lun->sgl_addrs[i], INLINE_SGL_MAX_SIZE, DMA_TO_DEVICE);
	}

	for (i = 0; i < MAX_SGLS_PER_LUN; i++) {
		free_page(lun->double_sgls[i]);
	}

	dma_unmap_single(&edev->pdev->dev, lun->cdbs_dma_addr, CDB_BUFFER_SIZE, DMA_TO_DEVICE);
	order = get_order(CDB_BUFFER_SIZE);
	free_pages((unsigned long)lun->cdbs, order);
	kfree(lun);
}

struct eblaze_lun *create_edev_lun(struct eblaze_device *edev, int idx)
{
	struct eblaze_lun *lun;
	struct eblaze_cdb *cdbs;
	int order = 0;
	int i;

	if ((lun  = kzalloc(sizeof(struct eblaze_lun), GFP_KERNEL)) == NULL) {
		goto out;
	}

	order = get_order(CDB_BUFFER_SIZE);
	cdbs = (struct eblaze_cdb *)__get_free_pages(GFP_DMA32, order);
	if (cdbs == NULL) {
		goto clean1;
	}

	lun->cdbs = cdbs;
	lun->cdbs_dma_addr = dma_map_single(&edev->pdev->dev, lun->cdbs,
					    CDB_BUFFER_SIZE, DMA_TO_DEVICE);
	for (i = 0; i < MAX_SGLS_PER_LUN; i++) {
		order = get_order(INLINE_SGL_MAX_SIZE);
		lun->double_sgls[i] = __get_free_pages(GFP_KERNEL, order);
		if ((void *)lun->double_sgls[i] == NULL) {
			goto clean3;
		}

		lun->sgl_addrs[i] = dma_map_single(&edev->pdev->dev, (void *)lun->double_sgls[i],
						   INLINE_SGL_MAX_SIZE, DMA_TO_DEVICE);
	}

	//lun->sgl_size = INLINE_SGL_MAX_SIZE;

	lun->write_idx = lun->read_idx = 0;
	lun->lun_id = idx;
	INIT_LIST_HEAD(&lun->submit_list);
	spin_lock_init(&lun->submit_list_lock);

	/* Reserve block0 for badblock manage */
	lun->bytes_size = (uint64_t)((uint64_t)BYTE_SIZE_IN_PAGE * (uint64_t)PAGE_SIZE_IN_BLOCK * (uint64_t)(NR_BLOCKS_PER_LUN - 1));
	DPRINTK(DEBUG, "bytes_size:%llu\n", lun->bytes_size);

	INIT_WORK(&lun->worker, eblaze_lun_worker_wrapper);

	return lun;

clean3:
	for (; i >= 0; i--) {
		dma_unmap_single(&edev->pdev->dev, lun->sgl_addrs[i],
				 INLINE_SGL_MAX_SIZE, DMA_TO_DEVICE);
		free_pages(lun->double_sgls[i], get_order(INLINE_SGL_MAX_SIZE));
	}

	dma_unmap_single(&edev->pdev->dev, lun->cdbs_dma_addr,
			 CDB_BUFFER_SIZE, DMA_TO_DEVICE);
	free_pages((unsigned long)lun->cdbs, get_order(CDB_BUFFER_SIZE));
clean1:
	kfree(lun);
out:
	return NULL;
}

int init_edev_luns(struct eblaze_device *edev)
{
	int i, j;
	struct eblaze_lun *lun;
	uint32_t low, high;
	size_t size;
	int order;
	dma_addr_t addr;

	size = sizeof(struct eblaze_cmpl_info) * (MAX_CMPLS_PER_EDEV);
	order = get_order(size);
	edev->cmpls = (struct eblaze_cmpl_info *)__get_free_pages(GFP_DMA32, order);
	if (edev->cmpls == NULL) {
		return -ENOMEM;
	}

	edev->cmpls_dma_addr = dma_map_single(&edev->pdev->dev, edev->cmpls, size, DMA_FROM_DEVICE);

	for (i = 0; i < NR_LUNS_PER_EDEV; i++) {
		lun = create_edev_lun(edev, i);
		if (lun == NULL) {
			goto failed;
		}

		edev->luns[i] = lun;
		lun->edev = edev;
	}

	for (j = 0; j < NR_LUNS_PER_EDEV; j++) {
		addr = edev->luns[j]->cdbs_dma_addr;
		low = addr & DMA_ADDR_LOW_MASK;
		high = addr >> DMA_ADDR_HIGH_SHIFT;
		BUG_ON(((addr + CDB_BUFFER_SIZE) >> DMA_ADDR_HIGH_SHIFT) != high);
		writel(low, edev->reg_base  + REG_CDB_BUFFER_ADDR_BASE + j * 8);
		writel(high, edev->reg_base + REG_CDB_BUFFER_ADDR_BASE + j * 8 + 4);
		writel(low, edev->reg_base  + REG_CDB_RPTR_BASE        + j * 8);
		writel(high, edev->reg_base + REG_CDB_RPTR_BASE        + j * 8 + 4);
		writel(low, edev->reg_base  + REG_CDB_WPTR_BASE        + j * 8);
		writel(high, edev->reg_base + REG_CDB_WPTR_BASE        + j * 8 + 4);
	}

	low = edev->cmpls_dma_addr & DMA_ADDR_LOW_MASK;
	high = edev->cmpls_dma_addr >> DMA_ADDR_HIGH_SHIFT;
	writel(low, edev->reg_base  + REG_CMPL_BUFFER_ADDR);
	writel(high, edev->reg_base + REG_CMPL_BUFFER_ADDR   + 4);
	writel(low, edev->reg_base  + REG_CMPL_WPTR);
	writel(high, edev->reg_base + REG_CMPL_WPTR          + 4);
	writel(low, edev->reg_base  + REG_CMPL_RPTR);
	writel(high, edev->reg_base                + REG_CMPL_RPTR      + 4);
	writel(MAX_SLOTS_PER_LUN, edev->reg_base   + REG_CDB_BUF_SIZE);
	writel(MAX_CMPLS_PER_EDEV, edev->reg_base  + REG_CMPL_BUFFER_SIZE);
	BUG_ON(((edev->cmpls_dma_addr + size) >> DMA_ADDR_HIGH_SHIFT) != high);

	eblaze_init_comm_context(edev);

	/* TODO:disable the dma cmd queue rptr notify interrupt */

	return 0;
failed:

	for (; i >= 0; i--) {
		destroy_edev_lun(edev, i);
	}

	dma_unmap_single(&edev->pdev->dev, edev->cmpls_dma_addr, size, DMA_FROM_DEVICE);
	kfree(edev->cmpls);

	return -EINVAL;
}

void destroy_edev_luns(struct eblaze_device *edev)
{
	size_t size;
	int i;

	size = sizeof(struct eblaze_cmpl_info) * (MAX_CMPLS_PER_EDEV);
	dma_unmap_single(&edev->pdev->dev, edev->cmpls_dma_addr, size, DMA_FROM_DEVICE);
	free_pages((unsigned long)edev->cmpls, get_order(size));

	for (i = 0; i < NR_LUNS_PER_EDEV; i++) {
		destroy_edev_lun(edev, i);
	}
}

#define PRINT_LOW_WORD  0x01
#define PRINT_HIGH_WORD 0x02
static struct eblaze_fpga_counter fpga_counter[] = {
	{0x7C803200, 0x01, "scatter_output_sob_cpl_debug_cnt"},
	{0x7C803200, 0x02, "scatter_input_sob_cpl_debug_cnt"},
	{0x7C803204, 0x01, "scatter_ram_rd_cpl_debug_cnt"},
	{0x7C803204, 0x02, "scatter_cmd_read_dv_cpl_debug_cnt"},
	{0x7C803208, 0x01, "host_dma_cpl_cpl_state_cnt_debug_cnt"},
	{0x7C803208, 0x02, "host_dma_cpl_state_cnt_debug_cnt"},
	{0x7C80320c, 0x01, "gather_cpl_extract_sof_cmd_debug_cnt"},
	{0x7C80320c, 0x02, "gather_ram_we_cmd_debug_cnt"},
	{0x7C803210, 0x01, "gather_cmd_read_dv_cmd_debug_cnt"},
	{0x7C803210, 0x02, "host_dma_cmd_get_cpl_status_cnt_debug_cnt"},
	{0x7C803214, 0x01, "host_dma_cmd_get_status_cnt_debug_cnt"},
	{0x7C803214, 0x02, "scatter_output_sob_cpl_ch_debug_cnt[0]"},
	{0x7C803218, 0x01, "scatter_input_sob_cpl_ch_debug_cnt[0]"},
	{0x7C803218, 0x02, "scatter_ram_rd_cpl_ch_debug_cnt[0]"},
	{0x7C80321c, 0x01, "scatter_cmd_read_dv_cpl_ch_debug_cnt[0]"},
	{0x7C80321c, 0x02, "host_dma_cpl_cpl_state_cnt_ch_debug_cnt[0]"},
	{0x7C803220, 0x01, "host_dma_cpl_state_cnt_ch_debug_cnt[0]"},
	{0x7C803220, 0x02, "scatter_output_sob_cpl_ch_debug_cnt[1]"},
	{0x7C803224, 0x01, "scatter_input_sob_cpl_ch_debug_cnt[1]"},
	{0x7C803224, 0x02, "scatter_ram_rd_cpl_ch_debug_cnt[1]"},
	{0x7C803228, 0x01, "scatter_cmd_read_dv_cpl_ch_debug_cnt[1]"},
	{0x7C803228, 0x02, "host_dma_cpl_cpl_state_cnt_ch_debug_cnt[1]"},
	{0x7C80322c, 0x01, "host_dma_cpl_state_cnt_ch_debug_cnt[1]"},
	{0x7C80322c, 0x02, "scatter_output_sob_cpl_ch_debug_cnt[2]"},
	{0x7C803230, 0x01, "scatter_input_sob_cpl_ch_debug_cnt[2]"},
	{0x7C803230, 0x02, "scatter_ram_rd_cpl_ch_debug_cnt[2]"},
	{0x7C803234, 0x01, "scatter_cmd_read_dv_cpl_ch_debug_cnt[2]"},
	{0x7C803234, 0x02, "host_dma_cpl_cpl_state_cnt_ch_debug_cnt[2]"},
	{0x7C803238, 0x01, "host_dma_cpl_state_cnt_ch_debug_cnt[2]"},
	{0x7C803238, 0x02, "scatter_output_sob_cpl_ch_debug_cnt[3]"},
	{0x7C80323c, 0x01, "scatter_input_sob_cpl_ch_debug_cnt[3]"},
	{0x7C80323c, 0x02, "scatter_ram_rd_cpl_ch_debug_cnt[3]"},
	{0x7C803240, 0x01, "scatter_cmd_read_dv_cpl_ch_debug_cnt[3]"},
	{0x7C803240, 0x02, "host_dma_cpl_cpl_state_cnt_ch_debug_cnt[3]"},
	{0x7C803244, 0x01, "host_dma_cpl_state_cnt_ch_debug_cnt[3]"},

	{0x7C803380, 0x01, "S_rd_cnt_nand"},
	{0x7C803382, 0x02, "S_rd_cnt_nand_front"},
	{0x7C803384, 0x01, "S_rd_cnt"},
	{0x7C803388, 0x01, "CH0_S_we_cnt"},
	{0x7C80338A, 0x02, "CH1_S_we_cnt"},
	{0x7C80338C, 0x01, "CH2_S_we_cnt"},
	{0x7C80338E, 0x02, "CH3_S_we_cnt"},
	{0x7C803390, 0x01, "CH4_S_we_cnt"},
	{0x7C803392, 0x02, "CH5_S_we_cnt"},
	{0x7C803394, 0x01, "CH6_S_we_cnt"},
	{0x7C803396, 0x02, "CH7_S_we_cnt"},
	{0x7C803398, 0x01, "CH8_S_we_cnt"},
	{0x7C80339A, 0x02, "CH9_S_we_cnt"},
	{0x7C80339C, 0x01, "CH10_S_we_cnt"},
	{0x7C80339E, 0x02, "CH11_S_we_cnt"},
	{0x7C8033A0, 0x01, "CH0_read_cnt"},
	{0x7C8033A2, 0x02, "CH1_read_cnt"},
	{0x7C8033A4, 0x01, "CH2_read_cnt"},
	{0x7C8033A6, 0x02, "CH3_read_cnt"},
	{0x7C8033A8, 0x01, "CH4_read_cnt"},
	{0x7C8033AA, 0x02, "CH5_read_cnt"},
	{0x7C8033AC, 0x01, "CH6_read_cnt"},
	{0x7C8033AE, 0x02, "CH7_read_cnt"},
	{0x7C8033B0, 0x01, "CH8_read_cnt"},
	{0x7C8033B2, 0x02, "CH9_read_cnt"},
	{0x7C8033B4, 0x01, "CH10_read_cnt"},
	{0x7C8033B6, 0x02, "CH11_read_cnt"},
	{0x7C8033B8, 0x01, "CH0_read_front_cnt"},
	{0x7C8033BA, 0x02, "CH1_read_front_cnt"},
	{0x7C8033BC, 0x01, "CH2_read_front_cnt"},
	{0x7C8033BE, 0x02, "CH3_read_front_cnt"},
	{0x7C8033C0, 0x01, "CH4_read_front_cnt"},
	{0x7C8033C2, 0x02, "CH5_read_front_cnt"},
	{0x7C8033C4, 0x01, "CH6_read_front_cnt"},
	{0x7C8033C6, 0x02, "CH7_read_front_cnt"},
	{0x7C8033C8, 0x01, "CH8_read_front_cnt"},
	{0x7C8033CA, 0x02, "ch9_read_front_cnt"},
	{0x7C8033CC, 0x01, "ch10_read_front_cnt"},
	{0x7C8033CE, 0x02, "ch11_read_front_cnt"},
	{0x7C8033D0, 0x01, "inst_read_cnt"},
	{0x7C8033D2, 0x02, "inst_prog_cnt"},

	{0x7C803304, 0x01, "CH0_S_interleave_cnt"},
	{0x7C803306, 0x02, "CH1_S_interleave_cnt"},
	{0x7C803308, 0x01, "CH2_S_interleave_cnt"},
	{0x7C80330A, 0x02, "CH3_S_interleave_cnt"},
	{0x7C80330C, 0x01, "CH4_S_interleave_cnt"},
	{0x7C80330E, 0x02, "CH5_S_interleave_cnt"},
	{0x7C803310, 0x01, "CH6_S_interleave_cnt"},
	{0x7C803312, 0x02, "CH7_S_interleave_cnt"},
	{0x7C803314, 0x01, "CH8_S_interleave_cnt"},
	{0x7C803316, 0x02, "CH9_S_interleave_cnt"},
	{0x7C803318, 0x01, "CH10_S_interleave_cnt"},
	{0x7C80331A, 0x02, "CH11_S_interleave_cnt"},
	{0x7C80331C, 0x01, "CH0_S_8k_cnt_wr_nand_cmd"},
	{0x7C80331E, 0x02, "CH1_S_8k_cnt_wr_nand_cmd"},
	{0x7C803320, 0x01, "CH2_S_8k_cnt_wr_nand_cmd"},
	{0x7C803322, 0x02, "CH3_S_8k_cnt_wr_nand_cmd"},
	{0x7C803324, 0x01, "CH4_S_8k_cnt_wr_nand_cmd"},
	{0x7C803326, 0x02, "CH5_S_8k_cnt_wr_nand_cmd"},
	{0x7C803328, 0x01, "CH6_S_8k_cnt_wr_nand_cmd"},
	{0x7C80332A, 0x02, "CH7_S_8k_cnt_wr_nand_cmd"},
	{0x7C80332C, 0x01, "CH8_S_8k_cnt_wr_nand_cmd"},
	{0x7C80332E, 0x02, "CH9_S_8k_cnt_wr_nand_cmd"},
	{0x7C803330, 0x01, "CH10_S_8k_cnt_wr_nand_cmd"},
	{0x7C803332, 0x02, "CH11_S_8k_cnt_wr_nand_cmd"},
	{0x7C803334, 0x01, "CH0_S_cmd_cnt_controller"},
	{0x7C803336, 0x02, "CH1_S_cmd_cnt_controller"},
	{0x7C803338, 0x01, "CH2_S_cmd_cnt_controller"},
	{0x7C80333A, 0x02, "CH3_S_cmd_cnt_controller"},
	{0x7C80333C, 0x01, "CH4_S_cmd_cnt_controller"},
	{0x7C80333E, 0x02, "CH5_S_cmd_cnt_controller"},
	{0x7C803340, 0x01, "CH6_S_cmd_cnt_controller"},
	{0x7C803342, 0x02, "CH7_S_cmd_cnt_controller"},
	{0x7C803344, 0x01, "CH8_S_cmd_cnt_controller"},
	{0x7C803346, 0x02, "CH9_S_cmd_cnt_controller"},
	{0x7C803348, 0x01, "CH10_S_cmd_cnt_controller"},
	{0x7C80334A, 0x02, "CH11_S_cmd_cnt_controller"},
	{0x7C80334C, 0x01, "CH0_S_cmd_cnt_intel"},
	{0x7C80334E, 0x02, "CH1_S_cmd_cnt_intel"},
	{0x7C803350, 0x01, "CH2_S_cmd_cnt_intel"},
	{0x7C803352, 0x02, "CH3_S_cmd_cnt_intel"},
	{0x7C803354, 0x01, "CH4_S_cmd_cnt_intel"},
	{0x7C803356, 0x02, "CH5_S_cmd_cnt_intel"},
	{0x7C803358, 0x01, "CH6_S_cmd_cnt_intel"},
	{0x7C80335A, 0x02, "CH7_S_cmd_cnt_intel"},
	{0x7C80335C, 0x01, "CH8_S_cmd_cnt_intel"},
	{0x7C80335E, 0x02, "CH9_S_cmd_cnt_intel"},
	{0x7C803360, 0x01, "CH10_S_cmd_cnt_intel"},
	{0x7C803362, 0x02, "CH11_S_cmd_cnt_intel"},
	{0x7C803364, 0x01, "CH0_none_read_error_cnt"},
	{0x7C803366, 0x02, "CH1_none_read_error_cnt"},
	{0x7C803368, 0x01, "CH2_none_read_error_cnt"},
	{0x7C80336A, 0x02, "CH3_none_read_error_cnt"},
	{0x7C80336C, 0x01, "CH4_none_read_error_cnt"},
	{0x7C80336E, 0x02, "CH5_none_read_error_cnt"},
	{0x7C803370, 0x01, "CH6_none_read_error_cnt"},
	{0x7C803372, 0x02, "CH7_none_read_error_cnt"},
	{0x7C803374, 0x01, "CH8_none_read_error_cnt"},
	{0x7C803376, 0x02, "CH9_none_read_error_cnt"},
	{0x7C803378, 0x01, "CH10_none_read_error_cnt"},
	{0x7C80337A, 0x02, "CH11_none_read_error_cnt"},

	{0x7C803284, 0x01, "S_4k_cnt_mux"},
	{0x7C803288, 0x01, "S_4k_cnt_decode"},
	{0x7C80328C, 0x01, "S_4k_cnt_demux"},
	{0x7C803290, 0x01, "S_8k_cnt_cmd"},
	{0x7C803294, 0x01, "S_pkg_gen_cnt"},
	{0x7C803298, 0x01, "S_axi_valid_pos_cnt"},
	{0x7C80329A, 0x02, "S_axi_valid_cnt"},
	{0x7C80329C, 0x01, "S_arvalid_cnt"},
	{0x7C80329E, 0x02, "nand_rpkg_error_header_dv_cnt"},
	{0x7C8032A0, 0x01, "nand_rpkg_bch_error_header_dv_cnt"},
	{0x7C8032A2, 0x02, "nand2mem_wdone_dv_cnt"},
	{0x7C8032A4, 0x01, "xor_wdone_dv_cnt"},
	{0x7C8032A6, 0x02, "xor_rpkg_sob_cnt"},
	{0x7C8032A8, 0x01, "nand_rpkg_2pcie_dv_cnt"},
	{0x7C8032AA, 0x02, "mem_rpkg_sob_cnt"},
	{0x7C8032AC, 0x01, "nand_rpkg_2mem_sob_cnt"},
	{0x7C8032AE, 0x02, "d2p_cmd_dv_cnt"},
	{0x7C8032B0, 0x01, "mem_rpkg_buf_sob_cnt_cnt"},
	{0x7C8032B2, 0x02, "mem_rpkg_2n_sob_cnt"},
	{0x7C8032B4, 0x01, "mem_rpkg_2n_sob_xen_cnt"},
	{0x7C8032B6, 0x02, "n2x_cmd_header_only_cnt"},
	{0x7C8032B8, 0x01, "n2x_cmd_dv_4k_cnt"}
};

static int eblaze_fpga_read_proc(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	int ret = 0;
	int i, j, k;
	uint32_t value;
	struct eblaze_lun *lun = (struct eblaze_lun *)data;
	struct eblaze_device *edev = lun->edev;
	int nr = sizeof(fpga_counter) / sizeof(struct eblaze_fpga_counter);

	for (i = (int)off, j = 0; i < nr; i++) {
		if (ret >= PAGE_SIZE - 1024 - 256) {
			*start = (char *)(unsigned long)j;
			goto end;
		}

		writel(fpga_counter[i].addr, edev->reg_base + 0x5000);
		for (k = 0; k < 16; k++)
			value = readl(edev->reg_base + 0x5004);

		if (fpga_counter[i].flag & PRINT_LOW_WORD) {
			value &= 0xffff;
		} else if (fpga_counter[i].flag & PRINT_HIGH_WORD) {
			value &= 0xffff0000;
			value >>= 16;
		}

		ret += sprintf(page + ret, "%-44s: %5d  %4x %12x\n",
			       fpga_counter[i].name, value, value, fpga_counter[i].addr);
		j++;
	}

	*start = (char *)(unsigned long)j;
	*eof = 1;
end:
	return ret;
}

static int eblaze_stat_read_proc(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	int ret = 0;
	int i;
	struct eblaze_lun *lun = (struct eblaze_lun *)data;
	struct eblaze_device *edev = lun->edev;

	ret += sprintf(page + ret, "[cmd queue] wptr:%u rptr:%u\n",
		       lun->write_idx, lun->read_idx);
	ret += sprintf(page + ret, "[cpl queue] wptr:%u rptr:%u\n",
		       edev->cmpls_write_idx, edev->cmpls_read_idx);
	ret += sprintf(page + ret, "[edev status] %u\n", edev->status);
	ret += sprintf(page + ret, "192 luns send:\n");
	for (i = 0; i < NR_LUNS_PER_EDEV; i++) {
		ret += sprintf(page + ret, "%llu ", edev->luns[i]->send_io);
	}
	ret += sprintf(page + ret, "\n");
	ret += sprintf(page + ret, "edev pending:%llu, wait:%llu\n",
		       edev->pending_io, edev->wait_io);

	*eof = 1;

	return ret;
}

static int eblaze_create_proc_for_lun(struct eblaze_lun *lun, struct proc_dir_entry *dir_ent)
{
	uint32_t id;
	char stat_str[16], fpga_str[16];
	struct proc_dir_entry *ent;

	id = lun->lun_id;
	snprintf(stat_str, 16, "stat-%u", id);
	snprintf(fpga_str, 16, "fpga-%u", id);

	/* If create one proc file failed, just return without deleting others */
	ent = create_proc_entry(stat_str, 0444, dir_ent);
	if (ent == NULL) {
		DPRINTK(ERR, "Create entry stat failed\n");
		return -ENOMEM;
	}
	ent->read_proc = eblaze_stat_read_proc;
	ent->write_proc = NULL;
	ent->data = lun;

	ent = create_proc_entry(fpga_str, 0644, dir_ent);
	if (ent == NULL) {
		DPRINTK(ERR, "Create entry fpga failed\n");
		return -ENOMEM;
	}
	ent->read_proc = eblaze_fpga_read_proc;
	ent->write_proc = NULL;
	ent->data = lun;

	return 0;
}

static void eblaze_remove_proc_for_lun(struct eblaze_lun *lun, struct proc_dir_entry *dir_ent)
{
	uint32_t id;
	char stat_str[16], fpga_str[16];

	id = lun->lun_id;
	snprintf(stat_str, 16, "stat-%u", id);
	snprintf(fpga_str, 16, "fpga-%u", id);

	remove_proc_entry(stat_str, dir_ent);
	remove_proc_entry(fpga_str, dir_ent);
}

int eblaze_create_proc(struct eblaze_device *edev)
{
	int ret = 0;
	int flag = 0;
	int i;
	struct eblaze_lun *lun;

	edev->proc_dir = proc_mkdir(edev->name, NULL);
	if (edev->proc_dir == NULL)
		return -ENOMEM;

	/* If create proc file on one pcie failed, just return without deleting raid proc file */
	for (i = 0; i < NR_LUNS_PER_EDEV; i++) {
		lun = edev->luns[i];
		ret = eblaze_create_proc_for_lun(lun, edev->proc_dir);
		if (ret) {
			flag = 1;
			DPRINTK(NOTICE, "Create proc for lun:%d failed\n", i);
		}
	}

	/* Return the last error */
	return (flag == 0) ? 0 : -1;
}

void eblaze_remove_proc(struct eblaze_device *edev)
{
	int i;
	struct eblaze_lun *lun;

	for (i = 0; i < NR_LUNS_PER_EDEV; i++) {
		lun = edev->luns[i];
		eblaze_remove_proc_for_lun(lun, edev->proc_dir);
	}

	remove_proc_entry(edev->name, edev->proc_dir->parent);
	edev->proc_dir = NULL;
}

static inline void eblaze_send_cmd_end(struct eblaze_comm_dev *ecd)
{
	writel((CMD_EXITINT << CMD_SHIFT), ecd->write_reg);
}

static u32 eblaze_send_cmd_imm(u32 cmd, u16 data, struct eblaze_comm_dev *ecd)
{
	u32 read_value;
	u32 value;

	cmd &= CMD_MASK;
	value = IS_MAJORCMD(cmd) ? ST_INTERRUPT_MASK : 0u;
	value |= (cmd << CMD_SHIFT) | (((u32)data & DATA_MASK) << DATA_SHIFT);
	writel(value, ecd->write_reg);
	do {
		read_value = readl(ecd->read_reg);
#ifdef ASSERTCHECK
		if (read_value == 0xffffffff) {
			DPRINTK(DEBUG, "%08x\n", readl(ecd->read_reg));
			while (true)
				;
		}
#endif
	} while (((read_value & ST_CMD_MASK) >> ST_CMD_SHIFT) != cmd);

	return (read_value & ST_DATA_MASK) >> ST_DATA_SHIFT;
}

inline u32 eblaze_transfer_cur_cmd(struct eblaze_msg *ioctl_cmd,
				   u32 instruction_index, u16 *data_in, u16 **data_out)
{
	u32 cur_cmd;

	*data_out = NULL;

	if (instruction_index == 1) {
		cur_cmd = ioctl_cmd->ioctl_req->major_cmd;
	} else if (instruction_index == ioctl_cmd->ioctl_req->len + 2) {
		cur_cmd = CMD_ENDCMD;
	} else {
		cur_cmd = (instruction_index & 1) ? CMD_DATA1 : CMD_DATA2;

		if (ioctl_cmd->ioctl_req->is_write) {
			*data_in = ioctl_cmd->data[instruction_index - 2];
		} else {
			*data_out = ioctl_cmd->data + (instruction_index - 2);
		}
	}

	return cur_cmd;
}

static int eblaze_send_cmd_noimm(struct eblaze_comm_dev *ecd)
{
	struct eblaze_msg *ioctl_cmd = NULL;
	u32 cur_cmd;
	u32 last_cmd;
	u16 data_in;
	u16 *data_out;
	u32 reg_read;
	u32 isr_status;
	int retry;

	data_in = 0u;
	data_out = NULL;

	if (!list_empty(&ecd->cmd_list))
		ioctl_cmd = list_first_entry(&ecd->cmd_list, struct eblaze_msg, node);

	while (ioctl_cmd != NULL) {
		retry = 40;

		/* Must check it cuz this flow may break when retry is 0 */
		if (ecd->instruction_index == 0) {
			++ecd->instruction_index;
			cur_cmd = eblaze_transfer_cur_cmd(ioctl_cmd, ecd->instruction_index, &data_in, &data_out);
			isr_status = IS_MAJORCMD(cur_cmd) ? ST_INTERRUPT_MASK : 0u;
			writel(isr_status | (cur_cmd << CMD_SHIFT) | (((u32)data_in) << DATA_SHIFT), ecd->write_reg);
		}

		cur_cmd = eblaze_transfer_cur_cmd(ioctl_cmd, ecd->instruction_index, &data_in, &data_out);
		while (true) {
			reg_read = readl(ecd->read_reg);
			last_cmd = (reg_read & ST_CMD_MASK) >> ST_CMD_SHIFT;

			if (last_cmd != cur_cmd) {
				if (--retry == 0) {
					return -ETIMEDOUT;
				}
				continue;
			}

			retry = 40;

			if (data_out != NULL) {
				*data_out = (reg_read & ST_DATA_MASK) >> ST_DATA_SHIFT;
			}

			if (++ecd->instruction_index == ioctl_cmd->ioctl_req->len + 3) {
				eblaze_send_cmd_end(ecd);
				ecd->instruction_index = 0;
				list_del(&ioctl_cmd->node);

				if (ioctl_cmd->ioctl_req->request_status == CMD_ECHO_SUCCEED) {
					ioctl_cmd->ioctl_req->request_status = (reg_read & ST_DATA_MASK) >> ST_DATA_SHIFT;
				}

				/* Multi-tasklet will access pending_dev parallel */
				if (eb_atomic_dec(&ioctl_cmd->ioctl_req->pending_dev) == 0) {
					complete(&ioctl_cmd->ioctl_req->ioctl_comp);
				}

				if (!list_empty(&ecd->cmd_list))
					ioctl_cmd = list_first_entry(&ecd->cmd_list, struct eblaze_msg, node);
				else
					ioctl_cmd = NULL;

				break;
			}

			cur_cmd = eblaze_transfer_cur_cmd(ioctl_cmd, ecd->instruction_index, &data_in, &data_out);
			isr_status = IS_MAJORCMD(cur_cmd) ? ST_INTERRUPT_MASK : 0u;
			writel(isr_status | (cur_cmd << CMD_SHIFT) | (((u32)data_in) << DATA_SHIFT), ecd->write_reg);
		}
	}

	return 0;
}

static void eblaze_comm_imm(u32 major_cmd, u32 len, u16 *data, bool is_write,
			    struct eblaze_comm_dev *ecd)
{
	u32 cmd, stat;

	eblaze_send_cmd_imm(major_cmd, 0, ecd);
	len = len / sizeof(u16);
	cmd = CMD_DATA1;
	while (len-- != 0) {
		if (is_write)
			eblaze_send_cmd_imm(cmd, *data, ecd);
		else
			*data = eblaze_send_cmd_imm(cmd, 0, ecd);
		cmd = CMD_DATA1 + CMD_DATA2 - cmd;

		DPRINTK(DEBUG, "cmd %x\n", cmd);

		++data;
	}

	stat = eblaze_send_cmd_imm(CMD_ENDCMD, 0, ecd);
	eblaze_send_cmd_end(ecd);
}


void eblaze_comm_noimm(struct eblaze_msg *ioctl_cmd, struct eblaze_device *edev)
{
	struct eblaze_comm_dev *ecd = &edev->comm_dev;

	/* link task to ecd linked list */
	spin_lock_bh(&ecd->cmd_list_lock);
	list_add_tail(&ioctl_cmd->node, &ecd->cmd_list);
	spin_unlock_bh(&ecd->cmd_list_lock);

	/* trigger interrupt tasklet */
	eb_atomic_or(&edev->intr_stat, 1);

	disable_edev_irq(edev);
	tasklet_schedule(&edev->comm_tasklet);
}

static void eblaze_clear_wait(struct eblaze_comm_dev *ecd)
{
	DPRINTK(DEBUG, "clear wait++\n");
	eblaze_comm_imm(CMD_CLEARWAIT, 0, NULL, false, ecd);
	DPRINTK(DEBUG, "clear wait--\n");
}

static void eblaze_clear_intr(struct eblaze_comm_dev *ecd)
{
	DPRINTK(DEBUG, "clear interrupt++\n");
	eblaze_comm_imm(CMD_CLEARINT, 0, NULL, false, ecd);
	DPRINTK(DEBUG, "clear interrupt--\n");
}

static void eblaze_read_info(struct eblaze_comm_dev *ecd)
{
	char format[256];
	struct eblaze_print_info print_info;

	eblaze_comm_imm(CMD_READINFO, sizeof(struct eblaze_print_info),
			(u16 *)&print_info, false, ecd);
	strncpy(format, (char *)(print_info.value + print_info.paramlen),
		print_info.strlen);
	printk("[fw] ");
	printk(format,
	       print_info.value[0], print_info.value[1], print_info.value[2],
	       print_info.value[3], print_info.value[4], print_info.value[5],
	       print_info.value[6], print_info.value[7], print_info.value[8],
	       print_info.value[9], print_info.value[10], print_info.value[11],
	       print_info.value[12], print_info.value[13],
	       print_info.value[14], print_info.value[15]);
}

static void eblaze_pcd_handle(struct eblaze_device *edev)
{
	int ret = 0;
	u32 value, new_status;
	struct eblaze_comm_dev *ecd = &edev->comm_dev;

	value = readl(ecd->read_reg);
	new_status = (value & ST_STAGE_MASK) >> ST_STAGE_SHIFT;

check_again:
	if ((edev->status != new_status) &&
	    (edev->status != ST_STAGE_MID || new_status != ST_STAGE_READY)) {
		DPRINTK(NOTICE, "edev change status from %u to %u\n",
			edev->status, new_status);
		edev->status = new_status;
		schedule_work(&edev->stat_work);
	}

	/* Handle device cmd first */
	ret = eblaze_send_cmd_noimm(ecd);
	if (ret) {
		DPRINTK(DEBUG, "Device send cmd sequence timeout\n");
	} else if (value & ST_WAIT_MASK) {
		switch ((value & ST_MSG_MASK) >> ST_MSG_SHIFT) {
		case MSG_READYWAIT:
			DPRINTK(DEBUG, "msg ready wait\n");
			break;
		case MSG_PRINT:
			eblaze_read_info(ecd);
			break;
		case MSG_BADTETRIS:
			DPRINTK(DEBUG, "msg bad tetris\n");
			break;
		default:
			DPRINTK(DEBUG, "msg unknown:%x\n",
				(value & ST_MSG_MASK) >> ST_MSG_SHIFT);
			break;
		}

		/*
		 * If pcd clear wait when ready, set status to ST_STAGE_MID.
		 * during this MID-RUN period, reinit op should wait it to run.
		 */
		if (edev->status == ST_STAGE_READY) {
			if (edev->is_unload == false) {
				eblaze_clear_wait(&edev->comm_dev);
				edev->status = ST_STAGE_MID;
			}
		} else {
			/* In this case, raid's status will change to READY */
			DPRINTK(DEBUG, "clear ready anyway, status:%d\n", edev->status);
			eblaze_clear_wait(&edev->comm_dev);
		}
	} else {
			DPRINTK(DEBUG, "status:%u\n", new_status);
			eblaze_clear_intr(&edev->comm_dev);
	}

	value = readl(ecd->read_reg);
	new_status = (value & ST_STAGE_MASK) >> ST_STAGE_SHIFT;
	if (new_status != edev->status)
		goto check_again;
}

static u32 get_intr_stat(struct eblaze_device *edev)
{
	u32 old, new;

	do {
		old = edev->intr_stat;
		if ((old & INTR_LOCK_MASK) || !old)
			return 0;

		new = INTR_LOCK_MASK;
	} while (eb_atomic_cmpxchg(&edev->intr_stat, old, new) != old);

	return old;
}

static void eblaze_comm_tasklet(unsigned long arg)
{
	u32 cur;
	struct eblaze_device *edev = (struct eblaze_device *)arg;

	cur = 0;
	do {
		cur = get_intr_stat(edev);
		if (!cur) {
			enable_edev_irq(edev);
			return;
		}

		disable_edev_irq(edev);
		eblaze_pcd_handle(edev);
		enable_edev_irq(edev);

		eb_atomic_and(&edev->intr_stat, (INTR_LOCK_MASK - 1));
	} while (true);
}

void eblaze_ioctl_req_init(struct eblaze_ioctl_request *ioctl_request,
			   struct eblaze_msg *ioctl_cmd, u32 major_cmd,
			   u32 cmd_seq_len, void *data_in, void** data_out,
			   u32 pending_dev)
{
	int i;
	bool is_write;

	is_write = IS_CMDTODEV(major_cmd);
	ioctl_request->major_cmd = major_cmd;
	ioctl_request->len = cmd_seq_len / sizeof(u16);
	ioctl_request->is_write = is_write;
	init_completion(&ioctl_request->ioctl_comp);
	ioctl_request->pending_dev = pending_dev;
	ioctl_request->request_status = CMD_ECHO_SUCCEED;

	for (i = 0; i != pending_dev; ++i) {
		if (is_write) {
			ioctl_cmd[i].data = data_in;
		} else if (data_out != NULL) {
			ioctl_cmd[i].data = data_out[i];
		}
		ioctl_cmd[i].ioctl_req = ioctl_request;
	}
}

void eblaze_beacon(struct eblaze_device *edev, bool is_baecon_On)
{
	uint16_t baecon_value;	
	struct eblaze_ioctl_request ioctl_request;
	struct eblaze_msg ioctl_cmd;

	baecon_value = is_baecon_On;
	eblaze_ioctl_req_init(&ioctl_request, &ioctl_cmd, CMD_BAECON,
			      sizeof(uint16_t), &baecon_value, NULL, 1);
	/* send CMD_BAECON to pcie device 0 cpu 1 */
	eblaze_comm_noimm(&ioctl_cmd, edev);
	wait_for_completion(&ioctl_request.ioctl_comp);
}

int eblaze_send_fw(struct eblaze_device *edev, u32 size, char *data)
{
	struct eblaze_ioctl_request ioctl_request;
	struct eblaze_msg ioctl_cmd[1];

	DPRINTK(DEBUG, "++\n");
	eblaze_ioctl_req_init(&ioctl_request, ioctl_cmd, CMD_WRITEFIRMWARE,
			      size, data, NULL, 1);
	eblaze_comm_noimm(&ioctl_cmd[0], edev);
	wait_for_completion(&ioctl_request.ioctl_comp);
	DPRINTK(DEBUG, "++\n");

	return ioctl_request.request_status;
}

char *rom_str="Model:\0PB3LM600G01\0Serial Number:\0MH13240262\0Firmware Version:\00007\0\0\0";
void eblaze_get_rom_info(struct eblaze_device *edev)
{
#if 1
	eblaze_comm_imm(CMD_READROM, sizeof(edev->rom.rom), (u16 *)edev->rom.rom,
			false, &edev->comm_dev);
#else
	int i;
	for (i = 0; i < 128; i++)
		edev->rom.rom[i] = rom_str[i];
#endif
	strncpy(edev->rom.driver_version, driver_version,
		min(strlen(driver_version) + 1, sizeof(edev->rom.driver_version)));
}

u32 eblaze_read_xadc_value(struct eblaze_device *edev, int which)
{
	u32 value;

	writel(which << XADC_WRITE_SHIFT, edev->reg_base + REG_XADC);

	do {
		value = readl(edev->reg_base + REG_XADC);
	} while (((value & XADC_WRITE_MASK) >> XADC_WRITE_SHIFT) != which);

	return readl(edev->reg_base + REG_XADC) & XADC_READ_MASK;
}

void eblaze_get_dyn_info(struct eblaze_device *edev, struct dyn_info *d_info)
{
	d_info->capacity_max = (u64)((u64)BYTE_SIZE_IN_PAGE * (u64)PAGE_SIZE_IN_BLOCK * (u64)(NR_BLOCKS_PER_LUN) * (u64)NR_LUNS_PER_EDEV);
	d_info->link_width = edev->pcie_link_width;
	d_info->link_gen = edev->pcie_link_gen;

	d_info->board_temperature = (readl(edev->reg_base + REG_PCB_TEMPERATURE) & PCB_TEMPERATURE_MASK);;
	d_info->temperature = eblaze_read_xadc_value(edev, XADC_TEMP_CHN);
	d_info->temperature_max = eblaze_read_xadc_value(edev, XADC_MAX_TEMP_CHN);
	d_info->temperature_min = eblaze_read_xadc_value(edev, XADC_MIN_TEMP_CHN);
}

long eblaze_wait_status(struct eblaze_device *edev, u32 stat, long timeout)
{
	long ret;

	if (!edev)
		return -1;

	ret = wait_event_interruptible_timeout(edev->stat_wq,
					       edev->status == stat, timeout);
	if (ret < 0) {
		return ret;
	} else if (ret == 0) {
		return -ETIMEDOUT;
	}

	return 0;
}

void eblaze_status_change_worker(struct work_struct *work)
{
	struct eblaze_device *edev;
	
	edev = container_of(work, struct eblaze_device, stat_work);
	if (waitqueue_active(&edev->stat_wq)) {
		DPRINTK(DEBUG, "worker: wake up wait queue\n");
		wake_up_interruptible(&edev->stat_wq);
	}
}

void eblaze_init_comm_context(struct eblaze_device *edev)
{
	edev->comm_dev.read_reg = edev->reg_base + REG_MB0_C2S;
	edev->comm_dev.write_reg = edev->reg_base + REG_MB0_S2C;
	spin_lock_init(&edev->comm_dev.cmd_list_lock);
	INIT_LIST_HEAD(&edev->comm_dev.cmd_list);
	edev->status = ST_STAGE_INIT;
	init_waitqueue_head(&edev->stat_wq);
	INIT_WORK(&(edev->stat_work), eblaze_status_change_worker);
	tasklet_init(&edev->comm_tasklet, eblaze_comm_tasklet, (unsigned long)edev);
}

#ifdef EBLAZE_TFD_INTERFACE
extern struct pci_driver tfd_driver;
#endif
#ifdef EBLAZE_BLK_INTERFACE
extern struct pci_driver blk_driver;
#endif

static int __init eblaze_init(void)
{
	int ret = 0;

	int cpu_num;
	int i;
	unsigned long *value;
	cpu_num = num_online_cpus();

	for (i = 0; i < cpu_num; i++) {
		value = &get_cpu_var(enter_jiffies);
		*value = jiffies;
		put_cpu_var(enter_jiffies);
	}

	cmd_pool = kmem_cache_create("cmd_pool", sizeof(struct eblaze_cmd), 0,
				    SLAB_HWCACHE_ALIGN, NULL);
	if (cmd_pool == NULL) {
		DPRINTK(ERR, "Create cmd pool failed\n");
		return -ENOMEM;
	}
	sema_init(&cmd_limiter, 1024);

	eblaze_workqueue = create_workqueue("eblaze_workerd");
	if (eblaze_workqueue == NULL) {
		kmem_cache_destroy(cmd_pool);
		return -ENOMEM;
	}

	spin_lock_init(&cet_lock);
	ret = eblaze_char_major = register_chrdev(0, "EBLAZE_CHAR_DEV", &edev_chr_ops);

	if (ret < 0) {
		printk(KERN_INFO "Unable to get major for eblaze device \n");
		goto err1;
	}

	printk(KERN_INFO "char major:%d\n", eblaze_char_major);
	eblaze_class = class_create(THIS_MODULE, "eblaze1");

	if (IS_ERR(eblaze_class)) {
		ret = PTR_ERR(eblaze_class);
		goto err2;
	}

#ifdef EBLAZE_TFD_INTERFACE
	ret = pci_register_driver(&tfd_driver);
#endif
#ifdef EBLAZE_BLK_INTERFACE
	ret = pci_register_driver(&blk_driver);
#endif

	if (ret < 0) {
		goto err3;
	}

	return 0;
err3:
	class_destroy(eblaze_class);
err2:
	unregister_chrdev(eblaze_char_major, "EBLAZE_CHAR_DEV");
err1:
	destroy_workqueue(eblaze_workqueue);
	kmem_cache_destroy(cmd_pool);
	return ret;
}

static void __exit eblaze_exit(void)
{
#ifdef EBLAZE_TFD_INTERFACE
	pci_unregister_driver(&tfd_driver);
#endif
#ifdef EBLAZE_BLK_INTERFACE
	pci_unregister_driver(&blk_driver);
#endif
	class_destroy(eblaze_class);
	unregister_chrdev(eblaze_char_major, "EBLAZE_CHAR_DEV");
	destroy_workqueue(eblaze_workqueue);
	kmem_cache_destroy(cmd_pool);
}

module_param_named(int_interval, eblaze_int_interval, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(int_interval, "Set the interrupt delay");

module_init(eblaze_init);
module_exit(eblaze_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bo Wu <bo.wu@memblaze.com>");
