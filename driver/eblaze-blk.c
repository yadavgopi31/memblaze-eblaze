
#include "eblaze-core.h"
#include "eblaze-blk.h"

#ifdef EBLAZE_BLK_INTERFACE

static struct pci_device_id eblaze_blk_device_id[] = {
	{0x1c5f, 0x1530, PCI_ANY_ID, PCI_ANY_ID,},
	{0,}
};

extern uint32_t eblaze_int_interval;
static volatile uint8_t edev_probe_idx = 0;

static inline uint16_t blk_get_lun_id(struct bio *bio)
{
	return (bio->bi_sector * 512 / (u64)LUN_SIZE);
}

static inline uint32_t blk_get_start_page(struct bio *bio, u16 lun_id)
{
	/* 4K bounce */
	return ((bio->bi_sector * 512 % (u64)LUN_SIZE) >> BYTE_SHIFT_IN_SECTOR) +
	        (lun_id << LUN_SHIFT);
}

static inline uint16_t blk_get_nr_pages(struct bio *bio)
{
	/* block device never has erase operation */
	return bio->bi_size >> BYTE_SHIFT_IN_SECTOR;
}

void blk_io_callback(void *priv, int unused)
{
	struct eblaze_cmd *cmd = (struct eblaze_cmd *)priv;
	struct bio *bio = (struct bio *)cmd->cmd_private;

	/* FIXME: Temp for test */
	cmd->status = 0;

	kfree(cmd->ibd_sg);
	bio_endio(bio, cmd->status);
}

static inline void sg_unmark_end(struct scatterlist *sg)
{
	sg->page_link &= ~0x02;
}

static void __blk_segment_map_sg(struct request_queue *q, struct bio_vec *bvec,
				 struct scatterlist *sglist, struct bio_vec **bvprv,
				 struct scatterlist **sg, int *nsegs, int *cluster)
{
	int nbytes = bvec->bv_len;
	if (*bvprv && *cluster) {
		if ((*sg)->length + nbytes > queue_max_segment_size(q))
			goto new_segment;

		if (!BIOVEC_PHYS_MERGEABLE(*bvprv, bvec))
			goto new_segment;
		if (!BIOVEC_SEG_BOUNDARY(q, *bvprv, bvec))
			goto new_segment;

		(*sg)->length += nbytes;
	} else {
new_segment:
		if (!*sg)
			*sg = sglist;
		else {
			sg_unmark_end(*sg);
			*sg = sg_next(*sg);
		}

		sg_set_page(*sg, bvec->bv_page, nbytes, bvec->bv_offset);
		(*nsegs)++;
	}
	*bvprv = bvec;
}

int blk_bio_map_sg(struct request_queue *q, struct bio *bio,
		   struct scatterlist *sglist)
{
	struct bio_vec *bvec, *bvprv;
	struct scatterlist *sg;
	int nsegs, cluster;
	unsigned long i;

	nsegs = 0;
	cluster = 1;	/* FIXME: just set it to 1 */

	bvprv = NULL;
	sg = NULL;
	bio_for_each_segment(bvec, bio, i) {
		__blk_segment_map_sg(q, bvec, sglist, &bvprv, &sg,
				   &nsegs, &cluster);
	} /* segments in bio */

	if (sg)
		sg_mark_end(sg);

	BUG_ON(bio->bi_phys_segments && nsegs > bio->bi_phys_segments);
	return nsegs;
}

int eblaze_make_request(struct request_queue *q, struct bio *bio)
{
	struct scatterlist *sl;
	int nr_segs;
	u16 lun_id;
	struct eblaze_lun *lun;
	struct eblaze_device *edev = (struct eblaze_device *)q->queuedata;
	struct eblaze_cmd *cmd;

	lun_id = blk_get_lun_id(bio);
	lun = edev->luns[lun_id];
	cmd= eb_alloc_cmd(lun);
	BUG_ON(cmd == NULL);

	nr_segs = bio_phys_segments(q, bio);
	while ((sl = kmalloc(sizeof(struct scatterlist) * nr_segs, GFP_KERNEL)) == NULL)
		;
	sg_init_table(sl, nr_segs);
	blk_bio_map_sg(q, bio, sl);
	cmd->op = bio_rw_flagged(bio, BIO_RW) ? CMD_WRITE : CMD_READ;
	cmd->cmd_private = (void *)bio;
	cmd->callback = blk_io_callback;

	cmd->ibd_sg = sl;
	cmd->nr_orig_ibd_sg = nr_segs;
	cmd->nr_ibd_sg = dma_map_sg(&lun->edev->pdev->dev, sl, nr_segs,
				   (cmd->op == CMD_READ) ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	cmd->start_fpage = blk_get_start_page(bio, lun_id);
	cmd->nr_pages = blk_get_nr_pages(bio);

	if (eb_insert_cmd(cmd, lun))
		eb_schedule_submit_work(lun);

	DPRINTK(DEBUG, "cmd S:%u L:%u\n", cmd->start_fpage, cmd->nr_pages);
	return 0;
}

int eblaze_lun_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

int eblaze_lun_release(struct gendisk *disk, fmode_t mode)
{
	return 0;
}

int eblaze_lun_ioctl(struct block_device *bdev, fmode_t mode, unsigned cmd,
		     unsigned long arg)
{
	return 0;
}

static const struct block_device_operations eblaze_blk_fops = {
	.open = eblaze_lun_open,
	.release = eblaze_lun_release,
	.ioctl = eblaze_lun_ioctl
};

static int edev_create_blkdev(struct eblaze_device *edev)
{
	struct gendisk *disk;
	struct request_queue *queue;

	if ((disk = alloc_disk(1 << 4)) == NULL) {
		return -EINVAL;
	}

	if ((queue = blk_init_queue(NULL, NULL)) == NULL) {
		put_disk(disk);
		return -ENOMEM;
	}

	sprintf(disk->disk_name, "%s", edev->name);
	disk->major = edev->block_major;
	disk->first_minor = edev->probe_idx << 4;
	disk->fops = &eblaze_blk_fops;
	disk->private_data = edev;
	blk_queue_make_request(queue, eblaze_make_request);
	blk_queue_bounce_limit(queue, edev->pdev->dma_mask);
#if defined(RHEL_RELEASE_VERSION)
	blk_queue_max_segments(queue, edev->sg_tablesize);
#else
	blk_queue_max_hw_segments(queue, edev->sg_tablesize);
#endif
	blk_queue_max_segment_size(queue, edev->max_segment_size);
	blk_queue_max_hw_sectors(queue, 2048);
	blk_queue_dma_alignment(queue, 0x7);
	blk_queue_logical_block_size(queue, edev->write_size);
	blk_queue_physical_block_size(queue, edev->write_size);
	blk_queue_io_min(queue, edev->write_size);
	blk_queue_io_opt(queue, BYTE_SIZE_IN_PAGE);
	queue->queuedata = edev;
	disk->queue = queue;
	edev->disk = disk;
	edev->queue = queue;
	set_capacity(disk, ((u64)LUN_SIZE * (u64)NR_LUNS_PER_EDEV) >> 9);
	add_disk(disk);

	return 0;
}

static void edev_destroy_blkdev(struct eblaze_device *edev)
{
	del_gendisk(edev->disk);
	put_disk(edev->disk);

	blk_cleanup_queue(edev->queue);
}

static int eblaze_init_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct eblaze_device *edev;
	int ret = 0;

	edev = (struct eblaze_device *)kzalloc(sizeof(struct eblaze_device), GFP_KERNEL);
	if (edev == NULL) {
		return -ENOMEM;
	}

	edev->is_baecon_On = 0;

	if ((ret = edev_init_pci(edev, pdev)) != 0) {
		goto clean1;
	}

	edev->pdev = pdev;
	edev->probe_idx = eb_atomic_inc(&edev_probe_idx) - 1;
	if ((ret = create_edev_chrdev(edev)) != 0) {
		goto clean2;
	}

	edev->sg_tablesize = INLINE_SGL_MAX_NUM;
	edev->max_segment_size = INLINE_MAX_SEGMENT_SIZE;
	edev->write_size = PAGE_SIZE;
	if ((ret = init_edev_luns(edev)) != 0) {
		DPRINTK(ERR, "init eblaze luns failed\n");
		goto clean3;
	}

	spin_lock_init(&edev->cmpls_lock);
	writel(eblaze_int_interval, edev->reg_base + REG_IRQ_CTRL1);
	if ((ret = request_irq(pdev->irq, eblaze_irq_handler, IRQF_SHARED,
			       "eblaze", (void *)edev)) != 0) {
		DPRINTK(ERR, "Unable to get irq %d for %s\n", pdev->irq, edev->name);
		goto clean4;
	}

	eblaze_get_rom_info(edev);
	enable_edev_irq(edev);
	sprintf(edev->name, "eblaze_%c", 'a' + edev->probe_idx);
	ret = register_blkdev(0, edev->name);
	if (ret < 0) {
		DPRINTK(ERR, "Unable to register block major for %s\n", edev->name);
		goto clean5;
	} else {
		edev->block_major = ret;
		DPRINTK(ERR, "Registered block major %d for %s\n", edev->block_major, edev->name);
	}

	if ((ret = edev_create_blkdev(edev)) != 0) {
		DPRINTK(ERR, "Failed to create logical blkdevs for %s\n", edev->name);
		goto clean7;
	}

	eblaze_create_proc(edev);
	sema_init(&edev->ioctl_sem, 1);

	return 1;

clean7:
	unregister_blkdev(edev->block_major, edev->name);
clean5:
	disable_edev_irq(edev);
	free_irq(pdev->irq, edev);
clean4:
	destroy_edev_luns(edev);
clean3:
	destroy_edev_chrdev(edev);
clean2:
	eb_atomic_dec(&edev_probe_idx);
	edev_remove_pci(edev, pdev);
clean1:
	kfree(edev);

	return ret;
}

static void eblaze_remove_one(struct pci_dev *pdev)
{
	struct eblaze_device *edev;

	edev = (struct eblaze_device *)pci_get_drvdata(pdev);
	if (edev == NULL) {
		DPRINTK(ERR, "edev is null\n");
		return;
	}

	eblaze_remove_proc(edev);
	edev_destroy_blkdev(edev);
	unregister_blkdev(edev->block_major, edev->name);
	disable_edev_irq(edev);
	free_irq(pdev->irq, edev);
	destroy_edev_luns(edev);
	destroy_edev_chrdev(edev);
	edev_remove_pci(edev, pdev);
	kfree(edev);
}

static void eblaze_shutdown_one(struct pci_dev *pdev)
{
	struct eblaze_device *edev;

	edev = (struct eblaze_device *)pci_get_drvdata(pdev);
	if (edev == NULL) {
		return;
	}
}

struct pci_driver blk_driver = {
	.name = "eblaze",
	.probe = eblaze_init_one,
	.remove = eblaze_remove_one,
	.shutdown = eblaze_shutdown_one,
	.id_table = eblaze_blk_device_id
};

#endif
