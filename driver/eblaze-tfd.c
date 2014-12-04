
#include "eblaze-core.h"
#include "eblaze-tfd.h"

#ifdef EBLAZE_TFD_INTERFACE

static struct pci_device_id eblaze_tfd_device_id[] = {
	{0x1c5f, 0x1530, PCI_ANY_ID, PCI_ANY_ID,},
	{0,}
};

static volatile uint8_t tfd_edev_idx = 0;

#ifdef EBLAZE_TFD_ERR_INJECT
u32 ERR_INJECT_META_READ_EIO = 0;
u32 ERR_INJECT_META_READ_NOT_EIO = 0;
u32 ERR_INJECT_DATA_READ_EIO = 0;
u32 ERR_INJECT_DATA_READ_NOT_EIO = 0;
u32 ERR_INJECT_WRITE = 0;
u32 ERR_INJECT_ERASE = 0;

u32 ERR_INJECT_TIMEOUT_READ = 0;
u32 ERR_INJECT_TIMEOUT_WRITE = 0;
u32 ERR_INJECT_TIMEOUT_ERASE = 0;
u32 ERR_INJECT_TIMEOUT_READ_OOB = 0;
u32 ERR_INJECT_TIMEOUT_WRITE_OOB = 0;
u32 ERR_INJECT_TIMEOUT_CHK_BADBLOCK = 0;
u32 ERR_INJECT_TIMEOUT_MARK_BADBLOCK = 0;
#endif

/* start_page unit:4K */
static inline uint32_t tfd_get_start_page(uint32_t start_page, struct eblaze_lun *lun)
{
#ifdef EBLAZE_RAMDISK
	/* 8M = 2048 * 4K */
	return start_page + (lun->lun_id * 2048);
#else
	/* 16K bounce, and reserve block0 */
	return start_page + PAGE_SIZE_IN_BLOCK * SECTOR_SIZE_IN_PAGE +
	       (lun->lun_id << LUN_SHIFT);
#endif
}

static inline uint16_t tfd_get_nr_pages(struct tfd_mtd_request *req)
{
	/*
	 * if erase, nr_pages express block number, if read/write,
	 * nr_pages express the 4K pages calced by req length, if read/write obd,
	 * nr_pages express the 4K pages calced by req ooblen.
	 */
	 /* FIXME: change back after tecent fix his bug */
#if 1
	if (req->type == MTD_REQUEST_ERASE) {
		return (req->len >> (BYTE_SHIFT_IN_PAGE + PAGE_SHIFT_IN_BLOCK));
	} else {
		BUG_ON(req->len == 0);
		return (req->len >> BYTE_SHIFT_IN_SECTOR);
	}
#else
	if (req->type == MTD_REQUEST_ERASE) {
		return (req->len >> (BYTE_SHIFT_IN_PAGE + PAGE_SHIFT_IN_BLOCK));
	} else if (req->type == MTD_REQUEST_READ || req->type == MTD_REQUEST_WRITE) {
		BUG_ON(req->len == 0);
		return (req->len >> BYTE_SHIFT_IN_SECTOR);
	} else if (req->type == MTD_REQUEST_READ_OOB || req->type == MTD_REQUEST_WRITE_OOB) {
		BUG_ON(req->ooblen == 0);
		return (req->ooblen >> 4);
	} else {
		BUG_ON(1);
		return 0;
	}
#endif
}

/*
 * Slice ssl to dsl with nr_pages
 * @dsl: destination scatterlist
 * @ssl: source scatterlist
 * @index: the iter index for ssl, it points to the current usable sl in ssl
 * @offset: the current usable offset in current sl
 * @max_sgl: the sl number of ssl
 * @max_slice: the size to slice from ssl to dsl
 *
 * This interface consider about the case as follows:
 * ssl: 1K--->512K--->3K
 * dsl: 1K--->511K, 1K--->3K
 */
static inline uint16_t slice_sl(struct scatterlist *dsl, struct scatterlist *ssl,
				uint16_t *index, unsigned int *offset,
				uint16_t max_sgl, uint32_t max_slice)
{
	uint16_t i , j;
	uint32_t slice = 0;
	unsigned int left;

	i = 0;
	j = *index;
	if (j == max_sgl)
		return 0;

	if (*offset != 0) {
		i++;
		*dsl = *(ssl + j);
		dsl->offset = *offset;
		left = (ssl + j)->length - (*offset - (ssl + j)->offset);
		if (left <= max_slice) {
			dsl->length = left;
			*offset = 0;
			slice += left;
			j++;
		} else {
			dsl->length = max_slice;
			*offset += max_slice;
			slice += max_slice;
			goto done;
		}
	}

	while (j < max_sgl && slice != max_slice) {
		if (likely(slice + (ssl + j)->length <= max_slice)) {
			*(dsl + i) = *(ssl + j);
			j++;
		} else {
			*(dsl + i) = *(ssl + j);
			(dsl + i)->length = max_slice - slice;
			*offset = (ssl + j)->offset + max_slice - slice;
		}

		slice += (dsl + i)->length;
		i++;
		BUG_ON(i >= 16);
	}

	*index = j;
done:
	DPRINTK(DEBUG, "i:%u j:%u slice:%u, offset:%u\n", i, j, slice, *offset);
	sg_mark_end(dsl + i - 1);
	return i;
}

void tfd_async_io_callback(void *priv, int unused)
{
	struct eblaze_cmd *cmd = (struct eblaze_cmd *)priv;
	struct tfd_mtd_request *req = (struct tfd_mtd_request *)cmd->cmd_private;
	int status = 0;

#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_ERASE) {
		/* Inject erase error one time */
		ERR_INJECT_ERASE = 0;
		if (cmd->op == CMD_ERASE)
			cmd->status = UNKNOWN_ERROR;
	} else if (ERR_INJECT_WRITE) {
		if (cmd->op == CMD_WRITE)
			cmd->status = UNKNOWN_ERROR;
	} else if (ERR_INJECT_META_READ_EIO || ERR_INJECT_DATA_READ_EIO) {
		if (cmd->op == CMD_READ)
			cmd->status = BCH_ERROR_3;
	} else if (ERR_INJECT_META_READ_NOT_EIO || ERR_INJECT_DATA_READ_NOT_EIO) {
		if (cmd->op == CMD_READ)
			cmd->status = UNKNOWN_ERROR;
	}
#endif

	if (cmd->has_context == false) {
		if (cmd->op == CMD_READ) {
			if (cmd->status == BCH_ERROR_3) {
				status = -EIO;
				req->nr_ecc = cmd->nr_ecc;
			}
#ifdef EBLAZE_TFD_ERR_INJECT
			if (cmd->status == UNKNOWN_ERROR)
				status = -EAGAIN;
#endif
		} else {
			if (cmd->status)
				status = -EAGAIN;
		}

		if (status == 0) {
			req->retlen = req->len;
		} else {
			req->retlen = status;
			req->ooblen = 0;

			DPRINTK(ERR, "eblaze_lun:%u cmd:%u S:%u L:%u error:%u\n",
				cmd->lun->lun_id, cmd->op, cmd->start_fpage,
				cmd->nr_pages, cmd->status);
		}
		req->callbk(req);
	} else {
		/* Only read or write big io would has context */
		if (cmd->op == CMD_READ) {
			if (cmd->status == BCH_ERROR_3) {
				cmd->context->status = -EIO;
				if (req->nr_ecc < cmd->nr_ecc)
					req->nr_ecc = cmd->nr_ecc;
			}
		} else {
			if (cmd->status)
				cmd->context->status = -EAGAIN;
		}

		if (eb_atomic_dec(&cmd->context->nr_slice) == 0) {
			if (cmd->context->status == 0) {
				req->retlen = req->len;
			} else {
				req->retlen = cmd->context->status;
				req->ooblen = 0;

				DPRINTK(ERR, "eblaze_lun:%u cmd:%u S:%u L:%u error:%u\n",
					cmd->lun->lun_id, cmd->op, cmd->start_fpage,
					cmd->nr_pages, cmd->status);
			}

			kfree(cmd->context->reqs);
			kfree(cmd->context);
			req->callbk(req);
		}
	}
}

int32_t tfd_do_async_io(struct tfd_mtd_request *req)
{
	int ret = 0;
	int i;
	uint8_t op = 0;
	struct eblaze_lun *lun = (struct eblaze_lun *)req->tfd_mtd->mtd.priv;
	struct eblaze_cmd *cmd;
	struct eblaze_cmd_context *context;
	struct eblaze_inside_request *reqs, *inside_req;
	uint32_t start_page;
	uint16_t nr_pages, nr_slice;
	uint16_t ibd_sl_index = 0, obd_sl_index = 0;
	unsigned int ibd_sl_offset = 0, obd_sl_offset = 0;
	bool is_queueempty = false;

	start_page = tfd_get_start_page(req->offset >> BYTE_SHIFT_IN_SECTOR, lun);
	nr_pages = tfd_get_nr_pages(req);
	if (nr_pages == 0 || req->offset + req->len > lun->bytes_size) {
		DPRINTK(ERR, "IO check failed, S:%llu, L:%lu", req->offset, req->len);
		req->retlen = -EINVAL;
		req->ooblen = 0;
		req->callbk(req);
		return -EINVAL;
	}

	if (req->type == MTD_REQUEST_READ || req->type == MTD_REQUEST_READ_OOB)
		op = CMD_READ;
	else if (req->type == MTD_REQUEST_WRITE || req->type == MTD_REQUEST_WRITE_OOB)
		op = CMD_WRITE;
	else if (req->type == MTD_REQUEST_ERASE)
		op = CMD_ERASE;
	else
		WARN_ON(1);

	/*
	 * If io pages larger than INNER_MAX_PAGE_NUM, should slice it.
	 * To keep things simple, all of the scatterlist segment len should be
	 * 4K times which is guaranteed by tecent design.
	 */
	nr_slice = (nr_pages + INNER_MAX_PAGE_NUM - 1) / INNER_MAX_PAGE_NUM;
	if (likely(nr_slice <= 1 || op == CMD_ERASE)) {
		/* submit the io directly to dma */
		cmd = eb_alloc_cmd(lun);
		cmd->cmd_private = (void *)req;
		cmd->start_fpage = start_page;
		cmd->nr_pages = nr_pages;
		cmd->callback = tfd_async_io_callback;
		if (req->nr_datasg != 0) {
			cmd->ibd_sg = (struct scatterlist *)req->databuf;
			cmd->nr_orig_ibd_sg = req->nr_datasg;
			cmd->nr_ibd_sg = dma_map_sg(&lun->edev->pdev->dev, cmd->ibd_sg,
						    cmd->nr_orig_ibd_sg,
						    (op == CMD_WRITE) ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
		}
		if (req->nr_oobsg != 0) {
			cmd->obd_sg = (struct scatterlist *)req->oobbuf;
			cmd->nr_orig_obd_sg = req->nr_oobsg;
			cmd->nr_obd_sg = dma_map_sg(&lun->edev->pdev->dev, cmd->obd_sg,
						    cmd->nr_orig_obd_sg,
						    (op == CMD_WRITE) ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
		}

		cmd->op = op;
		is_queueempty = eb_insert_cmd(cmd, lun);
	} else {
		DPRINTK(DEBUG, "slice the big io, nr_slice:%u\n", nr_slice);
		context = kzalloc(sizeof(struct eblaze_cmd_context), GFP_KERNEL);
		reqs = kzalloc(sizeof(struct eblaze_inside_request) * nr_slice, GFP_KERNEL);
		if (context == NULL || reqs == NULL) {
			kfree(context);
			kfree(reqs);
			return -ENOMEM;
		}

		context->nr_slice = nr_slice;
		context->reqs = reqs;
		i = 0;
		while (i < nr_slice) {
			/* Alloc cmd from a slab pool */
			cmd = eb_alloc_cmd(lun);
			cmd->context = context;
			cmd->has_context = true;
			cmd->cmd_private = (void *)req;
			cmd->start_fpage = start_page;
			cmd->nr_pages = min(nr_pages, (uint16_t)INNER_MAX_PAGE_NUM);
			start_page += cmd->nr_pages;
			nr_pages -= cmd->nr_pages;
			cmd->callback = tfd_async_io_callback;

			inside_req = reqs + i;
			i++;
			if (req->nr_datasg != 0) {
				cmd->nr_orig_ibd_sg = slice_sl(inside_req->ibd_sgl, req->databuf,
							       &ibd_sl_index, &ibd_sl_offset,
							       req->nr_datasg, INNER_MAX_IO_SIZE);
				cmd->ibd_sg = inside_req->ibd_sgl;
				cmd->nr_ibd_sg = dma_map_sg(&lun->edev->pdev->dev, cmd->ibd_sg,
							    cmd->nr_orig_ibd_sg,
							    (op == CMD_WRITE) ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
			}
			if (req->nr_oobsg != 0) {
				cmd->nr_orig_obd_sg = slice_sl(inside_req->obd_sgl, req->oobbuf,
							       &obd_sl_index, &obd_sl_offset,
							       req->nr_oobsg, INNER_MAX_OBD_SIZE);

				/* The obd may have only one 64 bytes for a flash page(16K) */
				if (cmd->nr_orig_obd_sg != 0) {
					cmd->obd_sg = inside_req->obd_sgl;
					cmd->nr_obd_sg = dma_map_sg(&lun->edev->pdev->dev, cmd->obd_sg,
								    cmd->nr_orig_obd_sg,
								    (op == CMD_WRITE) ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
				}
			}

			cmd->op = op;
			is_queueempty |= eb_insert_cmd(cmd, lun);
		}
	}

	if (is_queueempty)
		eb_schedule_submit_work(lun);

	return ret;
}

/* Read ibd or read ibd+obd */
int32_t tfd_async_read(struct tfd_mtd_request *req)
{
#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_TIMEOUT_READ) {
		while (1)
			;
	}
#endif

	if (req->offset & BYTE_MASK_IN_SECTOR || req->len & BYTE_MASK_IN_SECTOR) {
		DPRINTK(ERR, "IO should be 4K align\n");
		req->retlen = -EINVAL;
		req->callbk(req);
		return -EINVAL;
	}

	if (req->nr_datasg == 0) {
		DPRINTK(ERR, "nr_datasg is 0\n");
		req->retlen = -EINVAL;
		req->callbk(req);
		return -EINVAL;
	}

	return tfd_do_async_io(req);
}

/*
 * Write ibd+obd, but here we just check ibd sgl, if the nr_pages set,
 * fw don't care the ibd sgl is null or the obd sgl is null.
 */
int32_t tfd_async_write(struct tfd_mtd_request *req)
{
#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_TIMEOUT_WRITE) {
		while (1)
			;
	}
#endif
	if (req->offset & BYTE_MASK_IN_PAGE || req->len & BYTE_MASK_IN_PAGE) {
		DPRINTK(ERR, "IO should be 4K align\n");
		req->retlen = -EINVAL;
		req->callbk(req);
		return -EINVAL;
	}

	if (req->nr_datasg == 0) {
		DPRINTK(ERR, "nr_datasg is 0\n");
		req->retlen = -EINVAL;
		req->callbk(req);
		return -EINVAL;
	}

	return tfd_do_async_io(req);
}

/* Read obd only */
int32_t tfd_async_read_oob(struct tfd_mtd_request *req)
{
#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_TIMEOUT_READ_OOB) {
		while (1)
			;
	}
#endif
	/* TODO: check the oob len */

	if (req->nr_oobsg == 0) {
		DPRINTK(ERR, "nr_oobsg is 0\n");
		req->ooblen = -EINVAL;
		req->callbk(req);
		return -EINVAL;
	}

	return tfd_do_async_io(req);
}

/*
 * Write ibd+obd, but here we just check obd sgl, if the nr_pages set,
 * fw don't care the ibd sgl is null or the obd sgl is null.
 */
int32_t tfd_async_write_oob(struct tfd_mtd_request *req)
{
#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_TIMEOUT_WRITE_OOB) {
		while (1)
			;
	}
#endif
	/* TODO: check the oob len */

	if (req->nr_oobsg == 0) {
		DPRINTK(ERR, "nr_oobsg is 0\n");
		req->ooblen = -EINVAL;
		req->callbk(req);
		return -EINVAL;
	}

	return tfd_do_async_io(req);
}

int32_t tfd_async_erase(struct tfd_mtd_request *req)
{
#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_TIMEOUT_ERASE) {
		while (1)
			;
	}
#endif
	if (req->offset & ERASE_MASK || req->len & ERASE_MASK) {
		DPRINTK(ERR, "IO should be 4K align\n");
		req->retlen = -EINVAL;
		req->callbk(req);
		return -EINVAL;
	}

	if (req->nr_datasg != 0 || req->nr_oobsg != 0) {
		DPRINTK(ERR, "nr_datasg or nr_oobsg is not 0\n");
		req->retlen = -EINVAL;
		req->ooblen = 0;
		req->callbk(req);
		return -EINVAL;
	}

	return tfd_do_async_io(req);
}

static void tfd_sync_io_callback(void *priv, int status)
{
	struct eblaze_cmd *cmd = (struct eblaze_cmd *)priv;
	struct tfd_page_request *req = (struct tfd_page_request *)cmd->cmd_private;

	if (status)
		DPRINTK(ERR, "lun_id:%u, op:%u, S:%u, L:%u, error:%u\n",
			req->lun->lun_id, req->op, req->start_page, req->nr_pages, req->status);

	req->status = status;
	complete(&req->req_cpl);
}

static void tfd_do_sync_io(struct tfd_page_request *req)
{
	bool is_write = false;
	struct eblaze_lun *lun = req->lun;
	struct eblaze_cmd *cmd;
	unsigned long timeout;

	cmd= eb_alloc_cmd(lun);
	cmd->cmd_private = (void *)req;

	/* Access block0, don't reserve it as tfd_get_start_page */
	cmd->start_fpage = req->start_page + (lun->lun_id << LUN_SHIFT);
	cmd->nr_pages = req->nr_pages;
	cmd->op = req->op;
	cmd->callback = tfd_sync_io_callback;

	if (req->op == CMD_ERASE) {
		goto issue_io;
	} else if (req->op == CMD_WRITE) {
		is_write = true;
	} else if (req->op == CMD_READ) {
		is_write = false;
	} else {
		WARN_ON(1);
	}

	if (req->nr_orig_ibd_sg != 0) {
		cmd->ibd_sg = &req->ibd_sgl;
		cmd->nr_orig_ibd_sg= req->nr_orig_ibd_sg;
		cmd->nr_ibd_sg = dma_map_sg(&lun->edev->pdev->dev, cmd->ibd_sg, cmd->nr_orig_ibd_sg,
					    is_write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
	}

	if (req->nr_orig_obd_sg != 0) {
		cmd->obd_sg = &req->obd_sgl;
		cmd->nr_orig_obd_sg = req->nr_orig_obd_sg;
		cmd->nr_obd_sg = dma_map_sg(&lun->edev->pdev->dev, cmd->obd_sg, cmd->nr_orig_obd_sg,
					    is_write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
	}

issue_io:
	/*
	 * There is a risk that complete done before the waiting call.
	 * Use timeout to prevent it, if timeout, req->status will tell us the
	 * the truly result.
	 */
	init_completion(&req->req_cpl);
	if (eb_insert_cmd(cmd, lun))
		eb_schedule_submit_work(lun);
	timeout = wait_for_completion_timeout(&req->req_cpl, HZ * BBE_IO_TIMEOUT);
	if (timeout == 0)
		DPRINTK(ERR, "io timeout\n");
}

/* insert_badblock should be protected by op_sem or run in single mode */
static inline uint32_t insert_badblock(struct tfd_bbe *bbe, uint32_t block_id, uint8_t inside_lun_id)
{
	int i;
	uint32_t addr;

	if (bbe->bba_cnt == MAX_BBA_PER_BBE) {
		WARN_ON(1);
		return -ERR_BBA_OVERFLOW;
	}

	addr = comb_addr(0, inside_lun_id, block_id, 0);
	for (i = 0; i < bbe->bba_cnt; i++) {
		DPRINTK(DEBUG, "addr:%u new_addr:%u extr:%u, new:%u\n",
			bbe->bba_array[i], addr, extr_block_addr(bbe->bba_array[i]), block_id);

		if (bbe->bba_array[i] ==  addr) {
			DPRINTK(ERR, "Badblock addr is already record\n");
			return -ERR_BBA_DUP;
		}
	}

	bbe->bba_array[bbe->bba_cnt++] = addr;

	return 0;
}

/* log_badblock should be protected by op_sem or run in single mode */
static int32_t log_badblock(uint32_t tetris_id, struct eblaze_device *edev)
{
	int ret;
	uint8_t i, j;
	struct tfd_page_request req;
	struct tfd_bbm *bbm = &edev->bbms[tetris_id];
	struct tfd_bbe *bbe = &bbm->bbe;
	uint8_t target_lun[MAX_BBE_COPY];
	uint8_t inside_lun_id = 0;
	uint8_t lun_id = 0;
	uint32_t min_erase = -1;
	uint32_t offset;

	for (i = 0; i != MAX_BBE_COPY; i++) {
		inside_lun_id = 0;
		min_erase = -1;
		for (j = 0; j != LUN_SIZE_IN_TETRIS; j++) {
			if ((bbm->status[j] & (BBB_VITAL | BBB_NEXT_VITAL | BBB_ERR)) == 0) {
				if (bbm->pos[j] == PAGE_SIZE_IN_BLOCK) {
					if(bbm->bbe.erase_cnt[j] < min_erase) {
						min_erase = bbm->bbe.erase_cnt[j];
						inside_lun_id = j;
					}
				} else {
					inside_lun_id = j;
					break;
				}
			}
		}

		target_lun[i] = inside_lun_id;
		bbm->status[inside_lun_id] |= BBB_NEXT_VITAL;
	}

	for (i = 0; i != LUN_SIZE_IN_TETRIS; i++) {
		bbm->status[i] &= ~BBB_VITAL;
	}

	for(i = 0; i != MAX_BBE_COPY; i++) {
		inside_lun_id = target_lun[i];
		bbm->status[inside_lun_id] ^= BBB_VITAL | BBB_NEXT_VITAL;
	}

	bbm->bbe.generation++;
	bbm->nr_copy = 0;
	for(i = 0; i != MAX_BBE_COPY; i++) {
		inside_lun_id = target_lun[i];
		lun_id = inside_lun_id + tetris_id * NR_LUN_PER_TETRIS;
		offset = bbm->pos[inside_lun_id];

		DPRINTK(NOTICE, "Log bbe: inside_lun:%u, real_lun:%u, ofs:%u\n",
			inside_lun_id, lun_id, offset);

		if (offset == PAGE_SIZE_IN_BLOCK) {
			offset = 0;
			(bbe->erase_cnt[inside_lun_id])++;
			bbm->pos[inside_lun_id] = 0;

			req.lun = edev->luns[lun_id];
			req.start_page = 0;
			req.nr_pages = 1;	/* one block */
			req.op = CMD_ERASE;
			tfd_do_sync_io(&req);
			if (req.status != 0) {
				DPRINTK(ERR, "Erase block0 error\n");
				bbm->status[inside_lun_id] |= BBB_ERR;
				insert_badblock(bbe, 0, inside_lun_id);
				ret = -ERR_LOG_BBE;
				return ret;
			}
		}

		req.lun = edev->luns[lun_id];
		req.start_page = offset * SECTOR_SIZE_IN_PAGE;
		req.nr_pages = 4;
		req.op = CMD_WRITE;
		sg_init_table(&req.ibd_sgl, 1);
		req.ibd = (void *)__get_free_pages(GFP_KERNEL, 2);
		if (req.ibd == NULL) {
			DPRINTK(ERR, "Alloc page failed\n");
			ret = -ENOMEM;
			return ret;
		}
		sg_set_page(&req.ibd_sgl, virt_to_page(req.ibd), PAGE_SIZE * 4, 0);
		sg_init_table(&req.obd_sgl, 1);
		sg_set_buf(&req.obd_sgl, (void *)req.obd, sizeof(struct tfd_obd) * 4);

		memcpy(req.ibd, (void *)&bbm->bbe, sizeof(struct tfd_bbe));
		req.obd[0].token = VALID_PAGE_TOKEN;
		req.obd[1].token = VALID_HI_PAGE_TOKEN;

		req.nr_orig_ibd_sg = 1;
		req.nr_orig_obd_sg = 1;
		tfd_do_sync_io(&req);
		__free_pages(virt_to_page(req.ibd), 2);
		if (req.status != 0) {
			DPRINTK(ERR, "Write bbe error\n");
			bbm->status[inside_lun_id] |= BBB_ERR;
			insert_badblock(bbe, 0, inside_lun_id);
			ret = -ERR_LOG_BBE;
			return ret;
		}

		/* Update the write position for bbm */
		bbm->pos[inside_lun_id]++;
		bbm->nr_copy++;
	}

	DPRINTK(DEBUG, "bbm bbe copy:%u\n", bbm->nr_copy);
	return 0;
}

int32_t is_badblock(struct eblaze_lun *lun, uint32_t block_id)
{
	int i;
	uint32_t addr;
	uint32_t tetris_id = lun->lun_id;
	uint8_t inside_lun_id;
	struct tfd_bbm *bbm;
	struct tfd_bbe *bbe;

	inside_lun_id = do_div(tetris_id, NR_LUN_PER_TETRIS);
	bbm = &lun->edev->bbms[tetris_id];
	bbe = &bbm->bbe;
	addr = comb_addr(0, inside_lun_id, block_id, 0);
	down(&bbm->op_sem);
	for (i = 0; i < bbe->bba_cnt; i++) {
		DPRINTK(DEBUG, "addr:%u extr:%u, new:%u\n",
			bbe->bba_array[i], extr_block_addr(bbe->bba_array[i]), block_id);

		if (bbe->bba_array[i] == addr) {
			up(&bbm->op_sem);
			return 1;
		}
	}
	up(&bbm->op_sem);

	return 0;
}

int32_t mark_badblock(struct eblaze_lun *lun, uint32_t block_id)
{
	int ret;
	uint16_t i = 0;
	uint32_t tetris_id = lun->lun_id;
	uint8_t inside_lun_id;
	struct tfd_bbm *bbm;
	struct tfd_bbe *bbe;

	inside_lun_id = do_div(tetris_id, NR_LUN_PER_TETRIS);
	bbm = &lun->edev->bbms[tetris_id];
	bbe = &bbm->bbe;
	down(&bbm->op_sem);
	ret = insert_badblock(bbe, block_id, inside_lun_id);
	if (ret) {
		up(&bbm->op_sem);
		return ret;
	}

	while (i++ < (NR_LUN_PER_TETRIS - MAX_BBE_COPY)) {
		ret = log_badblock(tetris_id, lun->edev);
		if (ret == 0)
			break;
	}
	up(&bbm->op_sem);

	return ret;
}

int32_t tfd_block_isbad(struct tfd_mtd *mtd, loff_t ofs)
{
	int ret;
	struct eblaze_lun *lun = (struct eblaze_lun *)mtd->mtd.priv;
	uint16_t block_id = ofs >> (BYTE_SHIFT_IN_PAGE + PAGE_SHIFT_IN_BLOCK);

#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_TIMEOUT_CHK_BADBLOCK) {
		while (1)
			;
	}
#endif

	/* The block0 is transparent for user */
	block_id++;
	if (block_id >= NR_BLOCKS_PER_LUN)
		return -ERR_BBA_ILLEGAL;

	ret = is_badblock(lun, block_id);

	return ret;
}

int32_t tfd_block_markbad(struct tfd_mtd *mtd, loff_t ofs)
{
	int ret;
	struct eblaze_lun *lun = (struct eblaze_lun *)mtd->mtd.priv;
	uint16_t block_id = ofs >> (BYTE_SHIFT_IN_PAGE + PAGE_SHIFT_IN_BLOCK);

#ifdef EBLAZE_TFD_ERR_INJECT
	if (ERR_INJECT_TIMEOUT_MARK_BADBLOCK) {
		while (1)
			;
	}
#endif

	/* The block0 is transparent for user */
	block_id++;
	if (block_id >= NR_BLOCKS_PER_LUN)
		return -ERR_BBA_ILLEGAL;

	ret = mark_badblock(lun, block_id);
	return ret;
}

/* Scan the whole 8 eblaze_lun's block0 */
static int tfd_rd_bbm_thread(void *arg)
{
	int ret = 0;
	uint16_t i, j;
	struct tfd_bbm_context *bbm_context = (struct tfd_bbm_context *)arg;
	struct tfd_bbm *bbm = bbm_context->bbm;
	struct tfd_bbe *bbe = &bbm->bbe;
	uint32_t job_id;
	uint32_t offset;
	uint8_t inside_lun_id;
	uint8_t real_lun_id;
	struct tfd_bbe *cur_bbe;
	struct tfd_page_request req;
	struct eblaze_lun *lun;

	cur_bbe = kzalloc(sizeof(struct tfd_bbe), GFP_KERNEL);
	if (cur_bbe ==  NULL) {
		DPRINTK(ERR, "Alloc bbe failed\n");
		bbm_context->scan_failed = true;
		return -ENOMEM;
	}

	/* Calc the lun id and offset for this thread */
	job_id = eb_atomic_inc(&bbm_context->nr_job) - 1;
	inside_lun_id = job_id / NR_JOBS_PER_LUN;
	offset = job_id % NR_JOBS_PER_LUN;		/* always 0 */
	real_lun_id = inside_lun_id + bbm_context->tetris_id * NR_LUN_PER_TETRIS;
	lun = bbm_context->edev->luns[real_lun_id];	/* lun for this thread */

	/* Every lun's bbb be scaned by NR_JOBS_PER_LUN jobs, i is page id */
	for (i = offset; i < PAGE_SIZE_IN_BLOCK; i += NR_JOBS_PER_LUN) {
		req.lun = lun;
		req.start_page = i * SECTOR_SIZE_IN_PAGE;
		req.nr_pages = 4;
		req.op = CMD_READ;

		sg_init_table(&req.ibd_sgl, 1);
		req.ibd = (void *)__get_free_pages(GFP_KERNEL, 2);
		if (req.ibd == NULL) {
			DPRINTK(ERR, "Alloc page failed\n");
			bbm_context->scan_failed = true;
			ret = -ENOMEM;
			goto cleanup;
		}
		sg_set_page(&req.ibd_sgl, virt_to_page(req.ibd), PAGE_SIZE * 4, 0);
		sg_init_table(&req.obd_sgl, 1);
		sg_set_buf(&req.obd_sgl, (void *)req.obd, sizeof(struct tfd_obd) * 4);
		req.nr_orig_ibd_sg = 1;
		req.nr_orig_obd_sg = 1;
		req.status = 0;

		/* If read error, consider this block is unsafe */
		tfd_do_sync_io(&req);
		if (req.status != 0) {
			int bba_iter;

			memcpy((void *)cur_bbe, req.ibd, sizeof(struct tfd_bbe));
			DPRINTK(ERR, "Read block error when scan badblock\n");
			DPRINTK(ERR, "sig:%u, bba_cnt:%u, generation:%u bba_addr:\n",
				cur_bbe->signature, cur_bbe->bba_cnt, cur_bbe->generation);
			for (bba_iter = 0; bba_iter < 32; bba_iter++){
				printk("%u ", cur_bbe->bba_array[bba_iter]);
			}
			printk("\n");

			down(&bbm->op_sem);
			ret = insert_badblock(bbe, 0, inside_lun_id);
			up(&bbm->op_sem);
			bbm->status[lun->lun_id] |= BBB_ERR;
			if (ret == 0)
				bbm_context->need_update = true;

			__free_pages(virt_to_page(req.ibd), 2);
			break;
		}

		/* Search sequentially until found the first empty page, the new bbe will log into this page */
		if (req.obd[0].token == NULL_PAGE_TOKEN) {
			DPRINTK(NOTICE, "Quit search cuz hit empty page:%u\n", i);

			/* Optimize: if one thread, no need this check */
			if (i < bbm->pos[inside_lun_id])
				bbm->pos[inside_lun_id] = i;

			__free_pages(virt_to_page(req.ibd), 2);
			break;
		}

		memcpy((void *)cur_bbe, req.ibd, sizeof(struct tfd_bbe));
		__free_pages(virt_to_page(req.ibd), 2);

		if (cur_bbe->signature == BBM_SIG) {
			down(&bbm->op_sem);

			DPRINTK(NOTICE, "Found bbe, generation:%u, at lun:%u\n",
				cur_bbe->generation, inside_lun_id);

			if (cur_bbe->generation >= bbe->generation) {
				if (cur_bbe->generation > bbe->generation) {
					bbm->nr_copy = 0;
					for (j = 0; j != NR_JOBS_PER_TETRIS; j++) {
						bbm->status[j] &= ~BBB_VITAL;
					}
				}

				eb_atomic_inc(&bbm->nr_copy);
				bbm->status[inside_lun_id] |= BBB_VITAL;
				memcpy((void *)bbe, (void *)cur_bbe, sizeof(struct tfd_bbe));

				DPRINTK(NOTICE, "Update nr_copy:%u, generation:%u\n",
					bbm->nr_copy, bbe->generation);
			}

			up(&bbm->op_sem);
		}
	}

cleanup:
	kfree(cur_bbe);
	if (eb_atomic_dec(&bbm_context->counter) == 0)
		complete(&bbm_context->rd_cpl);

	return 0;
}

static void read_badblock(uint32_t tetris_id, struct tfd_bbm_context *bbm_context)
{
	uint32_t i;

	for (i = 0; i < NR_LUN_PER_TETRIS; i++)
		bbm_context->bbm->pos[i] = PAGE_SIZE_IN_BLOCK;

	for (i = 0; i < NR_JOBS_PER_TETRIS; i++) {
		bbm_context->rd_bbm_jobs[i] = kthread_run(tfd_rd_bbm_thread, bbm_context, "rd_bbm_%d", i);
	}
}

void print_badblock(uint32_t tetris_id, struct eblaze_device *edev)
{
	int i;
	struct tfd_bbm *bbm = &(edev->bbms[tetris_id]);

	printk("-----------------------------------------------------------\n");
	printk("Found bbe copy:%u, generation:%u, bad_cnt:%u\n",
		bbm->nr_copy, bbm->bbe.generation, bbm->bbe.bba_cnt);
	for (i = 0; i < bbm->bbe.bba_cnt; i++) {
		printk("%u@%u ", extr_block_addr(bbm->bbe.bba_array[i]),
		       extr_sl_addr(bbm->bbe.bba_array[i]) + tetris_id * NR_LUN_PER_TETRIS);
		if (i != 0 && i != (bbm->bbe.bba_cnt - 1) && (i % 16) == 0)
			printk("\n");
	}
	printk("\n");

	for (i = 0; i < NR_LUN_PER_TETRIS; i++)
		if (bbm->status[i] == BBB_VITAL)
			printk("At eblaze_lun:%u\n", i);
	printk("-----------------------------------------------------------\n");
}

static int tfd_init_bbm_info(struct eblaze_device *edev)
{
	int ret = 0;
	uint32_t i, j;
	uint32_t bba;
	struct tfd_bbm_context *bbm_context;

	memset(edev->bbms, 0, sizeof(struct tfd_bbm) * NR_TETRIS);
	for (i = 0; i < NR_TETRIS; i++) {
		sema_init(&edev->bbms[i].op_sem, 1);
	}
		
	bbm_context = kmalloc(sizeof(struct tfd_bbm_context), GFP_KERNEL);
	if (bbm_context == NULL)
		return -ENOMEM;

	for (i = 0; i < NR_TETRIS; i++) {
		memset(bbm_context, 0, sizeof(struct tfd_bbm_context));
		bbm_context->edev = edev;
		bbm_context->tetris_id = i;
		bbm_context->bbm = &edev->bbms[i];
		bbm_context->counter = NR_JOBS_PER_TETRIS;

		init_completion(&bbm_context->rd_cpl);
		read_badblock(i, bbm_context);
		wait_for_completion(&bbm_context->rd_cpl);

		for (j = 0; j < bbm_context->bbm->bbe.bba_cnt; j++) {
			bba = bbm_context->bbm->bbe.bba_array[j];
			if (extr_block_addr(bba) == 0) {
				bbm_context->bbm->status[extr_sl_addr(bba)] |= BBB_ERR;
			}
		}

		print_badblock(i, edev);

		if (bbm_context->bbm->nr_copy == 0 || bbm_context->scan_failed == true) {
			DPRINTK(ERR, "Scan badblock for tetris:%u failed\n", i);
			ret = -ERR_BBE_NONE;
			goto cleanup;
		}

		/* It's unsafe that searched bbe less than 2, re-log it again */
		if (bbm_context->bbm->nr_copy < 2 || bbm_context->need_update) {
			j = 0;
			while (j++ < (NR_LUN_PER_TETRIS - MAX_BBE_COPY)) {
				DPRINTK(NOTICE, "Update badblock info:%u\n", j);

				ret = log_badblock(i, edev);
				if (ret == 0) {
					break;
				}
			}
		}
	}

cleanup:
	kfree(bbm_context);
	return ret;
}

static int32_t tfd_lun_init_mtd(struct eblaze_device *edev)
{
	struct eblaze_lun *lun = NULL;
	struct mtd_info *mtd = NULL;
	int i, ret;

	sprintf(edev->hostinfo.name, SSD_DEV_NAME"%c", 'a' + edev->probe_idx);
	edev->hostinfo.can_queue = TFD_MAX_PCI_QUEUE_DEPTH;
	edev->hostinfo.cmd_per_dev = MAX_CMDS_PER_LUN;
	edev->hostinfo.max_length = EXT_MAX_IO_SIZE;
	edev->hostinfo.sg_tablesize = EXT_SGL_MAX_NUM;
	edev->hostinfo.max_segment_size = EXT_MAX_SEGMENT_SIZE;	/* 512K */

	for (i = 0; i < NR_LUNS_PER_EDEV; i++) {
		lun = edev->luns[i];
		if (NULL == lun) {
			DPRINTK(ERR, "lun %d in NULL\n", i);
			return -1;
		}

		mtd = &lun->tfd_mtd.mtd;
		mtd->priv = lun;
		mtd->size = lun->bytes_size;
		mtd->erasesize = lun->edev->erase_size;
		mtd->writesize = lun->edev->write_size;
		mtd->oobsize = lun->edev->oob_size;
		lun->tfd_mtd.host = &edev->hostinfo;
		lun->tfd_mtd.chipnums = 1;
		lun->tfd_mtd.chipsize = lun->bytes_size;
		lun->tfd_mtd.async_read = tfd_async_read;
		lun->tfd_mtd.async_write = tfd_async_write;
		lun->tfd_mtd.async_erase = tfd_async_erase;
		lun->tfd_mtd.async_read_oob = tfd_async_read_oob;
		lun->tfd_mtd.async_write_oob = tfd_async_write_oob;
		lun->tfd_mtd.block_isbad = tfd_block_isbad;
		lun->tfd_mtd.block_markbad = tfd_block_markbad;
		ret = add_tfd_mtd_device(&lun->tfd_mtd, edev->probe_idx);

		if (ret) {
			DPRINTK(ERR, "%s: add mtd %d failed\n", edev->name, i);
			return ret;
		}
	}

	return 0;
}

static void tfd_lun_exit_mtd(struct eblaze_device *edev)
{
	struct eblaze_lun *lun = NULL;
	int i, ret;

	for (i = 0; i < NR_LUNS_PER_EDEV; i++) {
		lun = edev->luns[i];
		if (NULL == lun) {
			DPRINTK(ERR, "lun %d in NULL.\n", i);
			return;
		}

		ret = del_tfd_mtd_device(&lun->tfd_mtd, edev->probe_idx);

		if (ret) {
			DPRINTK(ERR, "%s: del mtd %d failed\n", edev->name, i);
			return;
		}
	}
}

static int tfd_init_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret = 0;
	struct eblaze_device *edev;

	edev = kzalloc(sizeof(struct eblaze_device), GFP_KERNEL);
	if (edev == NULL) {
		return -ENOMEM;
	}

	edev->probe_idx = eb_atomic_inc(&tfd_edev_idx) - 1;
	edev->is_baecon_On = 0;
	sprintf(edev->name, SSD_DEV_NAME"%c", 'a' + edev->probe_idx);
	if ((ret = edev_init_pci(edev, pdev)) != 0) {
		goto clean1;
	}

	edev->pdev = pdev;
	if ((ret = create_edev_chrdev(edev)) != 0) {
		goto clean2;
	}

	/* No used, the tecent limit EXT_SGL_MAX_NUM set is outside */
	edev->sg_tablesize = INLINE_SGL_MAX_NUM;
	edev->max_segment_size = INLINE_MAX_SEGMENT_SIZE;
	edev->write_size = BYTE_SIZE_IN_PAGE;
	edev->erase_size = ERASE_SIZE;
	edev->oob_size = OOB_SIZE;

	if ((ret = init_edev_luns(edev)) != 0) {
		DPRINTK(DEBUG, "init eblaze luns failed\n");
		goto clean3;
	}

	spin_lock_init(&edev->cmpls_lock);

	if ((ret = request_irq(pdev->irq, eblaze_irq_handler, IRQF_SHARED,
			       "eblaze", (void *)edev)) != 0) {
		DPRINTK(DEBUG, "Request irq:%d failed for %s\n",
			pdev->irq, edev->name);
		goto clean4;
	}

	eblaze_get_rom_info(edev);
	enable_edev_irq(edev);
	eblaze_create_proc(edev);

	if ((ret = tfd_lun_init_mtd(edev)) != 0 ) {
		DPRINTK(ERR, "eblaze_lun register mtd fail\n");
		goto clean7;
	}

	ret = tfd_init_bbm_info(edev);
	if (ret < 0) {
		DPRINTK(ERR, "scan badblock info error\n");
		goto clean8;
	}

	sema_init(&edev->ioctl_sem, 1);

	return 1;

clean8:
	tfd_lun_exit_mtd(edev);
clean7:
	disable_edev_irq(edev);
	free_irq(pdev->irq, edev);
clean4:
	destroy_edev_luns(edev);
clean3:
	destroy_edev_chrdev(edev);
clean2:
	eb_atomic_dec(&tfd_edev_idx);
	edev_remove_pci(edev, pdev);
clean1:
	kfree(edev);

	return ret;
}

static void tfd_remove_one(struct pci_dev *pdev)
{
	struct eblaze_device *edev;
	edev = (struct eblaze_device *)pci_get_drvdata(pdev);

	if (edev == NULL) {
		return;
	}

	tfd_lun_exit_mtd(edev);
	eblaze_remove_proc(edev);
	disable_edev_irq(edev);
	free_irq(pdev->irq, edev);
	destroy_edev_luns(edev);
	destroy_edev_chrdev(edev);
	eb_atomic_dec(&tfd_edev_idx);
	edev_remove_pci(edev, pdev);
	kfree(edev);
	printk(KERN_INFO "%s\n", __FUNCTION__);
}

static void tfd_shutdown_one(struct pci_dev *pdev)
{
	struct eblaze_device *edev;
	edev = (struct eblaze_device *)pci_get_drvdata(pdev);

	if (edev == NULL) {
		return;
	}
}

struct pci_driver tfd_driver = {
	.name = "eblaze_tfd",
	.probe = tfd_init_one,
	.remove = tfd_remove_one,
	.shutdown = tfd_shutdown_one,
	.id_table = eblaze_tfd_device_id
};

#endif
