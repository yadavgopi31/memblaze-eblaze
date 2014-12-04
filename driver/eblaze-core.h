#ifndef __EBLAZE_CORE_H__
#define __EBLAZE_CORE_H__

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/aer.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/interrupt.h>
#include <linux/blkdev.h>
#include <linux/irqreturn.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/firmware.h>
#include <linux/semaphore.h>
#include <linux/mempool.h>
#include <linux/time.h>

#include "eblaze-ioctl.h"

#define EBLAZE_DEBUG
//#define EBLAZE_RAMDISK
//#define EBLAZE_TFD_INTERFACE
#define EBLAZE_BLK_INTERFACE
//#define EBLAZE_TFD_ERR_INJECT
//#define PERF_OPT

#define EB_PRINTK_EMERG			0	/* No use */
#define EB_PRINTK_ALERT			1	/* Hardfault, readonly, bad block etc */
#define EB_PRINTK_CRIT			2
#define EB_PRINTK_ERR			3	/* Error */
#define EB_PRINTK_WARNING		4
#define EB_PRINTK_NOTICE		5	/* Execute flow watch */
#define EB_PRINTK_INFO			6	/* Specific debug info */
#define EB_PRINTK_DEBUG			7	/* Huge debug info */

#ifdef EBLAZE_DEBUG
#define PFX				"[eblaze] "
#define EB_DEBUG_LEVEL			EB_PRINTK_NOTICE

#define DPRINTK(level, fmt, args...)					\
	do {								\
		if (EB_PRINTK_##level <= EB_DEBUG_LEVEL)		\
			printk(KERN_##level PFX "%s: %d: " fmt,		\
			       __FUNCTION__, __LINE__, ## args);	\
	} while (0)
#else
#define DPRINTK(level, fmt, args...)
#endif

#define MAX_NR_EDEV			16
#define DMA_ADDR_LOW_MASK		0xffffffff
#define DMA_ADDR_HIGH_SHIFT		32
#define DMA_LEN_SHIFT			3	/* Unit:8 bytes */
#ifndef PCI_EXP_LNKSTA_NLW
#define PCI_EXP_LNKSTA_NLW		0x03f0
#endif

#define BYTE_SHIFT_IN_SECTOR		12	/* 4K bytes */
#define SECTOR_SHIFT_IN_PAGE		2	/* 4 sectors */
#define PAGE_SHIFT_IN_BLOCK 		9	/* 512 pages */
#define BLOCK_SHIFT_IN_LUN		12
#define LUN_SHIFT_IN_TETRIS		3	/* 8 LUN */

#define BLOCK_SHIFT			(SECTOR_SHIFT_IN_PAGE + PAGE_SHIFT_IN_BLOCK)
#define LUN_SHIFT			(BLOCK_SHIFT + BLOCK_SHIFT_IN_LUN)
#define TETRIS_SHIFT			(LUN_SHIFT + LUN_SHIFT_IN_TETRIS)

#define BYTE_SHIFT_IN_PAGE		(BYTE_SHIFT_IN_SECTOR + SECTOR_SHIFT_IN_PAGE)
#define BYTE_SIZE_IN_PAGE		(1 << BYTE_SHIFT_IN_PAGE)
#define BYTE_MASK_IN_PAGE		(BYTE_SIZE_IN_PAGE - 1)
#define BYTE_SIZE_IN_SECTOR		(1 << BYTE_SHIFT_IN_SECTOR)
#define BYTE_MASK_IN_SECTOR		(BYTE_SIZE_IN_SECTOR - 1)
#define SECTOR_SIZE_IN_PAGE		(1 << SECTOR_SHIFT_IN_PAGE)
#define SECTOR_MASK_IN_PAGE		(SECTOR_SIZE_IN_PAGE - 1)
#define PAGE_SIZE_IN_BLOCK		(1 << PAGE_SHIFT_IN_BLOCK)
#define PAGE_MASK_IN_BLOCK		(PAGE_SIZE_IN_BLOCK - 1)
#define BLOCK_SIZE_IN_LUN		(1 << BLOCK_SHIFT_IN_LUN)
#define BLOCK_MASK_IN_LUN		(BLOCK_SIZE_IN_LUN - 1)
#define LUN_SIZE_IN_TETRIS		(1 << LUN_SHIFT_IN_TETRIS)
#define LUN_MASK_IN_TETRIS		(LUN_SIZE_IN_TETRIS - 1)

#define ERASE_SIZE			(BYTE_SIZE_IN_PAGE * PAGE_SIZE_IN_BLOCK)
#define ERASE_MASK			(ERASE_SIZE - 1)
#define OOB_PER_4K			16
#define OOB_SIZE			(OOB_PER_4K * 4)
#define OOB_MASK			(OOB_SIZE - 1)

#ifdef EBLAZE_RAMDISK
#define NR_BLOCKS_PER_LUN		1
#else
#define NR_BLOCKS_PER_LUN		1058
#endif

#define LUN_SIZE			((u64)BYTE_SIZE_IN_PAGE * (u64)PAGE_SIZE_IN_BLOCK * (u64)NR_BLOCKS_PER_LUN)
#define NR_LUNS_PER_EDEV		192

#define MAX_CMDS_PER_LUN		31
#define MAX_SGLS_PER_LUN		MAX_CMDS_PER_LUN
#define MAX_SLOTS_PER_LUN		(MAX_CMDS_PER_LUN + 1)
#define MAX_CMPLS_PER_EDEV 		(MAX_SLOTS_PER_LUN * 256)
#define CDB_NULL			MAX_SLOTS_PER_LUN
#define SGL_NULL			MAX_SGLS_PER_LUN
#define CDB_BUFFER_SIZE			(sizeof(struct eblaze_cdb) * MAX_SLOTS_PER_LUN)

/*
 * The tecent requires max io size as one block, which is 16K * 512.
 * But our driver is 4K, so we need split the big scatterlist.
 */
#define INLINE_IBD_SGL_MAX_SIZE		(2048)
#define INLINE_OBD_SGL_MAX_SIZE		(4096 - INLINE_IBD_SGL_MAX_SIZE)
#define INLINE_SGL_MAX_SIZE		(INLINE_IBD_SGL_MAX_SIZE + INLINE_OBD_SGL_MAX_SIZE)

#define INLINE_SGL_MAX_NUM		(INLINE_IBD_SGL_MAX_SIZE / sizeof(struct eblaze_sgl_elem))
#define INLINE_MAX_SEGMENT_SIZE		(4096 * 64)		/* 256K */
#define INLINE_MAX_PAGE_NUM		(INLINE_SGL_MAX_NUM * INLINE_MAX_SEGMENT_SIZE / PAGE_SIZE)

#define INNER_MAX_PAGE_NUM		(64)
#define INNER_MAX_IO_SIZE		(4096 * INNER_MAX_PAGE_NUM)
#define INNER_MAX_OBD_SIZE		(16 * INNER_MAX_PAGE_NUM)

#define EXT_SGL_MAX_NUM			(32)			/* adapter to tfd_mtd_request */
#define EXT_MAX_SEGMENT_SIZE		(4096 * 64)		/* 256K */
#define EXT_MAX_IO_SIZE			(EXT_MAX_SEGMENT_SIZE * EXT_SGL_MAX_NUM)

#define REG_MB0_S2C			0x10	/* Host 2 Microblaze */
#define REG_MB0_C2S			0x14	/* Microblaze 2 host */	
#define REG_CDB_BUF_SIZE		0x28
#define REG_CMPL_BUFFER_ADDR		0x30
#define REG_CMPL_BUFFER_SIZE		0x38
#define REG_CDB_BUFFER_ADDR_BASE	0x800
#define REG_IRQ_CTRL0			0x1000
#define REG_IRQ_CTRL1			0x1004
#define REG_IRQ_STATUS_1		0x100C
#define REG_IRQ_CPL_BIT			8
#define REG_IRQ_EVENT_BIT		16

#define REG_CDB_WPTR_BASE		0x3000
#define REG_CDB_RPTR_BASE		0x3800
#define REG_CMPL_WPTR			0x4000
#define REG_CMPL_RPTR			0x4800
#define REG_IRQ_CPL_MASK		(1 << REG_IRQ_CPL_BIT)
#define REG_IRQ_EVENT_MASK		(1 << REG_IRQ_EVENT_BIT)

#define REG_PCB_TEMPERATURE		0xc
#define PCB_TEMPERATURE_MASK		0x1fff

#define REG_XADC			0x8
#define XADC_WRITE_SHIFT		16
#define XADC_WRITE_MASK			0x007f0000
#define XADC_READ_MASK			0xffff

#define XADC_TEMP_CHN			0x00
#define XADC_MAX_TEMP_CHN		0x20
#define XADC_MIN_TEMP_CHN		0x24

/* Status Register */
#define ST_DATA_SHIFT			0	/* 0-15 */
#define ST_DATA_MASK			((1 << 16) - 1)
#define ST_CMD_SHIFT			16	/* 16-23 */
#define ST_CMD_MASK			(((1 << 8) - 1) << ST_CMD_SHIFT)
#define ST_MSG_SHIFT			24	/* 24-27 */
#define ST_MSG_MASK			(((1 << 4) - 1) << ST_MSG_SHIFT)
#define ST_STAGE_SHIFT			28	/* 28-29 */
#define ST_STAGE_MASK			(((1 << 2) - 1) << ST_STAGE_SHIFT)
#define ST_WAIT_SHIFT			30
#define ST_WAIT_MASK			(1 << ST_WAIT_SHIFT)
#define ST_INTERRUPT_SHIFT		31
#define ST_INTERRUPT_MASK		(1 << ST_INTERRUPT_SHIFT)

#define MSG_NULL			0
#define MSG_PRINT			1
#define MSG_READYWAIT			2
#define MSG_BADTETRIS			3

#define DATA_MASK			0xffff
#define DATA_SHIFT			0u
#define CMD_MASK			0x7fff
#define CMD_SHIFT			16

#define CMD_ENDCMD			0x21
#define CMD_DATA1			0x22
#define CMD_DATA2			0x23
#define CMD_TOGGLEDEFAULT		0x24
#define CMD_EXITINT			0x25

#define CMD_REINIT			0x14
#define CMD_BADTETRIS_INFO		0x3
#define CMD_READINFO			0x5
#define CMD_READMON			0x6
#define CMD_READROM			0x7
#define CMD_LOCKROM			0x2
#define CMD_WRITEROM			0x11
#define CMD_WRITEFIRMWARE		0x18
#define CMD_CLEARWAIT			0x9
#define CMD_CLEARINT			0xa
#define CMD_BAECON			0x1b

#define MIN_MAJORCMD			0x1
#define MAX_MAJORCMD			0x20
#define CMD_TODEVMASK			0x10
#define IS_CMDTODEV(cmd)		((cmd & CMD_TODEVMASK) != 0)
#define IS_MAJORCMD(cmd)		(cmd >= MIN_MAJORCMD && cmd <= MAX_MAJORCMD)

#define CMD_ECHO_SUCCEED		0
#define CMD_ECHO_FAILED			1
#define CMD_ECHO_INVALID_PARMA		2
#define CMD_ECHO_INVALID_DEVICE		3
#define CMD_ECHO_PROBE_NO_FINISH	4
#define CMD_ECHO_MALLOC_FAILED		5

/* The position bit in u32 to mark tasklet already enter */
#define INTR_LOCK_BIT			20
#define INTR_LOCK_MASK			(0x1 << INTR_LOCK_BIT)

#define NR_JOBS_PER_LUN			1
#define NR_LUN_PER_TETRIS		8
#define NR_TETRIS			(NR_LUNS_PER_EDEV / NR_LUN_PER_TETRIS)
#define NR_JOBS_PER_TETRIS		(NR_JOBS_PER_LUN * NR_LUN_PER_TETRIS)
#define MAX_BBA_PER_BBE			2000	/* Max badblock addr in bbe */
#define MAX_BBE_COPY			2
#define BBM_SIG				0xac5efcb0
#define BBE_IO_TIMEOUT			120	/* HZ */

#define VALID_PAGE_TOKEN		0xca53187e
#define VALID_HI_PAGE_TOKEN		0x7e
#define NULL_PAGE_TOKEN			0x0

#define ERR_LOG_BBE			100
#define ERR_BBE_NONE			101
#define ERR_BBA_OVERFLOW		102
#define ERR_BBA_ILLEGAL			103
#define ERR_BBA_DUP			104

#define MAGICNUMBER			0x32132325

enum {
	BBB_ERR = 1, 		/* this block 0 is corrupt */
	BBB_LOG_ERR = 2,	/* this block 0 is marked as corrupt */
	BBB_VITAL = 4,		/* this block 0 is used as containing bbe */
	BBB_NEXT_VITAL = 8,	/* this block 0 will be used as contaning bbe */
};

/* FIXME: change these tfd_xx names */
struct tfd_obd
{
	union
	{
		uint64_t timestamp;
		uint64_t persistentinfo;
	};

	union
	{
		uint32_t lsa;
		uint32_t metablockindex;
	};

	union
	{
		uint32_t token;
		struct
		{
			uint8_t tokenhi;
			uint8_t status;
			uint16_t erasecount;
		};
	};
};

/*
 * This type sync request is for eblaze inside use, now it's only used
 * in badblock manage code.
 * TODO: make it more general not only for one page.
 */
struct tfd_page_request {
	struct eblaze_lun *lun;
	uint32_t start_page;
	uint16_t nr_pages;

	void *ibd;
	struct tfd_obd obd[4];	/* obd is a 16 bytes struct for 4K */
	struct scatterlist ibd_sgl;
	struct scatterlist obd_sgl;
	int nr_orig_ibd_sg;
	int nr_orig_obd_sg;

	struct completion req_cpl;
	uint16_t status;
	uint16_t op;
};

struct tfd_bbm_context {
	uint32_t tetris_id;
	volatile uint32_t nr_job;
	struct task_struct *rd_bbm_jobs[NR_JOBS_PER_TETRIS];
	volatile uint32_t counter;
	struct completion rd_cpl;
	struct tfd_bbm *bbm;
	struct eblaze_device *edev;
	bool need_update;
	bool scan_failed;
};

struct tfd_bbe {
	uint32_t signature;
	uint32_t bba_cnt;
	uint32_t generation;
	uint32_t bba_array[MAX_BBA_PER_BBE];
	uint16_t erase_cnt[NR_LUN_PER_TETRIS];
};

struct tfd_bbm {
	struct tfd_bbe bbe;
	uint32_t pos[NR_LUN_PER_TETRIS];	/* Current writed pos of block0 */
	uint8_t status[NR_LUN_PER_TETRIS];	/* Current block0 status */
	uint8_t nr_copy;			/* Current writed bbe copy num */
	uint8_t bbm_status;
	struct semaphore op_sem;
};

enum eblaze_io_return_value {
	BCH_ERROR_1 = 1,			/* 38~42 bit error and error recovery */
	BCH_ERROR_3 = 3,			/* more than 43 bit error and can't recovery */
	UNKNOWN_ERROR = 9,			/* for error injection use */
};

enum eblaze_cmd_type {
	CMD_READ = 1,
	CMD_WRITE = 2,
	CMD_ERASE = 3,
};

struct eblaze_inside_request {
	struct scatterlist ibd_sgl[16];
	struct scatterlist obd_sgl[4];
};

struct eblaze_cmd_context {
	int32_t status;
	volatile uint16_t nr_slice;
	struct eblaze_inside_request *reqs;
};

struct eblaze_lun;
struct eblaze_cmd {
	struct eblaze_lun *lun;
	struct list_head node;

	uint32_t start_fpage;
	uint16_t nr_pages;
	struct scatterlist *ibd_sg;
	struct scatterlist *obd_sg;
	int nr_ibd_sg;
	int nr_obd_sg;
	int nr_orig_ibd_sg;
	int nr_orig_obd_sg;

	uint8_t lun_id;
	uint8_t cmd_id;
	uint8_t cdb_id;
	uint8_t fail_cnt;
	uint8_t op;
	uint16_t status;
	uint16_t nr_ecc;
	void *cmd_private;
	bool has_context;
	struct eblaze_cmd_context *context;
	void (*callback)(void *, int);

#ifdef PERF_OPT
	struct timeval tv;
	int submit_delay;
	int hardware_delay;
	int complete_delay;
#endif
};

enum cmd_state {
	CMD_NEW,
	CMD_ABORTED,
	CMD_CDB_READY,
	CMD_CDB_ACKED,
	CMD_DONE_INT,
	CMD_DONE,
	CMD_FAILED
};

enum eblaze_lun_event {
	EB_LUN_SUBMIT_EVENT,
	EB_LUN_CMPL_EVENT,
	EB_LUN_EVENT_COUNT,
};

#pragma pack(2)
struct eblaze_cdb {
	uint32_t start_fpage;
	uint16_t nr_pages;
	uint16_t op;

	struct {
		uint32_t low;
		uint16_t high;
	} ibd_sg_addr;
	uint16_t nr_ibd_sg;

	struct {
		uint32_t low;
		uint16_t high;
	} obd_sg_addr;
	uint16_t nr_obd_sg;

	uint32_t indicators;
	uint16_t status;
	uint16_t reserved;
};

struct eblaze_sgl_elem {
	struct {
		uint32_t low;
		uint16_t high;
	} addr;

	uint16_t len;
};
#pragma pack()

struct eblaze_lun {
	struct work_struct worker;
	struct eblaze_device *edev;
	u64 bytes_size;
	u8 lun_id;
	u8 write_idx;
	u8 read_idx;
	struct eblaze_cdb *cdbs;
	dma_addr_t cdbs_dma_addr;
	long unsigned int submit_cmd_bitmap;
	volatile long unsigned int cmpl_cmd_bitmap;
	struct eblaze_cmd *cmd_slots[MAX_CMDS_PER_LUN];

	/* TODO: remove this huge staff */
	long unsigned int sgl_bitmap;
	unsigned long double_sgls[MAX_CMDS_PER_LUN];
	dma_addr_t sgl_addrs[MAX_CMDS_PER_LUN];
	unsigned long big_sgls[MAX_CMDS_PER_LUN];
	dma_addr_t big_sgl_addrs[MAX_CMDS_PER_LUN];
	int big_sgl_order[MAX_CMDS_PER_LUN];
	u16 sgl_size;
	spinlock_t sgl_lock;

	volatile u32 nest;
	struct list_head submit_list;
	spinlock_t submit_list_lock;
	u32 iter_cpu;

	volatile u64 send_io;

#ifdef EBLAZE_TFD_INTERFACE
	struct tfd_mtd tfd_mtd;
#endif
};

struct eblaze_cmpl_info {
	uint32_t indicators;
	uint16_t status;
	uint16_t nr_ecc;
};

struct eblaze_comm_dev {
	struct list_head cmd_list;	/* ioctl cmd list */
	spinlock_t cmd_list_lock;	/* protecting cmd_list */
	u32 instruction_index;
	u8 *read_reg;
	u8 *write_reg;
};

struct eblaze_device {
	char name[16];
	struct pci_dev *pdev;
	uint8_t *reg_base;
	uint32_t write_size;
	uint32_t erase_size;
	uint32_t oob_size;
	int32_t max_length;		/* max length of a single request */
	int32_t sg_tablesize;		/* max_nr_segments */
	int32_t max_segment_size;
	int probe_idx;
	struct eblaze_lun *luns[NR_LUNS_PER_EDEV];
	struct eblaze_cmpl_info *cmpls;
	dma_addr_t cmpls_dma_addr;
	uint16_t cmpls_write_idx;
	uint16_t cmpls_read_idx;
	spinlock_t cmpls_lock;
	int block_major;
	struct proc_dir_entry *proc_dir;

	volatile uint32_t intr_stat;	/* Interrupt status of cpu devs */
	volatile uint32_t intr_mask;	/* Interupt mask (0 or 0xffffffff) */
	volatile bool is_unload;	/* TODO: remove it */
	uint32_t status;		/* init, ready, run */
	uint32_t is_baecon_On;
	wait_queue_head_t stat_wq;
	struct work_struct stat_work;
	struct eblaze_comm_dev comm_dev;
	struct tasklet_struct comm_tasklet;
	struct tfd_bbm bbms[NR_TETRIS];

	uint32_t pcie_link_width;
	uint32_t pcie_link_gen;
	struct rom_info rom;
	struct semaphore ioctl_sem;

	volatile u64 send_io;
	volatile u64 submit_io;
	volatile u64 pending_io;
	volatile u64 recv_io;
	volatile u64 cmpl_io;
	volatile u64 wait_io;

#ifdef EBLAZE_BLK_INTERFACE
	struct gendisk *disk;
	struct request_queue *queue;
#endif

#ifdef EBLAZE_TFD_INTERFACE
	struct host_info hostinfo;
#endif
};

struct char_edev_map {
	int char_minor;
	struct eblaze_device *edev;
};

struct eblaze_fpga_counter {
	uint32_t addr;
	uint8_t flag;
	const char *name;
};

struct eblaze_ioctl_request {
	/* record the right pending number for different ioctl cmd */
	u32 major_cmd;
	u32 len;
	bool is_write;

	volatile u32 pending_dev;
	int request_status;
	struct completion ioctl_comp;
};

struct eblaze_msg {
	/* Link into the pblaze_comm_dev->cmd_list */
	struct list_head node;
	struct eblaze_ioctl_request *ioctl_req;
	u16 *data;
};

enum {
	ST_STAGE_INIT,
	ST_STAGE_READY,
	ST_STAGE_RUN,
	ST_STAGE_MID = 10,	/* The middle stage between ready and run */
	ST_STAGE_STOP,		/* Some core status are not run */
	ST_STAGE_COUNT
};

struct eblaze_print_info {
	u16 infolen;
	u16 paramlen;
	u16 strlen;
	u32 value[16 + 256 / sizeof(u32)];
};

struct firmware_data {
	u32 magic;
	u32 model;
	u32 version;
	u32 length;
	u32 crc;
	u8 data[1];
};

struct ioctl_rw_io {
	bool is_write;
	uint32_t start_page;
	uint16_t nr_pages;
	uint16_t nr_sg;
	struct eblaze_lun *lun;

	unsigned long data[16];
	int order[16];
	int pages[16];
	struct scatterlist sgbuf[16];
	unsigned long oob_data;
	struct scatterlist oobbuf;
};

#define serial_add(i, v, r)    ((i) = ((i) + (v)) % (r))

static inline void disable_edev_irq(struct eblaze_device *edev)
{
	uint32_t v = readl(edev->reg_base + REG_IRQ_CTRL0);
	v &= ~1;
	writel(v, edev->reg_base + REG_IRQ_CTRL0);
	readl(edev->reg_base + REG_IRQ_CTRL0);
	readl(edev->reg_base + REG_IRQ_CTRL0);
	edev->intr_mask = 0x0;
}

static inline void enable_edev_irq(struct eblaze_device *edev)
{
	uint32_t v = readl(edev->reg_base + REG_IRQ_CTRL0);
	edev->intr_mask = 0xffffffff;
	v |= 1;
	writel(v, edev->reg_base + REG_IRQ_CTRL0);
}

/* From gcc version 4.1.2, __sync_* functions supported */
#define eb_atomic_cmpxchg		__sync_val_compare_and_swap
#define eb_atomic_cmpxchg16		__sync_val_compare_and_swap
#define eb_atomic_add			__sync_fetch_and_add
#define eb_atomic_add16			__sync_fetch_and_add
#define eb_atomic_sub			__sync_fetch_and_sub
#define eb_atomic_sub16			__sync_fetch_and_sub

#define eb_atomic_add_and_fetch		__sync_add_and_fetch
#define eb_atomic_add_and_fetch16	__sync_add_and_fetch
#define eb_atomic_sub_and_fetch		__sync_sub_and_fetch
#define eb_atomic_sub_and_fetch16	__sync_sub_and_fetch

#define eb_atomic_or			__sync_fetch_and_or
#define eb_atomic_or16			__sync_fetch_and_or
#define eb_atomic_and			__sync_fetch_and_and
#define eb_atomic_and16			__sync_fetch_and_and
#define eb_atomic_xchg			__sync_lock_test_and_set

/* set the appointed bit to 1, and return the old bit value */
static inline int eb_atomic_test_and_set_bit(volatile unsigned long *pv, int pos)
{
	unsigned long new, old;
	new = 1u << pos;
	old = eb_atomic_or(pv, new);
	old = (old >> pos) & 1;
	return old;
}

/* clear the appointed bit to 0, and return the old bit value */
static inline int eb_atomic_test_and_clear_bit(volatile unsigned long *pv, int pos)
{
	unsigned long new, old;
	new = ~(1u << pos);
	old = eb_atomic_and(pv, new);
	old = (old >> pos) & 1;
	return old;
}

#define eb_atomic_inc(a)		eb_atomic_add_and_fetch(a, 1u)
#define eb_atomic_inc16(a)		eb_atomic_add_and_fetch16(a, 1u)
#define eb_atomic_dec(a)		eb_atomic_sub_and_fetch(a, 1u)
#define eb_atomic_dec16(a)		eb_atomic_sub_and_fetch16(a, 1u)

static inline uint32_t extr_sl_addr(uint32_t addr)
{
	return (addr >> LUN_SHIFT) & LUN_MASK_IN_TETRIS;
}

static inline uint32_t extr_block_addr(uint32_t addr)
{
	return (addr >> BLOCK_SHIFT) & BLOCK_MASK_IN_LUN;
}

static inline uint32_t comb_addr(uint32_t tetrisid, uint32_t sl, uint32_t block, uint32_t ps)
{
	return (tetrisid << TETRIS_SHIFT) | (sl << LUN_SHIFT) | (block << BLOCK_SHIFT) | ps;
}

int edev_init_pci(struct eblaze_device *edev, struct pci_dev *pdev);
void edev_remove_pci(struct eblaze_device *edev, struct pci_dev *pdev);
int create_edev_chrdev(struct eblaze_device *edev);
void destroy_edev_chrdev(struct eblaze_device *edev);
struct eblaze_lun *create_edev_lun(struct eblaze_device *edev, int idx);
void destroy_edev_lun(struct eblaze_device *edev, int idx);
int init_edev_luns(struct eblaze_device *edev);
void destroy_edev_luns(struct eblaze_device *edev);
irqreturn_t eblaze_irq_handler(int irq, void *dev_id);
int eblaze_create_proc(struct eblaze_device *edev);
void eblaze_remove_proc(struct eblaze_device *edev);
long eblaze_wait_status(struct eblaze_device *edev, u32 stat, long timeout);
void eblaze_init_comm_context(struct eblaze_device *edev);
void eblaze_beacon(struct eblaze_device *edev, bool is_baecon_On);
int eblaze_send_fw(struct eblaze_device *edev, u32 size, char *data);
void eblaze_get_rom_info(struct eblaze_device *edev);
void eblaze_get_dyn_info(struct eblaze_device *edev, struct dyn_info *d_info);
struct eblaze_cmd *eb_alloc_cmd(struct eblaze_lun *lun);
bool eb_insert_cmd(struct eblaze_cmd *cmd, struct eblaze_lun *lun);
void eb_schedule_submit_work(struct eblaze_lun *lun);

#endif
