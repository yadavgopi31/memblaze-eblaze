#ifndef __EBLAZE_IOCTL_H__
#define __EBLAZE_IOCTL_H__

#define MAX_STR_LEN		1024
#define IOCTL_RW_SLICE		64
#define IOCTL_BADBLOCK_RET	100
#define ROM_SIZE		4096
#define DRVVER_SIZE		64

struct idx_addr {
	int idx;
	union {
		unsigned long bus;
		void *user;
	} addr;
};

struct idx_2addrs {
	int idx;
	void *user;
	unsigned long bus;
};

struct reginfo {
	unsigned reg_addr;
	int is64bits;
	union {
		int32_t v32;
		int64_t v64;
	} value;
};

struct user_erase_info{
        int lun_id;
        unsigned start_block;
        unsigned nr_blocks;
};

struct firmware_name {
	char name[MAX_STR_LEN];
};

struct user_rw_info {
	int lun_id;
	unsigned int start_page;
	unsigned int nr_pages;	/* if nr_pages == 0, no ibd*/
	unsigned int obd_len;	/* if obd_len == 0, no obd */
	int type;
	bool need_copy;

	void __user *ibd_addr;
	void __user *obd_addr;
};

struct user_bbm_info {
	int lun_id;
	int block_id;
	int op;		/* 0 for check, 1 for mark */
};

struct rom_info {
	char rom[ROM_SIZE];
	char driver_version[DRVVER_SIZE];
};

struct dyn_info {
	u64 capacity_max;
	u32 link_width;
	u32 link_gen;

	u16 temperature;
	u16 temperature_max;
	u16 temperature_min;
	u16 temperature_unsafe;
	u16 board_temperature;
};

#define IOCTL_MAGIC		162

#define MEMCON_BAECON			_IOW(IOCTL_MAGIC, 3, u32)
#define MEMCON_UPDATEFIRMWARE	_IOW(IOCTL_MAGIC, 7, struct firmware_name)
#define MEMCON_USER_ERASE       _IOWR(IOCTL_MAGIC, 8, struct user_erase_info)
#define MEMCON_USER_RW		_IOWR(IOCTL_MAGIC, 9, struct user_rw_info)

/* Block 0 is reserved */
#define MEMCON_TFD_BBM		_IOWR(IOCTL_MAGIC, 10, struct user_bbm_info)
#define MEMCON_TFD_RW		_IOWR(IOCTL_MAGIC, 11, struct user_rw_info)

#define MEMCON_GET_ROM_INFO	_IOR(IOCTL_MAGIC, 12, struct rom_info)
#define MEMCON_GET_DYN_INFO	_IOR(IOCTL_MAGIC, 13, struct dyn_info)
#define MEMCON_USER_DEF		_IO(IOCTL_MAGIC, 14)

/* Error injection */
#define MEMCON_ERR_INJECT_META_READ_EIO		_IOW(IOCTL_MAGIC, 20, u32)
#define MEMCON_ERR_INJECT_META_READ_NOT_EIO	_IOW(IOCTL_MAGIC, 21, u32)
#define MEMCON_ERR_INJECT_DATA_READ_EIO		_IOW(IOCTL_MAGIC, 22, u32)
#define MEMCON_ERR_INJECT_DATA_READ_NOT_EIO	_IOW(IOCTL_MAGIC, 23, u32)
#define MEMCON_ERR_INJECT_WRITE			_IOW(IOCTL_MAGIC, 24, u32)
#define MEMCON_ERR_INJECT_ERASE			_IOW(IOCTL_MAGIC, 25, u32)

#define MEMCON_ERR_INJECT_TIMEOUT_READ		_IOW(IOCTL_MAGIC, 26, u32)
#define MEMCON_ERR_INJECT_TIMEOUT_WRITE		_IOW(IOCTL_MAGIC, 27, u32)
#define MEMCON_ERR_INJECT_TIMEOUT_ERASE		_IOW(IOCTL_MAGIC, 28, u32)
#define MEMCON_ERR_INJECT_TIMEOUT_READ_OOB	_IOW(IOCTL_MAGIC, 29, u32)
#define MEMCON_ERR_INJECT_TIMEOUT_WRITE_OOB	_IOW(IOCTL_MAGIC, 30, u32)
#define MEMCON_ERR_INJECT_TIMEOUT_CHK_BADBLOCK	_IOW(IOCTL_MAGIC, 31, u32)
#define MEMCON_ERR_INJECT_TIMEOUT_MARK_BADBLOCK	_IOW(IOCTL_MAGIC, 32, u32)

#endif
