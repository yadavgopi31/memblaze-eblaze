#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <ncurses.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>

#include "eblaze-ioctl.h"

#define SCALE1000
#define MAX_TEXT_LENGTH		30
#define TEXT_COUNT		16

char text_array[TEXT_COUNT][MAX_TEXT_LENGTH];
int text_index = 0;
struct user_rom_info user_rom;

const char *find_value_base_on_key(const char *rom, const char *key)
{
	bool is_nulll = true;
	char c_rom, c_key;
	const char *rom_start = rom;
	bool is_key = true;

	while (true) {
		if ((c_rom = *rom++) == '\0') {
			if (is_nulll) {
				return --rom;
			}

			if (is_key && strcmp(rom_start, key) == 0) {
				return rom;
			}

			is_key = !is_key;
			is_nulll = true;
			rom_start = rom;
		} else {
			is_nulll = false;
		}
	}
}

const char *format_size(long long size)
{
	char *size_str;
	const char *unit_str = "";
	float local_size = (float)size;

#ifdef SCALE1000
	if (local_size >= 1000.0F) {
		local_size /= 1000.0F;
		unit_str = "k";
	}

	if (local_size >= 1000.0F) {
		local_size /= 1000.0F;
		unit_str = "M";
	}

	if (local_size >= 1000.0F) {
		local_size /= 1000.0F;
		unit_str = "G";
	}

	if (local_size >= 1000.0F) {
		local_size /= 1000.0F;
		unit_str = "T";
	}

	if (local_size >= 1000.0F) {
		local_size /= 1000.0F;
		unit_str = "P";
	}
#else
	if (local_size >= 1024.0F) {
		local_size /= 1024.0F;
		unit_str = "k";
	}

	if (local_size >= 1024.0F) {
		local_size /= 1024.0F;
		unit_str = "M";
	}

	if (local_size >= 1024.0F) {
		local_size /= 1024.0F;
		unit_str = "G";
	}

	if (local_size >= 1024.0F) {
		local_size /= 1024.0F;
		unit_str = "T";
	}

	if (local_size >= 1024.0F) {
		local_size /= 1024.0F;
		unit_str = "P";
	}
#endif

	size_str = text_array[(++text_index) & (TEXT_COUNT - 1)];
	snprintf(size_str, MAX_TEXT_LENGTH, "%0.2f%sB", local_size, unit_str);

	return size_str;
}

float get_board_temperature(u16 ad)
{
	return (int16_t)(ad << 3) / 128.0F;
}

float get_temperature(u16 ad)
{
	return (ad >> 4) * (503.975F / 4096) - 273.15F;
}

void help()
{
	printf("NAME\n");
	printf("\tebctl - eblaze control manage tool\n");
	printf("\n");
	printf("DESCRIPTION\n");
	printf("\t-d, --dev\n");
	printf("\t\tdevice name such as /dev/memcona\n");
	printf("\t-f, --firmware\n");
	printf("\t\tthe path of firmware to update such as xx/fw.bin\n");
	printf("\t-m, --monitore\n");
	printf("\t\tprint the card infomation with plain text only once\n");
	printf("\t-b, --userdef\n");
	printf("\t\tprint the user define infomation in kernel space, check it by using dmesg\n");

}

int update_firmware(const char *firmware_name, const char *dev_name)
{
	struct firmware_name ffn;
	char cmd[MAX_STR_LEN];
	int fd;
	char keyword;

	if (strncmp(dev_name, "/dev/memcon", strlen("/dev/memcon")) != 0) {
		fprintf(stderr, "wrong device_name:%s\n", dev_name);
		return -EINVAL;
	}

	fd = open(dev_name, O_RDWR | O_LARGEFILE);
	if (fd < 0) {
		if (errno == 13)
			printf("Please use root account to use this tool\n");

		printf("Error open device %s\n", dev_name);
		return -1;
	}

	printf("Update firmwre for %s with file %s. y to continue ... ", dev_name, firmware_name);
	keyword = getchar();
	if (keyword != 'y' && keyword != 'Y') {
		printf("Update firmwre aborted, program exit!\n");
		close(fd);
		return -1;
	}

	printf("Begin update firmware\n");
	snprintf(cmd, MAX_STR_LEN, "cp -f %s /lib/firmware/eblaze.fw", firmware_name);
	if (system(cmd) != 0) {
		printf("Cannot copy firmware file to /lib/firmware/eblaze.fw\n");
		return -1;
	}

	strncpy(ffn.name, "eblaze.fw", MAX_STR_LEN);
	if (ioctl(fd, MEMCON_UPDATEFIRMWARE, &ffn) < 0) {
		printf("Error in device ioctl\n");
		printf("Check if %s is mounted(Used by filesystem), beening read/written or used by other program\n", dev_name);
		return -1;
	}

	close(fd);
	printf("Update firmware done. Please turn off the computer and restart it to let new firmware work.\n");
	return 0;
}

int monitor(const char *dev_name)
{
	int fd;
	long long capacity_max;
	const char *user_rom_pointer;
	struct user_dyn_info dyn_info;

	fd = open(dev_name, O_RDONLY);
	if (fd < 0) {
		switch (errno) {
		case EACCES:
			printf("Permission Denied while opening %s, root account is required\n", dev_name);
			break;

		case ENOENT:
		case EIO:
			printf("open %s failed\n", dev_name);
			break;
		}

		return -1;
	}

	if (ioctl(fd, IOCTL_INITIALQUERYSTAT, &user_rom) < 0) {
		close(fd);
		return -1;
	}

	if (ioctl(fd, MEMCON_GET_DYN_INFO, &dyn_info) < 0) {
		close(fd);
		return -1;
	}

	user_rom_pointer = user_rom.rom;
	capacity_max = (long long)dyn_info.capacity_max;
	printf("Model=%s\n", find_value_base_on_key(user_rom.rom, "Model:"));
	printf("SerialNumber=%s\n", find_value_base_on_key(user_rom.rom, "Serial Number:"));
	printf("DriverVersion=%s\n", user_rom.driver_version);
	printf("FirmwareVersion=%s\n", find_value_base_on_key(user_rom.rom, "Firmware Version:"));
	printf("PCIeLink=%d(v%d)\n", dyn_info.link_width, dyn_info.link_gen);
	printf("BoardTemperature=%0.1fC\n", get_board_temperature(dyn_info.board_temperature));
	printf("CoreTemperature=%0.1fC\n", get_temperature(dyn_info.temperature));
	close(fd);
}

int do_user_def(const char *dev_name)
{
	int fd;

	fd = open(dev_name, O_RDONLY);
	if (fd < 0) {
		switch (errno) {
		case EACCES:
			printf("Permission Denied while opening %s, root account is required\n", dev_name);
			break;

		case ENOENT:
		case EIO:
			printf("open %s failed\n", dev_name);
			break;
		}

		return -1;
	}

	if (ioctl(fd, MEMCON_USER_DEF) < 0) {
		close(fd);
		return -1;
	}

	printf("Please use dmesg command to see the info\n");
	close(fd);
	return 0;
}

static struct option const long_options[] = {
	{"dev", 1, NULL, 'd'},
	{"firmware", 1, NULL, 'f'},
	{"monitor", 0, NULL, 'm'},
	{"userdef", 0, NULL, 'b'},
	{"help", 0, NULL, 'h'},
	{0, 0, 0, 0},
};

int main(int argc, char **argv)
{
	int c;
	int longindex;
	char dev_name[MAX_STR_LEN] = {0};
	char firmware_name[MAX_STR_LEN] = {0};
	bool do_update_fw = false;
	bool do_monitor = false;
	bool do_show_badblock = false;
	int op_counter = 0;

	while (1) {
		c = getopt_long(argc, argv, "d:f:mbh", long_options, &longindex);
		if (c < 0) {
			break;
		}

		switch (c) {
		case 'd':
			strncpy(dev_name, optarg, MAX_STR_LEN - 1);
			break;

		case 'f':
			do_update_fw = true;
			op_counter++;
			strncpy(firmware_name, optarg, MAX_STR_LEN - 1);
			break;

		case 'm':
			do_monitor = true;
			op_counter++;
			break;

		case 'b':
			do_show_badblock = true;
			op_counter++;
			break;

		case 'h':
			help();
			return 0;

		default:
			help();
			return -1;
		}
	}

	/* case such as "xxx -" should not pass */
	if (argc != optind || dev_name[0] == 0 || op_counter != 1) {
		return -1;
	}

	if (do_update_fw) {
		return update_firmware(firmware_name, dev_name);
	}

	if (do_monitor) {
		return monitor(dev_name);
	}

	if (do_show_badblock)
		return do_user_def(dev_name);
}
