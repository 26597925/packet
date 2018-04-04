#include "unpifi.h"

#define TYPE_SCAN 0x0040U

#define OPT_NONE 0x0000U
#define OPT_TIMESLOT 0x00001U
#define OPT_EXCLUSIVE 0x00002U
#define OPT_INTERFACE 0x00004U
#define OPT_SNIFFER 0x00008U
#define OPT_ONE_END 0x00010U
#define OPT_ANOTHER_END 0x00020U
#define OPT_MATCH 0x00040U
#define OPT_NUMBER 0x00080U
#define OPT_HOSTS 0x00100U
#define NUMBER_OF_OPT 9/*选项个数*/

#define HOSTS_NUMBER 50	

struct ipmac{
	struct in_addr ipaddr;
	char haddr[IFI_HADDR];
	struct ipmac *next;
};










