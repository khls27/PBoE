#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <linux/if_bridge.h>
#include <linux/sockios.h>

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#undef ETH_P_PBOE
#define ETH_P_PBOE 0x8866

#define SIOCDEVPRIVATE	0x89F0	/* private ioctl cmds: from 0x89f0 to 0x89FF */
#define PBOE_IOS_MODE_TYPE  (SIOCDEVPRIVATE + 1)
#define PBOE_IOS_BINDDEV    (SIOCDEVPRIVATE + 2)
#define PBOE_IOS_ADDPEER    (SIOCDEVPRIVATE + 3)
#define PBOE_IOS_SHOW       (SIOCDEVPRIVATE + 4)

#define MAX_DATA_LEN 1480
#define MIN_ETH_PKG_LEN 64

#define MAX_SESSION_NUM 1024

#define PBOE_DEV "pb0"
#define PBOE_VERSION "v0.0.125"

#ifndef SIOCBRADDBR
#define SIOCBRADDBR BRCTL_ADD_BRIDGE
#endif
#ifndef SIOCBRDELBR
#define SIOCBRDELBR BRCTL_DEL_BRIDGE
#endif
#ifndef SIOCBRADDIF
#define SIOCBRADDIF BRCTL_ADD_IF
#endif
#ifndef SIOCBRDELIF
#define SIOCBRDELIF BRCTL_DEL_IF
#endif


/* Maximum number of ports supported per bridge interface.  */
#ifndef MAX_PORTS
#define MAX_PORTS 32
#endif

#define PBOE_CFG_MODE_BIT           (1)
#define PBOE_CFG_BINDDEV_BIT        (1 << 1)        // bind a ether device
#define PBOE_CFG_BRIDGE_BIT         (1 << 2)        // add to bridge
#define PBOE_CFG_ADDPEER_BIT        (1 << 3)        // one peer at lest added

static unsigned char BOADCAST_MAC[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
enum PBOE_MODE_TYPE
{
    PBOE_MT_SINGLE = 0,         // single peer, default
    PBOE_MT_MULTI               // with multi peers
};

enum PBOE_FSM_STATE
{
    FSM_STE_IDEL        = 0,
    FSM_STE_S_DIS       = 1,
    FSM_STE_R_DIS       = 2,
    FSM_STE_S_OFFER     = 4,
    FSM_STE_R_OFFER     = 5,
    FSM_STE_S_RQST       = 7,
    FSM_STE_R_RQST       = 8,
    FSM_STE_R_ACK       = 9,
    FSM_STE_ESTABLISHED = 16,
    FSM_STE_MAINTAIN    = 17,
    FSM_STE_DIED        = 18,
};

enum PBOE_OPTION_CODE
{
    OPTCODE_PAD         = 0,
    OPTCODE_DIS         = 1,
    OPTCODE_OFFER       = 2,
    OPTCODE_RQST         = 3,
    OPTCODE_ACK         = 4,
    OPTCODE_NACK        = 5,
    OPTCODE_HEART_BEAT   = 6,
};

#pragma pack (1)
struct pboe_hdr {
    unsigned short sesid;
    unsigned short optcode;
    unsigned short optlen;
};

struct pboe_pkg {
    struct ethhdr ethhdr; /* Ethernet header */
    struct pboe_hdr pboehdr;
    unsigned char payload[MAX_DATA_LEN]; /* pad for min. Ethernet payload (50 bytes) */
};
#pragma pack ()

struct pboe_conn;

struct pboe_session {
    struct pboe_session *next;
    unsigned short sesid;
    unsigned char mac[ETH_ALEN];

    struct pboe_conn *conn;
    enum PBOE_FSM_STATE state;
};

struct pboe_conn {
    int sockfd;
    unsigned char ifname[IF_NAMESIZE];
    unsigned char ifmac[ETH_ALEN];
    unsigned char brname[IF_NAMESIZE];
    struct sockaddr_ll lladdr;

    enum PBOE_MODE_TYPE type;
    unsigned int sesNum;
    unsigned short sesidGen;
    struct pboe_session *pses;
    struct pboe_session **sesHhd;
};

static int connRcvPackage(struct pboe_conn *pconn);

static inline int isMacEqu(const unsigned char *mac1, const unsigned char *mac2)
{
    return (memcmp(mac1, mac2, ETH_ALEN) == 0);
}

static inline int doIoctl(int cmd, struct ifreq *pifr)
{
    int fd, rtn;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("ioctl create socket error");
        return -1;
    }
    rtn = ioctl(fd, cmd, pifr);
    if (rtn < 0)
    {
        perror("do ioctl error");
        close(fd);
        return rtn;
    }

    close(fd);
    return rtn;
}

int getIfMac(const char *dev, unsigned char *mac)
{
    struct ifreq req;
    int ret = 0;

    strcpy(req.ifr_name, dev);
    if ((ret = doIoctl(SIOCGIFHWADDR, &req)) < 0)
    {
        return ret;
    }
    memcpy(mac, req.ifr_hwaddr.sa_data, ETH_ALEN);
    return ret;
}

int getIfIndex(const char *dev)
{
    struct ifreq req;

    strcpy(req.ifr_name, dev);
    if (doIoctl(SIOCGIFINDEX, &req) < 0)
    {
        return -1;
    }
    return req.ifr_ifindex;
}

static inline void armIoctl(unsigned long *args, unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
    args[0] = arg0;
    args[1] = arg1;
    args[2] = arg2;
    args[3] = 0;
}

int setHwAddr(unsigned char *ifname, unsigned char *mac)
{
    struct ifreq ifr;

    if (!ifname || !mac)
    {
        return -1;
    }
    ifr.ifr_addr.sa_family = ARPHRD_ETHER;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    memcpy((unsigned char *)ifr.ifr_hwaddr.sa_data, mac, 6);

    if (doIoctl(SIOCSIFHWADDR, &ifr) < 0)
    {
        return -1;
    }
    return 0;
}

static int brAddDelIf(const unsigned char *brname, const unsigned char *devname, int add)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, brname, IF_NAMESIZE);
    ifr.ifr_ifindex = if_nametoindex(devname);
    if (doIoctl((add ? SIOCBRADDIF : SIOCBRDELIF), &ifr) != 0)
    {
        return -1;
    }
    return 0;
}

int ifUpDown(const char *ifname, const int up)
{
    struct ifreq ifr;

    if (!ifname)
    {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, (const char *)ifname, IFNAMSIZ - 1);

    if (doIoctl(SIOCGIFFLAGS, &ifr) != 0)
    {
        return -1;
    }

    if (up)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    if (doIoctl(SIOCSIFFLAGS, &ifr) != 0)
    {
        return -1;
    }

    return 0;
}
static int isBrPort(unsigned char *brname, unsigned char *devname)
{
    struct ifreq ifr;
    unsigned long args[4];
    struct __bridge_info bi;
    int ifidx[MAX_PORTS];
    unsigned char ifname[IF_NAMESIZE];
    int j;

    if (!strncmp(brname, devname, IF_NAMESIZE))
    {
        return 1;
    }

    strncpy(ifr.ifr_name, brname, IF_NAMESIZE);
    ifr.ifr_data = (char *)&args;
    armIoctl(args, BRCTL_GET_PORT_LIST, (unsigned long)ifidx, MAX_PORTS);
    if (doIoctl(SIOCDEVPRIVATE, &ifr) < 0)
    {
        return -1;
    }

    for (j = 0; j < MAX_PORTS; j++)
    {
        if (!ifidx[j])
            continue;

        memset(ifname, 0, IF_NAMESIZE);
        if (!if_indextoname(ifidx[j], ifname))
            perror("fail to get devname from index");
        else
        {
            if (!strncmp(devname, ifname, IF_NAMESIZE))
            {
                return 1;
            }
        }
    }
    return 0;
}

static int kpboeSetMode(unsigned char *pbdev, int type)
{
    struct ifreq ifr;
    int err;

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, pbdev, IFNAMSIZ);
    ifr.ifr_ifru.ifru_ivalue = type;
    if ( (err = doIoctl(PBOE_IOS_MODE_TYPE, &ifr)) < 0)
    {
        return err;
    }
    return 0;
}

static int kpboeBindDev(unsigned char *pbdev, unsigned char *edev)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, pbdev, IFNAMSIZ);
    strncpy(ifr.ifr_ifru.ifru_newname, edev, IFNAMSIZ);
    if (doIoctl(PBOE_IOS_BINDDEV, &ifr) < 0)
    {
        return -1;
    }
    return 0;
}

static int kpboeAddPeer(unsigned char *pbdev, unsigned char *peermac)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pbdev, IFNAMSIZ);
    memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, peermac, 6); 
    if (doIoctl(PBOE_IOS_ADDPEER, &ifr) < 0)
    {
        return -1;
    }
    return 0;
}


static int kpboeShow(unsigned char *pbdev)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pbdev, IFNAMSIZ);
    if (doIoctl(PBOE_IOS_SHOW, &ifr) < 0)
    {
        return -1;
    }
    return 0;
}

static int kpboeAdd2Bridge(unsigned char *pbdev, unsigned char *brname)
{
    unsigned char brmac[ETH_ALEN] = { 0 };
    int ret;

    if ((ret = getIfMac(brname, brmac)) != 0)
        return ret;

    if ((ret =  ifUpDown(pbdev, 0)) != 0)
        return ret;

    if ((ret = setHwAddr(pbdev, brmac)) != 0)
        return ret;

    if ((ret = ifUpDown(pbdev, 1)) != 0)
        return ret;

    if ((ret = brAddDelIf(brname, pbdev, 1)) != 0)
        return ret;

    return 0;
}

static void showUsage(char *app)
{
    printf("Usage: %s -imbh\n", app ? app : "pboecfg");
    printf("\t -i/--interface [ifname], device to bind on\n");
    printf("\t -s/--server, working as server mode\n");
    printf("\t -c/--client, working as client mode\n");
    printf("\t -b/--bridge [brname], bridge that pb0 will add into\n");
    printf("\t -a/--addpeer [peermac], add a peer by mac\n");
    printf("\t -S/--show, show the kernel status by printk\n");
    printf("\t -h/--help, show this usage\n");
}

struct option opts[] = {
    { "interface", required_argument, NULL, 'i' },
    { "bridge", required_argument, NULL, 'b' },
    { "addpeer", required_argument, NULL, 'a' },
    { "server", no_argument, NULL, 's' },
    { "client", no_argument, NULL, 'c' },
    { "show", no_argument, NULL, 'l' },
    { "help", no_argument, NULL, 'h' },
};

int main(int argc, char **argv)
{

    int opt = 0;
    char ifname[IF_NAMESIZE] = { 0 };
    int mode = 0;
    char brname[IF_NAMESIZE] = { 0 };
    unsigned char peermac[ETH_ALEN] = { 0 };
    unsigned short cfgBit = 0;
    int ret = 0;

    openlog("pboecfg", LOG_CONS | LOG_PID, LOG_USER);

    while ((opt = getopt_long(argc, argv, "i:b:a:sch", opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'h':
            showUsage(argv[0]);
            return 0;
        case 'i':
            strncpy(ifname, optarg, IF_NAMESIZE - 1);
            cfgBit |= PBOE_CFG_BINDDEV_BIT;
            break;
        case 's':
            mode = 1;
            cfgBit |= PBOE_CFG_MODE_BIT;
            break;
        case 'c':
            mode = 0;
            cfgBit |= PBOE_CFG_MODE_BIT;
            break;
        case 'b':
            strncpy(brname, optarg, IF_NAMESIZE - 1);
            cfgBit |= PBOE_CFG_BRIDGE_BIT;
            break;
        case 'a':
            {
                unsigned int u32Mac[ETH_ALEN] = { 0 };
                int i;

                sscanf(optarg, "%02x:%02x:%02x:%02x:%02x:%02x", &u32Mac[0], &u32Mac[1], &u32Mac[2], &u32Mac[3], &u32Mac[4], &u32Mac[5]);
                for (i = 0; i < ETH_ALEN; i++)
                {
                    peermac[i] = u32Mac[i] & 0xff;
                }
                cfgBit |= PBOE_CFG_ADDPEER_BIT;
                break;
            }
        case 'l':
            return kpboeShow(PBOE_DEV);

        default:
            syslog(LOG_ERR, "unknown option code:%c\n", opt);
            showUsage(argv[0]);
            return -1;
        }
    }

    if (!cfgBit)
    {
        syslog(LOG_ERR, "none option code");
        showUsage(argv[0]);
        return 1;
    }

    // first setup mode
    if (cfgBit & PBOE_CFG_MODE_BIT)
    {
        if ((ret = kpboeSetMode(PBOE_DEV, mode)) != 0)
        {
            syslog(LOG_ERR, "setup pboe kernel mode fail, see demsg for more information");
            return ret;
        }
    }

    // second setup ether device
    if (cfgBit & PBOE_CFG_BINDDEV_BIT)
    {
        if (ret = kpboeBindDev(PBOE_DEV, ifname))
        {
            syslog(LOG_ERR, "bind ether device:%s fail, see demsg for more information", ifname);
            return ret;
        }
    }

    // then setup bridge
    if (cfgBit & PBOE_CFG_BRIDGE_BIT)
    {
        if (!cfgBit & PBOE_CFG_BINDDEV_BIT)
        {
            // FIX-ME, check the bound device, get the ifname
            syslog(LOG_ERR, "get the bound information NOT implemented yet!");
            return -1;
        }
        if (isBrPort(brname, ifname))
        {
            syslog(LOG_ERR, "interface(%s) belong to the bridge(%s) is NOT allowed\n", ifname, brname);
            return -1;
        }
        kpboeAdd2Bridge(PBOE_DEV, brname);
    }

    // finally setup peer
    if (cfgBit & PBOE_CFG_ADDPEER_BIT)
    {
        if ((ret = kpboeAddPeer(PBOE_DEV, peermac)) != 0)
            return ret;
    }

    return 0;
}

