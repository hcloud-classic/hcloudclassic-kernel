#ifndef CCISS_CMD_H
#define CCISS_CMD_H
//###########################################################################
//DEFINES
//###########################################################################
#define CISS_VERSION "1.00"

//general boundary defintions
#define SENSEINFOBYTES          32//note that this value may vary between host implementations
#define MAXSGENTRIES            32
#define CCISS_SG_CHAIN		0x80000000
#define MAXREPLYQS              256

//Command Status value
#define CMD_SUCCESS             0x0000
#define CMD_TARGET_STATUS       0x0001
#define CMD_DATA_UNDERRUN       0x0002
#define CMD_DATA_OVERRUN        0x0003
#define CMD_INVALID             0x0004
#define CMD_PROTOCOL_ERR        0x0005
#define CMD_HARDWARE_ERR        0x0006
#define CMD_CONNECTION_LOST     0x0007
#define CMD_ABORTED             0x0008
#define CMD_ABORT_FAILED        0x0009
#define CMD_UNSOLICITED_ABORT   0x000A
#define CMD_TIMEOUT             0x000B
#define CMD_UNABORTABLE		0x000C

/* Unit Attentions ASC's as defined for the MSA2012sa */
#define POWER_OR_RESET			0x29
#define STATE_CHANGED			0x2a
#define UNIT_ATTENTION_CLEARED		0x2f
#define LUN_FAILED			0x3e
#define REPORT_LUNS_CHANGED		0x3f

/* Unit Attentions ASCQ's as defined for the MSA2012sa */

	/* These ASCQ's defined for ASC = POWER_OR_RESET */
#define POWER_ON_RESET			0x00
#define POWER_ON_REBOOT			0x01
#define SCSI_BUS_RESET			0x02
#define MSA_TARGET_RESET		0x03
#define CONTROLLER_FAILOVER		0x04
#define TRANSCEIVER_SE			0x05
#define TRANSCEIVER_LVD			0x06

	/* These ASCQ's defined for ASC = STATE_CHANGED */
#define RESERVATION_PREEMPTED		0x03
#define ASYM_ACCESS_CHANGED		0x06
#define LUN_CAPACITY_CHANGED		0x09

//transfer direction
#define XFER_NONE               0x00
#define XFER_WRITE              0x01
#define XFER_READ               0x02
#define XFER_RSVD               0x03

//task attribute
#define ATTR_UNTAGGED           0x00
#define ATTR_SIMPLE             0x04
#define ATTR_HEADOFQUEUE        0x05
#define ATTR_ORDERED            0x06
#define ATTR_ACA                0x07

//cdb type
#define TYPE_CMD				0x00
#define TYPE_MSG				0x01

//config space register offsets
#define CFG_VENDORID            0x00
#define CFG_DEVICEID            0x02
#define CFG_I2OBAR              0x10
#define CFG_MEM1BAR             0x14

//i2o space register offsets
#define I2O_IBDB_SET            0x20
#define I2O_IBDB_CLEAR          0x70
#define I2O_INT_STATUS          0x30
#define I2O_INT_MASK            0x34
#define I2O_IBPOST_Q            0x40
#define I2O_OBPOST_Q            0x44
#define I2O_DMA1_CFG		0x214

//Configuration Table
#define CFGTBL_ChangeReq        0x00000001l
#define CFGTBL_AccCmds          0x00000001l
#define DOORBELL_CTLR_RESET     0x00000004l
#define DOORBELL_CTLR_RESET2    0x00000020l

#define CFGTBL_Trans_Simple     0x00000002l
#define CFGTBL_Trans_Performant 0x00000004l
#define CFGTBL_Trans_use_short_tags 0x20000000l

#define CFGTBL_BusType_Ultra2   0x00000001l
#define CFGTBL_BusType_Ultra3   0x00000002l
#define CFGTBL_BusType_Fibre1G  0x00000100l
#define CFGTBL_BusType_Fibre2G  0x00000200l
typedef struct _vals32
{
        __u32   lower;
        __u32   upper;
} vals32;

typedef union _u64bit
{
   vals32	val32;
   __u64	val;
} u64bit;

// Type defs used in the following structs
#define BYTE __u8
#define WORD __u16
#define HWORD __u16
#define DWORD __u32
#define QWORD vals32 

//###########################################################################
//STRUCTURES
//###########################################################################
#define CISS_MAX_LUN	1024
#define CISS_MAX_PHYS_LUN	1024
// SCSI-3 Cmmands 

#pragma pack(1)	

#define CISS_INQUIRY 0x12
//Date returned
typedef struct _InquiryData_struct
{
  BYTE data_byte[36];
} InquiryData_struct;

#define CISS_REPORT_LOG 0xc2    /* Report Logical LUNs */
#define CISS_REPORT_PHYS 0xc3   /* Report Physical LUNs */
// Data returned
typedef struct _ReportLUNdata_struct
{
  BYTE LUNListLength[4];
  DWORD reserved;
  BYTE LUN[CISS_MAX_LUN][8];
} ReportLunData_struct;

#define CCISS_READ_CAPACITY 0x25 /* Read Capacity */ 
typedef struct _ReadCapdata_struct
{
  BYTE total_size[4];	// Total size in blocks
  BYTE block_size[4];	// Size of blocks in bytes
} ReadCapdata_struct;

#define CCISS_READ_CAPACITY_16 0x9e /* Read Capacity 16 */

/* service action to differentiate a 16 byte read capacity from
   other commands that use the 0x9e SCSI op code */

#define CCISS_READ_CAPACITY_16_SERVICE_ACT 0x10

typedef struct _ReadCapdata_struct_16
{
	BYTE total_size[8];   /* Total size in blocks */
	BYTE block_size[4];   /* Size of blocks in bytes */
	BYTE prot_en:1;       /* protection enable bit */
	BYTE rto_en:1;        /* reference tag own enable bit */
	BYTE reserved:6;      /* reserved bits */
	BYTE reserved2[18];   /* reserved bytes per spec */
} ReadCapdata_struct_16;

/* Define the supported read/write commands for cciss based controllers */

#define CCISS_READ_10   0x28    /* Read(10)  */
#define CCISS_WRITE_10  0x2a    /* Write(10) */
#define CCISS_READ_16   0x88    /* Read(16)  */
#define CCISS_WRITE_16  0x8a    /* Write(16) */

/* Define the CDB lengths supported by cciss based controllers */

#define CDB_LEN10	10
#define CDB_LEN16	16

// BMIC commands 
#define BMIC_READ 0x26
#define BMIC_WRITE 0x27
#define BMIC_CACHE_FLUSH 0xc2
#define CCISS_CACHE_FLUSH 0x01	//C2 was already being used by CCISS

#define CCISS_RESET_TYPE_CONTROLLER 0x00

//Command List Structure
typedef union _SCSI3Addr_struct {
   struct {
    BYTE Dev;
    BYTE Bus:6;
    BYTE Mode:2;        // b00
  } PeripDev;
   struct {
    BYTE DevLSB;
    BYTE DevMSB:6;
    BYTE Mode:2;        // b01
  } LogDev;
   struct {
    BYTE Dev:5;
    BYTE Bus:3;
    BYTE Targ:6;
    BYTE Mode:2;        // b10
  } LogUnit;
} SCSI3Addr_struct;

typedef struct _PhysDevAddr_struct {
  DWORD             TargetId:24;
  DWORD             Bus:6;
  DWORD             Mode:2;
  SCSI3Addr_struct  Target[2]; //2 level target device addr
} PhysDevAddr_struct;
  
typedef struct _LogDevAddr_struct {
  DWORD            VolId:30;
  DWORD            Mode:2;
  BYTE             reserved[4];
} LogDevAddr_struct;

typedef union _LUNAddr_struct {
  BYTE               LunAddrBytes[8];
  SCSI3Addr_struct   SCSI3Lun[4];
  PhysDevAddr_struct PhysDev;
  LogDevAddr_struct  LogDev;
} LUNAddr_struct;

#define CCISS_ABORT_MSG 0x00
#define CCISS_RESET_MSG 0x01
#define CCISS_RESET_TYPE_CONTROLLER 0x00
#define CCISS_RESET_TYPE_BUS 0x01
#define CCISS_RESET_TYPE_TARGET 0x03
#define CCISS_RESET_TYPE_LUN 0x04
#define CCISS_NOOP_MSG 0x03

/* Command List Structure */
#define CTLR_LUNID "\0\0\0\0\0\0\0\0"

typedef struct _CommandListHeader_struct {
  BYTE              ReplyQueue;
  BYTE              SGList;
  HWORD             SGTotal;
  QWORD             Tag;
  LUNAddr_struct    LUN;
} CommandListHeader_struct;
typedef struct _RequestBlock_struct {
  BYTE   CDBLen;
  struct {
    BYTE Type:3;
    BYTE Attribute:3;
    BYTE Direction:2;
  } Type;
  HWORD  Timeout;
  BYTE   CDB[16];
} RequestBlock_struct;
typedef struct _ErrDescriptor_struct {
  QWORD  Addr;
  DWORD  Len;
} ErrDescriptor_struct;
typedef struct _SGDescriptor_struct {
  QWORD  Addr;
  DWORD  Len;
  DWORD  Ext;
} SGDescriptor_struct;

typedef union _MoreErrInfo_struct{
  struct {
    BYTE  Reserved[3];
    BYTE  Type;
    DWORD ErrorInfo;
  }Common_Info;
  struct{
    BYTE  Reserved[2];
    BYTE  offense_size;//size of offending entry
    BYTE  offense_num; //byte # of offense 0-base
    DWORD offense_value;
  }Invalid_Cmd;
}MoreErrInfo_struct;
typedef struct _ErrorInfo_struct {
  BYTE               ScsiStatus;
  BYTE               SenseLen;
  HWORD              CommandStatus;
  DWORD              ResidualCnt;
  MoreErrInfo_struct MoreErrInfo;
  BYTE               SenseInfo[SENSEINFOBYTES];
} ErrorInfo_struct;

/* Command types */
#define CMD_RWREQ       0x00
#define CMD_IOCTL_PEND  0x01
#define CMD_SCSI	0x03
#define CMD_MSG_DONE	0x04
#define CMD_MSG_TIMEOUT 0x05
#define CMD_MSG_STALE	0xff

/* This structure needs to be divisible by COMMANDLIST_ALIGNMENT
 * because low bits of the address are used to to indicate that
 * whether the tag contains an index or an address.  PAD_32 and
 * PAD_64 can be adjusted independently as needed for 32-bit
 * and 64-bits systems.
 */
#define COMMANDLIST_ALIGNMENT (32)
#define IS_64_BIT ((sizeof(long) - 4)/4)
#define IS_32_BIT (!IS_64_BIT)
#define PAD_32 (0)
#define PAD_64 (4)
#define PADSIZE (IS_32_BIT * PAD_32 + IS_64_BIT * PAD_64)

typedef struct _CommandList_struct {
  CommandListHeader_struct Header;
  RequestBlock_struct      Request;
  ErrDescriptor_struct     ErrDesc;
  SGDescriptor_struct      SG[MAXSGENTRIES];
	/* information associated with the command */ 
  __u32			   busaddr; /* physical address of this record */
  ErrorInfo_struct * 	   err_info; /* pointer to the allocated mem */ 
  int			   ctlr;
  int			   cmd_type; 
  long			   cmdindex;
  struct list_head list;
  struct request *	   rq;
  struct completion *waiting;
  int	 retry_count;
  void * scsi_cmd;
  char   pad[PADSIZE];
} CommandList_struct;

//Configuration Table Structure
typedef struct _HostWrite_struct {
  DWORD TransportRequest;
  DWORD Reserved;
  DWORD CoalIntDelay;
  DWORD CoalIntCount;
} HostWrite_struct;

typedef struct _CfgTable_struct {
  BYTE			Signature[4];
  DWORD			SpecValence;
#define SIMPLE_MODE	0x02
#define PERFORMANT_MODE 0x04
#define MEMQ_MODE	0x08
  DWORD			TransportSupport;
  DWORD			TransportActive;
  HostWrite_struct	HostWrite;
  DWORD			CmdsOutMax;
  DWORD			BusTypes;
  DWORD			TransMethodOffset;
  BYTE 			ServerName[16];
  DWORD			HeartBeat;
  DWORD			SCSI_Prefetch;
  DWORD			MaxSGElements;
  DWORD			MaxLogicalUnits;
  DWORD			MaxPhysicalDrives;
  DWORD			MaxPhysicalDrivesPerLogicalUnit;
  DWORD			MaxPerformantModeCommands;
  u8			reserved[0x78 - 0x58];
  u32			misc_fw_support; /* offset 0x78 */
#define MISC_FW_DOORBELL_RESET (0x02)
#define MISC_FW_DOORBELL_RESET2 (0x10)
  u8		   driver_version[32];
} CfgTable_struct;

struct TransTable_struct {
  u32 BlockFetch0;
  u32 BlockFetch1;
  u32 BlockFetch2;
  u32 BlockFetch3;
  u32 BlockFetch4;
  u32 BlockFetch5;
  u32 BlockFetch6;
  u32 BlockFetch7;
  u32 RepQSize;
  u32 RepQCount;
  u32 RepQCtrAddrLow32;
  u32 RepQCtrAddrHigh32;
  u32 RepQAddr0Low32;
  u32 RepQAddr0High32;
};

#pragma pack()	 
#endif // CCISS_CMD_H