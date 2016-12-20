
#ifndef _KEYMNG_DBOP_H_
#define _KEYMNG_DBOP_H_

#include "keymngserverop.h"
#include "keymng_shmop.h"

#ifdef __cplusplus
extern "C" {
#endif

// 获取数据库中密钥编号(密钥序列号)
int KeyMngsvr_DBOp_GenKeyID(void *dbhdl, int *keyid);

// 写密钥网点信息 到数据库中
int KeyMngsvr_DBOp_WriteSecKey(void *dbhdl, NodeSHMInfo *pNodeInfo); 

#ifdef __cplusplus
}
#endif
#endif



