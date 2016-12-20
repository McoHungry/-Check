#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "keymnglog.h"
#include "keymngserverop.h"
#include "poolsocket.h"
#include "keymng_msg.h"
#include "myipc_shm.h"
#include "keymng_shmop.h"
#include "icdbapi.h"
#include "keymng_dbop.h"

int MngServer_InitInfo(MngServer_Info *svrInfo)
{
	int ret = 0;

	strcpy(svrInfo->serverId, "0001");
	strcpy(svrInfo->dbuse, "SECMNG");
	strcpy(svrInfo->dbpasswd, "SECMNG");
	strcpy(svrInfo->dbsid, "orcl");	// 数据库名
	svrInfo->dbpoolnum = 20;
	
	strcpy(svrInfo->serverip, "127.0.0.1");
	svrInfo->serverport = 8001;
	svrInfo->maxnode = 10; //服务器支持的最大网点个数
 	svrInfo->shmkey = 0x0001;
	svrInfo->shmhdl = 0;
		
	//初始化共享内存
	ret = KeyMng_ShmInit(svrInfo->shmkey, svrInfo->maxnode, &svrInfo->shmhdl);
	if (ret != 0)
	{
		printf("func KeyMng_ShmInit() err:%d 初始化共享内存失败\n", ret);
	}

	/*功能描述：	数据库连接池初始化*/
	ret = IC_DBApi_PoolInit(svrInfo->dbpoolnum, svrInfo->dbsid, svrInfo->dbuse, svrInfo->dbpasswd);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"数据库连接池初始化 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"数据库连接池初始化完成\n");
	
	printf("服务器端初始化信息完成\n");
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"服务器端初始化信息完成\n");
	
	return ret;
}

int MngServer_Agree(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int ret = 0, i = 0;
	ICDBHandle handle = NULL;
	int outTime = 3;
	int nsOutTime = 3;
	int keyid = 0;
	
	// 参数判断
	if (NULL == svrInfo || NULL == msgkeyReq || NULL == outData || NULL == datalen)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], -1,"穿入参数错误\n");
		return -1;
	}

	/*功能描述：	从连接池获取数据库连接*/
	ret = IC_DBApi_ConnGet(&handle, outTime, nsOutTime);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"从连接池获取数据库连接 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"从连接池获取数据库连接完成\n");

	/*功能描述：    数据库事务开始  */
	ret = IC_DBApi_BeginTran(handle);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret," 数据库事务开始 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2," 数据库事务开始完成\n");

	// 获取数据库中密钥编号(密钥序列号)
	ret = KeyMngsvr_DBOp_GenKeyID(handle, &keyid);
	if (ret != 0)
	{
		IC_DBApi_Rollback (handle);
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"获取数据库中密钥编号 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"获取数据库中密钥编号完成\n");

	// 组织应答报文
	MsgKey_Res msgKeyRes;
	memset(&msgKeyRes, 0, sizeof(MsgKey_Res));
	for (i = 0; i < 64; ++i)
	{
		msgKeyRes.r2[i] = 'a' + i;
	}
	strcpy(msgKeyRes.clientId, msgkeyReq->clientId);
	strcpy(msgKeyRes.serverId, msgkeyReq->serverId);
	msgKeyRes.seckeyid = keyid;
	msgKeyRes.rv = 0;	// 0表示成功

	if (strcmp(svrInfo->serverId, msgkeyReq->serverId) != 0)
	{
		msgKeyRes.rv = 1;
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], msgKeyRes.rv,"传入信息不匹配\n");
		//msgKeyRes.rv=10;
	}

	// 编码应答报文
	ret = MsgEncode((void *)&msgKeyRes, ID_MsgKey_Res, outData, datalen);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"编码应答报文 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"编码应答报文完成\n");

	// 组织网点秘钥信息
	NodeSHMInfo nodeShmInfo;
	memset(&nodeShmInfo, 0, sizeof(NodeSHMInfo));
	nodeShmInfo.status = 0;
	strcpy(nodeShmInfo.clientId, msgkeyReq->clientId);
	strcpy(nodeShmInfo.serverId, msgkeyReq->serverId);
	nodeShmInfo.seckeyid = keyid;
	// 协商密钥
	for (i = 0; i < 64; ++i)
	{
		nodeShmInfo.seckey[2 * i] = msgkeyReq->r1[i];
		nodeShmInfo.seckey[2 * i + 1] = msgKeyRes.r2[i];
	}

	// 写共享内存
	ret = KeyMng_ShmWrite(svrInfo->shmhdl, svrInfo->maxnode, &nodeShmInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"写共享内存 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"写共享内存完成\n");

	// 写密钥网点信息 到数据库中
	ret = KeyMngsvr_DBOp_WriteSecKey(handle, &nodeShmInfo);
	if (ret != 0)
	{
		IC_DBApi_Rollback (handle);
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"写密钥网点信息 到数据库中err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"写密钥网点信息 到数据库中完成\n"); 

	/*功能描述：	数据库事务提交*/
	ret = IC_DBApi_Commit(handle);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"数据库事务提交err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"数据库事务提交完成\n"); 
	
	if (ret == IC_DB_CONNECT_ERR)
	{
		IC_DBApi_ConnFree(handle, 0);// 需要修复
	}
	else
	{
		IC_DBApi_ConnFree(handle, 1);
	}

	return ret;
}

// 秘钥校验
int MngServer_Check(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int ret = 0;
	NodeSHMInfo pNodeInfo;
	memset(&pNodeInfo, 0, sizeof(NodeSHMInfo));

	MsgKey_Res pMsgKeyRes;
	memset(&pMsgKeyRes, 0, sizeof(pMsgKeyRes));

	if (svrInfo == NULL ||  msgkeyReq == NULL || outData == NULL || datalen == NULL)
	{
		ret = MngSvr_ParamErr;
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MngServer_Agree() err, (svrInfo==NULL || msgkeyReq==NULL || outData==NULL || datalen==NULL)");
		return ret;
	}

	//4. 读共享内存， 取出密钥网点信息。   -- r2[8]
	ret = KeyMng_ShmRead(svrInfo->shmhdl, msgkeyReq->clientId, msgkeyReq->serverId, svrInfo->maxnode, &pNodeInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func KeyMng_ShmWrite err：%d\n", ret);
		return ret;
	}

	//5. 比对 MsgKey_Res.rv  存储比对结果
	if (strncmp(msgkeyReq->r1, (const char *)pNodeInfo.seckey, 8) == 0)
	{
		pMsgKeyRes.rv = 0;
		printf("server MngServer_Check scuess\n");
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"server MngServer_Check scuess\n");
	}
	else
	{
		pMsgKeyRes.rv = 102;
		printf("server MngServer_Check failed\n");
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"server MngServer_Check failed\n");
	}

	//7. 组织应答报文
	strcpy(pMsgKeyRes.clientId, msgkeyReq->clientId);
	strcpy(pMsgKeyRes.serverId, msgkeyReq->serverId);
	pMsgKeyRes.seckeyid = pNodeInfo.seckeyid;
	memcpy(pMsgKeyRes.r2, "hello",5);

	//8. 编码应答报文
	ret = MsgEncode((void *)&pMsgKeyRes, ID_MsgKey_Res, outData, datalen);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MsgEncode err：%d\n", ret);
		return ret;
	}

	return ret;
}

//密钥注销
int MngServer_Revoke(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int ret = 0;
    ICDBHandle handle = NULL;
    if(svrInfo==NULL || msgkeyReq == NULL ||
            outData == NULL || datalen == NULL)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"参数出错:%d",ret);
        return ret;
    }

    NodeSHMInfo nodeInfo;
    memset (&nodeInfo,0,sizeof(NodeSHMInfo));
    ret = KeyMng_ShmRead (svrInfo->shmhdl,msgkeyReq->clientId,msgkeyReq->serverId,svrInfo->maxnode,&nodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"读取共享内存失败:%d",ret);
        return ret;
    }

    //组织应答报文
    MsgKey_Res res;
    memset (&res,0,sizeof(res));
    strcpy(res.clientId,msgkeyReq->clientId);
    res.rv = 0; //0表示注销成功，否则失败
    res.seckeyid = nodeInfo.seckeyid;
    strcpy(res.serverId,msgkeyReq->serverId);
    if(strcmp(msgkeyReq->serverId,svrInfo->serverId)!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"数据有误:%d",ret);
        res.rv = 2;
    }

    //报文编码
    ret = MsgEncode ((void*)&res,ID_MsgKey_Res,outData,datalen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"报文编码出错:%d",ret);
        return ret;
    }

    //写入共享内存
    nodeInfo.status = 1;//1表示密钥已经注销
    ret = KeyMng_ShmWrite (svrInfo->shmhdl,svrInfo->maxnode,&nodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"写入共享内存失败:%d",ret);
        return ret;
    }

    //数据库获取连接
    ret = IC_DBApi_ConnGet ((void**)&handle,3,0);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"初始化数据库失败:%d",ret);
        return ret;
    }

    //写入数据库
    ret = KeyMngsvr_DBOp_UpdateKey (handle,&nodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"写入数据库失败:%d",ret);
        return ret;
    }
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],2,"写入数据库成功:%d");

	/*功能描述：	数据库事务提交*/
	ret = IC_DBApi_Commit(handle);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"数据库事务提交err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"数据库事务提交完成\n"); 
	
	if (ret == IC_DB_CONNECT_ERR)
	{
		IC_DBApi_ConnFree(handle, 0);// 需要修复
	}
	else
	{
		IC_DBApi_ConnFree(handle, 1);
	}

    return ret;
}