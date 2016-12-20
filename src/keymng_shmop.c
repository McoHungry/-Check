

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>


#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "keymnglog.h"
#include "keymng_shmop.h"
#include "myipc_shm.h"

//#include "keymngclientop.h"
//#include "poolsocket.h"


//先检测共享内存是否存在 
//1 若存在则使用旧的；
//2 若不存在，则创建
int KeyMng_ShmInit(int key, int maxnodenum, int *shmhdl)
{
	int  		ret = 0;
	void 		*mapaddr = NULL;
	//打开共享内存 若共享内存不存在，返回错误
	ret = IPC_OpenShm(key, maxnodenum*sizeof(NodeSHMInfo), shmhdl);
	if (ret == MYIPC_NotEXISTErr)
	{
		printf("secmng 打开共享内存 不存在, 创建新的共享内存\n");
		//创建共享内存 若共享内存不存在，则创建
		ret = IPC_CreatShm(key,  maxnodenum*sizeof(NodeSHMInfo), shmhdl);
		if (ret != 0)
		{
			printf("secmng 创建共享内存失败 \n");
			return ret ;
		}	
		else
		{
			printf("系统创建共享内存 ok \n");
			//创建共享内存成功
			ret = IPC_MapShm(*shmhdl, &mapaddr);
			if (ret != 0)
			{
				printf("func IPC_MapShm() err:%d\n", ret);
				return ret ;
			}	
			memset(mapaddr, 0, maxnodenum*sizeof(NodeSHMInfo));
			IPC_UnMapShm(mapaddr);
		}
		return ret;
	}
	else if (ret != 0)
	{
		printf("打开共享内存失败 func IPC_OpenShm() err:%d", ret);
		return 0;
	}

	return ret;	
}

//1 先判断网点信息是否已经存在, 
//若存在 则覆盖
//若不存在 则找一个空的位置 写入网点密钥 
int KeyMng_ShmWrite(int shmhdl, int maxnodenum, NodeSHMInfo *pNodeInfo)
{	
	int				ret = 0, i = 0;
	NodeSHMInfo  	tmpNodeInfo; //空结点
	NodeSHMInfo		*pNode = NULL;
	
	void 			*mapaddr = NULL;
	
	memset(&tmpNodeInfo, 0, sizeof(tmpNodeInfo));
	
	//链接共享内存
	ret = IPC_MapShm(shmhdl, &mapaddr);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func IPC_MapShm() err");
		goto End;
	}
	
	//遍历共享内存的网点信息 
	for (i=0; i<maxnodenum; i++)
	{
		pNode = mapaddr + i* sizeof(NodeSHMInfo);
		if ( strcmp(pNodeInfo->clientId, pNode->clientId ) == 0 &&
			 strcmp(pNodeInfo->serverId, pNode->serverId )== 0 )
		{
			KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], ret,"找到网点信息, 更网点密钥");
			memcpy(pNode, pNodeInfo, sizeof(NodeSHMInfo));
			goto End;		
		}
	}
	
	//若没有找到 应该找一个空的位置 写入网点信息
	for (i=0; i<maxnodenum; i++)
	{
		pNode = mapaddr + i* sizeof(NodeSHMInfo);
		if ( memcmp(pNode, &tmpNodeInfo, sizeof(NodeSHMInfo)) == 0 )
		{
			KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], ret,"找到空网点位置, 写入新网点密钥");
			memcpy(pNode, pNodeInfo, sizeof(NodeSHMInfo));
			goto End;
		}
	}
	
	if (i == maxnodenum)
	{
		ret = 200;
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"网点信息已满错误");
		goto End;
	}
	
End:
	IPC_UnMapShm(mapaddr);

	return ret;	
}

int KeyMng_ShmRead(int shmhdl, char *clientId, char *serverId,  int maxnodenum, NodeSHMInfo *pNodeInfo)
{
	
	int				ret = 0, i = 0;
	NodeSHMInfo  	tmpNodeInfo; //空结点
	NodeSHMInfo		*pNode = NULL;
	
	void 			*mapaddr = NULL;
	
	memset(&tmpNodeInfo, 0, sizeof(tmpNodeInfo));
	
	//链接共享内存
	ret = IPC_MapShm(shmhdl, &mapaddr);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func IPC_MapShm() err");
		goto End;
	}

	//遍历共享内存的网点信息 
	for (i=0; i<maxnodenum; i++)
	{
		pNode = mapaddr + i* sizeof(NodeSHMInfo);
		if ( strcmp(clientId, pNode->clientId ) == 0 &&
			 strcmp(serverId, pNode->serverId )== 0 )
		{
			KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], ret,"找到网点信息, 更网点密钥");
			memcpy(pNodeInfo, pNode, sizeof(NodeSHMInfo));
			goto End;
			
		}
	}
	
	if (i == maxnodenum)
	{
		ret = 200;
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"网点信息已满错误");
		goto End;
	}
	
End:
	IPC_UnMapShm(mapaddr);

	return ret;	
}

