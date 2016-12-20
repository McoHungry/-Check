#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "keymng_msg.h"
#include "myipc_shm.h"
#include "poolsocket.h"
#include "keymnglog.h"
#include "keymngclientop.h"
#include "keymng_shmop.h"  //网点密钥

//初始化客户端 全局变量
int MngClient_InitInfo(MngClient_Info *pCltInfo)
{
	int ret = 0;

	strcpy(pCltInfo->clientId, "1111");
	strcpy(pCltInfo->AuthCode, "1111");
	strcpy(pCltInfo->serverId, "0001");
	strcpy(pCltInfo->serverip, "127.0.0.1");
	pCltInfo->serverport = 8001;
	pCltInfo->maxnode = 30; 					//最大的网点个数
 	pCltInfo->shmkey = 0x1111;
	pCltInfo->shmhdl = 0;						//shmid
	
	ret = KeyMng_ShmInit(pCltInfo->shmkey, pCltInfo->maxnode, &pCltInfo->shmhdl);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"共享内存初始化失败，%d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"共享内存初始化完成\n");
	printf("共享内存初始化完成\n");

	return 0;
}

// 秘钥协商
int MngClient_Agree(MngClient_Info *pCltInfo)
{
	int ret = 0, i=0;
	unsigned char *outDataReq = NULL;
	int outLenReq = 0;
	int outTime = 3;
	int connfd = -1;
	unsigned char *outDataRes = NULL;
	int outLenRes = 0;
	MsgKey_Res *pMsgKeyRes = NULL;
	int resType = 0;

	// 参数判断
	if (NULL == pCltInfo)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], -1,"func MngClient_Agree() 参数输入错误，%d\n", -1);
		return -1;
	}

	// 组织请求报文
	MsgKey_Req pMsgKeyReq;
	memset(&pMsgKeyReq, 0, sizeof(MsgKey_Req));
	pMsgKeyReq.cmdType = KeyMng_NEWorUPDATE;
	strcpy(pMsgKeyReq.clientId, pCltInfo->clientId);
	strcpy(pMsgKeyReq.AuthCode, pCltInfo->AuthCode);
	strcpy(pMsgKeyReq.serverId, pCltInfo->serverId);
	// 产生秘钥
	for (i = 0; i < 64; ++i)
	{
		pMsgKeyReq.r1[i] = 'a' + i;
	}
	
	// 编码报文
	ret = MsgEncode((void *)&pMsgKeyReq, ID_MsgKey_Req, &outDataReq, &outLenReq);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"编码报文 err: %d\n", ret);
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"编码报文完成\n");

	// socket客户端初始化
	ret = sckClient_init();
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"socket客户端初始化 err: %d\n", ret);
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"socket客户端初始化完成\n");

	// 客户端连接服务器
	ret = sckClient_connect(pCltInfo->serverip, pCltInfo->serverport, outTime, &connfd);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"客户端连接服务器 err: %d\n", ret);
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"客户端连接服务器完成\n");

	// 客户端发送报文
	ret = sckClient_send(connfd, outTime, outDataReq, outLenReq);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"客户端发送报文 err: %d\n", ret);
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"客户端发送报文完成\n");

	// --------等待服务器响应报文---------

	// 接受服务器的响应报文
	ret = sckClient_rev(connfd, outTime, &outDataRes, &outLenRes);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"接受服务器的响应报文 err: %d\n", ret);
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"接受服务器的响应报文完成\n");

	// 解码响应报文
	ret = MsgDecode(outDataRes, outLenRes, (void **)&pMsgKeyRes, &resType);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"解码响应报文 err: %d\n", ret);
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"解码响应报文完成\n");

	// 判断是否协商秘钥成功
	if (pMsgKeyRes->rv == 0)	// 成功
	{
		printf("秘钥协商成功!\n");
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"秘钥协商成功\n");
	}
	else						// 失败
	{
		ret = pMsgKeyRes->rv;
		printf("秘钥协商失败!\n");
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"秘钥协商失败 err: %d\n", ret);
		goto End;
	}
	printf("seckeyid %d\n",pMsgKeyRes->seckeyid );
	// 组织网点秘钥信息
	NodeSHMInfo nodeShmInfo;
	memset(&nodeShmInfo, 0, sizeof(NodeSHMInfo));
	nodeShmInfo.status = 0;	// 0表示正常 1表示不正常
	strcpy(nodeShmInfo.clientId, pCltInfo->clientId);
	strcpy(nodeShmInfo.serverId, pCltInfo->serverId);
	nodeShmInfo.seckeyid = pMsgKeyRes->seckeyid;
	for (i = 0; i < 64; ++i)
	{
		nodeShmInfo.seckey[2 * i] = pMsgKeyReq.r1[i];
		nodeShmInfo.seckey[2 * i + 1] = pMsgKeyRes->r2[i];
	}

	// 将网点信息写入共享内存
	ret = KeyMng_ShmWrite(pCltInfo->shmhdl, pCltInfo->maxnode, &nodeShmInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"将网点信息写入共享内存 err: %d\n", ret);
		goto End;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"将网点信息写入共享内存完成\n");

End:
	if (NULL == outDataReq)
	{
		MsgMemFree((void **)&outDataReq, 0);
	}
	if (connfd > 0)
	{
		//客户端 关闭和服务端的连接
    	sckClient_closeconn(connfd);
	}
	if (NULL == outDataRes)
	{
		MsgMemFree((void **)&outDataRes, 0);
	}
	if (NULL == pMsgKeyRes)
	{
		MsgMemFree((void **)&pMsgKeyRes, resType);
	}

	// 释放socket客户端
	sckClient_destroy();
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"释放socket客户端完成\n");

	return ret;
}


// 秘钥校验
int MngClient_Check(MngClient_Info *pCltInfo)
{
	int ret = 0;
	NodeSHMInfo pNodeInfo;
	MsgKey_Req pMsgKeyReq;	//组织请求报文
	unsigned char *outDataReq = NULL;
	int outLenReq = 0;

	MsgKey_Res *pMsgKeyRes = NULL;	//应答报文
	int resType = 0;
	unsigned char *outDataRes = NULL;
	int outLenRes = 0;

	int outTime = 3;
	int connfd = -1;

	if (pCltInfo == NULL)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"参数错误\n");
		return -1;
	}

	//1. 客户端读共享内存， 取出密钥网点信息。  128   ---   以前 8 个字节。
	ret = KeyMng_ShmRead(pCltInfo->shmhdl, pCltInfo->clientId, pCltInfo->serverId, /*pCltInfo->maxnode*/ 1, &pNodeInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func KeyMng_ShmRead err: %d\n", ret);
		return ret;
	}

	//2. 组织请求报文                  r1[8] ---》  服务器  共享内存  --- 比对 r2[8]  ===
	pMsgKeyReq.cmdType = KeyMng_Check;
	strcpy(pMsgKeyReq.clientId, pNodeInfo.clientId);
	strcpy(pMsgKeyReq.AuthCode, pCltInfo->AuthCode);
	strcpy(pMsgKeyReq.serverId, pNodeInfo.serverId);
	memcpy(pMsgKeyReq.r1, pNodeInfo.seckey, 8);

	//3. 编码请求报文
	ret = MsgEncode((void *)&pMsgKeyReq, ID_MsgKey_Req, &outDataReq, &outLenReq);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret," func MsgEncode err: %d\n", ret);
		return ret;
	}

	//4. 发送请求报文
	//客户端 初始化
	ret = sckClient_init();
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_init err: %d\n", ret);
		goto End;
	}
	//连接服务器
	ret = sckClient_connect(pCltInfo->serverip, pCltInfo->serverport, outTime, &connfd);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_connect err: %d\n", ret);
		goto End;
	}
	//客户端 发送报文
    ret = sckClient_send(connfd, outTime, outDataReq, outLenReq);
    if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_send err: %d\n", ret);
		goto End;
	}

	// -----wait------

	//5. 接收应答报文
	ret = sckClient_rev(connfd, outTime, &outDataRes, &outLenRes);
    if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func sckClient_rev err: %d\n", ret);
		goto End;
	}

	//6. 解码应答报文
	ret = MsgDecode( outDataRes, outLenRes, (void **)&pMsgKeyRes, &resType);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MsgDecode err: %d\n", ret);
		goto End;
	}

	//7. 查看 MsgKey_Res.rv 值
	if (pMsgKeyRes->rv == 0)
	{
		printf("MngClient_Check success!\n");
	}
	else
	{
		ret = pMsgKeyRes->rv;
		printf("MngClient_Check failed!\n");
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"MngClient_Check failed : %d\n", ret);
	}

End:
	if (outDataReq != NULL)
	{
		MsgMemFree((void **)&outDataReq, 0);
	}
	if (connfd > 0)
	{
		//客户端 关闭和服务端的连接
		sckClient_closeconn(connfd);
	}
	if (outDataRes != NULL)
	{
		sck_FreeMem((void **)&outDataRes);
	}
	if (pMsgKeyRes != NULL)
	{
		MsgMemFree((void **)&pMsgKeyRes, resType);
	}

	return ret;
}

//密钥注销
int MngClient_Revoke(MngClient_Info *pCltInfo)
{
	int ret = 0;
    int tv = 3;//等待时间
    int count = 3;//重发次数
    int connfd = 0;//socket文件描述符
    unsigned char* out = NULL;//发送报文
    int outLen = 0;//发送报文长度

    //从共享内存中读取数据
    NodeSHMInfo nodeInfo;
    memset(&nodeInfo,0,sizeof(NodeSHMInfo));

    ret = KeyMng_ShmRead (pCltInfo->shmhdl,pCltInfo->clientId,
                          pCltInfo->serverId,pCltInfo->maxnode,&nodeInfo);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"读取共享内存出错:%d",ret);
        return ret;
    }
    if(nodeInfo.status!=0)
    {
        ret = nodeInfo.status;
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"当前的密钥已注销，请更新密钥:%d",ret);
        printf("当前的密钥已注销，请更新密钥！！！！！！！！！！！！\n");
        return ret;
    }

    //组织请求报文
    MsgKey_Req req;
    memset (&req,0,sizeof(MsgKey_Req));
    req.cmdType = KeyMng_Revoke;
    strcpy(req.AuthCode,pCltInfo->AuthCode);
    strcpy(req.clientId,pCltInfo->clientId);
    strcpy(req.r1,"hello");
    strcpy(req.serverId,pCltInfo->serverId);

    //报文编码
    ret = MsgEncode ((void*)&req,ID_MsgKey_Req,&out,&outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"请求报文解码出错:%d",ret);
        goto END;
    }

    //客户端初始化
    ret = sckClient_init ();
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"客户端初始化出错:%d",ret);
        goto END;
    }

    //客户端连接
    ret = sckClient_connect (pCltInfo->serverip,pCltInfo->serverport,tv,&connfd);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"客户端连接出错:%d",ret);
        goto END;
    }

SEND:
	//发送报文
    ret = sckClient_send (connfd,tv,out,outLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"客户端发送出错:%d",ret);
        count--;
        if(count<0)
            goto END;
        goto SEND;
    }

    // ----------wait-----------

    //接收报文
    unsigned char* in = NULL;//接收服务器返回的数据
    int inLen = 0;//数据长度
    ret = sckClient_rev (connfd,tv,&in,&inLen);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"接收报文出错:%d",ret);
        goto END;
    }

    //报文解码
    MsgKey_Res *res = NULL;//服务器应答报文
    int resType = 0;//报文类型
    ret = MsgDecode (in,inLen,(void**)&res,&resType);
    if(ret!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"报文解码出错:%d",ret);
        goto END;
    }

     //是否注销成功
    if(res->rv!=0)
    {
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"密钥注销失败:%d",ret);
        printf("密钥注销失败\n");
        goto END;
    }

    //将当前共享内存的密钥状态置为禁用

    nodeInfo.status = 1;
    nodeInfo.seckeyid = res->seckeyid;

    ret = KeyMng_ShmWrite (pCltInfo->shmhdl,pCltInfo->maxnode,&nodeInfo);
    if(ret!=0)
    {
      KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"写入共享内存出错:%d",ret);
      goto END;
    }
    printf ("写入共享内存成功\n");
    KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],ret,"密钥注销成功");
    printf("密钥注销成功\n");

END:
    if(connfd>0)
    {
        sckClient_closeconn (connfd);
    }
    if(out!=NULL)
    {
        MsgMemFree ((void**)&out,0);
    }
    if(res!=NULL)
    {
        MsgMemFree ((void**)&res,resType);
    }
    if(in!=NULL)
    {
        sck_FreeMem ((void**)&in);
    }

    sckClient_destroy ();

    return ret;
}