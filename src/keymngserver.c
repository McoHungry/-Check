#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "poolsocket.h"
#include "keymngserverop.h"
#include "keymnglog.h"
#include "keymng_dbop.h"
#include "icdbapi.h"

int Flg = 0;
MngServer_Info mngServerInfo;

#define INIT_DAEMON() do{if(fork()>0)exit(0);setsid();if(fork()>0)exit(0);}while(0);

void sighandler(int signum)
{
	Flg = 1;
	return;	
}

void *(mystart_routine) (void *arg)
{
 	int ret = 0;
 	int connfd = (int)(intptr_t)arg;
 	int timeOut = 3;
 	MsgKey_Req *pMsgKeyReq = NULL;
 	int reqType = 0;
 	
 	while (1)
 	{
 		unsigned char *outDataReq = NULL;
 		int outLenReq = 0;
 		unsigned char *outData = NULL;
 		int outLen = 0;

 		// 服务端接受报文
 		ret = sckServer_rev(connfd, timeOut, &outDataReq, &outLenReq);
 		if (ret == Sck_ErrPeerClosed)
        {
            KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4],ret,"服务器端检查到客户端已经关闭 所以服务器端链接需要关闭:%d",ret);
            break;
        }
        else if (ret == Sck_ErrTimeOut)
        {
        	//sleep(5);
            //KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[2],ret,"服务器接受超时 %d\n", ret);
            continue;
        }
 		else if (ret != 0)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret,"服务端接受报文 err: %d\n", ret);
			break;
		}
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[2], 2,"服务端接受报文完成\n");

		// 解码服务端接受报文
		ret = MsgDecode(outDataReq, outLenReq, (void **)&pMsgKeyReq, &reqType);
		if (ret != 0)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret,"解码服务端接受报文 err: %d\n", ret);
			sck_FreeMem((void **)&outDataReq);
            continue;
		}
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"解码服务端接受报文完成\n");

		switch(pMsgKeyReq->cmdType)
		{
			case KeyMng_NEWorUPDATE:
				// 服务器端秘钥协商
				ret = MngServer_Agree(&mngServerInfo, pMsgKeyReq, &outData, &outLen);
				if (ret != 0)
				{
					sck_FreeMem((void **)&outDataReq);
					MsgMemFree((void **)&pMsgKeyReq, reqType);
					KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"服务器端秘钥协商 err: %d\n", ret);
					break;
				}
				KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"服务器端秘钥协商完成\n");
			break;
			case KeyMng_Check://秘钥校验
 				ret = MngServer_Check(&mngServerInfo, pMsgKeyReq, &outData, &outLen);
 				if (ret != 0)
				{
					sck_FreeMem((void **)&outDataReq);
					MsgMemFree((void **)&pMsgKeyReq, reqType);
					KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"服务器秘钥校验 err: %d\n", ret);
					break;
				}
 				KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"服务器端秘钥校验完成\n");
 			break;
 			case KeyMng_Revoke: //密钥注销
	            ret = MngServer_Revoke (&mngServerInfo, pMsgKeyReq, &outData, &outLen);
	            if (ret != 0)
				{
					sck_FreeMem((void **)&outDataReq);
					MsgMemFree((void **)&pMsgKeyReq, reqType);
					KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"服务器密钥注销 err: %d\n", ret);
					break;
				}
 				KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"服务器端密钥注销完成\n");
            break;
			default: 
				KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"未知操作\n");
				printf("未知操作\n");
			break;
		}

		// 服务器端发送报文
		ret = sckServer_send(connfd, timeOut, outData, outLen);
		if (ret == Sck_ErrPeerClosed)
		{
			sck_FreeMem((void **)&outDataReq);
			MsgMemFree((void **)&outData, 0);
			MsgMemFree((void **)&pMsgKeyReq, reqType);
			printf("服务器端检查到客户端已经关闭 所以服务器端链接需要关闭\n");
			KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"服务器端检查到客户端已经关闭 所以服务器端链接需要关闭 err: %d\n", ret);
            break;
		}
		else if (ret == Sck_ErrTimeOut)
        {
            sck_FreeMem((void **)&outDataReq);
			MsgMemFree((void **)&outData, 0);
			MsgMemFree((void **)&pMsgKeyReq, reqType);
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"服务器发送超时\n");
            continue;
        }
        else if (ret != 0)
        {
            sck_FreeMem((void **)&outDataReq);
			MsgMemFree((void **)&outData, 0);
			MsgMemFree((void **)&pMsgKeyReq, reqType);
            KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"服务器端发送报文 err: %d\n", ret);
            break;
        }
        KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"服务器端发送报文完成\n");

        sck_FreeMem((void **)&outDataReq);
		MsgMemFree((void **)&outData, 0);
		MsgMemFree((void **)&pMsgKeyReq, reqType);

    }
    //当客户端关闭时，服务器才把连接关闭
    sckServer_close (connfd);

    return NULL;
}

int main(void)
{
	int	ret = 0;
	int listenfd = -1;
	int timeOut = 3;
	int connfd = -1;
	
	//使应用程序成为守护进程
    INIT_DAEMON();
    signal(SIGUSR1,sighandler);
    //忽略管道破裂信号
    signal(SIGPIPE,SIG_IGN);

	// 初始化服务器信息
	memset(&mngServerInfo, 0, sizeof(MngServer_Info));
	ret = MngServer_InitInfo(&mngServerInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"初始化服务器信息 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"初始化服务器信息完成\n");

	// 初始化socket服务器
	ret = sckServer_init(mngServerInfo.serverport, &listenfd);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"初始化socket服务器 err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"初始化socket服务器完成\n");

	while (1)
	{
		if (Flg == 1)
		{
			break;
		}

		// 服务器监听
		ret = sckServer_accept(listenfd, timeOut, &connfd);
		if(ret == Sck_ErrTimeOut)
		{
			printf("服务器监听超时\n");
		}
		else if (ret != 0)
		{
			KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"服务器监听 err: %d\n", ret);
			return ret;
        }	
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"服务器监听完成\n");

		pthread_t pid = 0;
		pthread_create(&pid, NULL, mystart_routine, (void *)(intptr_t)connfd);
		pthread_detach(pid);
	}

	sleep (1);
	IC_DBApi_PoolFree();
	// 释放服务器
	sckServer_destroy();
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"释放服务器完成\n");
	printf("释放服务器, 主程序退出\n");
	
	return 0;	
}