#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "keymnglog.h"
#include "poolsocket.h"
#include "keymngclientop.h"
#include "keymng_msg.h"

int Usage()
{
    int nSel = -1;
    
    system("clear");    
    printf("\n  /*************************************************************/");
    printf("\n  /*************************************************************/");
    printf("\n  /*                   1.密钥协商                              */");
    printf("\n  /*                   2.密钥校验                              */");
    printf("\n  /*                   3.密钥注销                              */");
    printf("\n  /*                   4.密钥查看                              */");
    printf("\n  /*                   0.退出系统                              */");
    printf("\n  /*************************************************************/");
    printf("\n  /*************************************************************/");
    printf("\n\n  选择:");
    scanf("%d", &nSel);
    while(getchar() != '\n'); //把应用程序io缓冲器的所有的数据 都读走,避免影响下一次 输入
    
    return nSel;
}

int main()
{
	int ret = 0;
	int n = 0;

	MngClient_Info mngClientInfo;	// 初始化客户端信息
	memset(&mngClientInfo, 0, sizeof(MngClient_Info));

	//初始化客户端 全局变量
 	ret = MngClient_InitInfo(&mngClientInfo);
 	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4], ret,"func MngClient_InitInfo() err: %d\n", ret);
		return ret;
	}
	KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"初始化客户端-->完成！\n");

	while (1)
	{
		n = Usage();	//用户输入编号
		switch(n)
		{
			case KeyMng_NEWorUPDATE:
				// 秘钥协商
				ret= MngClient_Agree(&mngClientInfo);
			break;
			case KeyMng_Check:	
				//密钥校验
			    ret = MngClient_Check(&mngClientInfo);
			break;
			case KeyMng_Revoke://密钥注销
	            ret = MngClient_Revoke(&mngClientInfo);
	            if(ret!=0)
	            {
	                printf("服务器密钥注销失败\n");
	                KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[4],ret,"服务器密钥注销失败:%d",ret);
	            }else
	            {
	                printf("服务器密钥注销成功\n");
	                KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2],ret,"服务器密钥注销成功: %d", ret);
	            }
				break;
			case 0:
				exit(1);
			break;
			default:
				printf("选项不支持\n");
				KeyMng_Log(__FILE__, __LINE__,KeyMngLevel[2], 2,"该选项不支持, 选项的值为: %d\n", n);
			break;
		}
		if (ret)
		{
			printf("\nERROR!错误码为: %d\n", ret);
		}
		else
		{
			printf("\nSUCCESS!!!\n");
		}
		getchar();
	}

	printf("客户端完成!\n");
	return 0;
}


