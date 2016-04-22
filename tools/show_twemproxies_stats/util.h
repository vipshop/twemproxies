#ifndef _SHOW_UTIL_H_
#define _SHOW_UTIL_H_

#include <stdlib.h>
#include <string.h>
#include <time.h>

int my_atoi(const char* str){
     if(str == NULL)
     {
          printf("error: the argument of my_atoi is NULL!\n");
          exit(0);
     }
    
     int res=0;
     char sign='+';
     const char *pStr=str;
    
     //去空格
     while (*pStr==' ')
          pStr++;
     //判断正负
     if(*pStr=='+' || *pStr=='-')
          sign=*pStr++;    
     //计算绝对值
     while (*pStr>='0' && *pStr<='9')
     {
          res=res*10+*pStr-'0';
          pStr++;
     }

     return sign=='-'?-res:res;
}

long long my_atoll(const char* str){
     if(str == NULL)
     {
          printf("error: the argument of my_atoi is NULL!\n");
          exit(0);
     }
    
     long long res=0;
     char sign='+';
     const char *pStr=str;
    
     //去空格
     while (*pStr==' ')
          pStr++;
     //判断正负
     if(*pStr=='+' || *pStr=='-')
          sign=*pStr++;    
     //计算绝对值
     while (*pStr>='0' && *pStr<='9')
     {
          res=res*10+*pStr-'0';
          pStr++;
     }

     return sign=='-'?-res:res;
}

//最快的字符串倒置方法
void rever(char s[]){
     if(s == NULL)
     {
          printf("error: the argument of my_atoi is NULL!");
          exit(0);
     }
    
     int len=strlen(s);
     int i=0;
     int j=len-1;
     char c;
     while (i<j)
     {
          c=s[i];
          s[i]=s[j];
          s[j]=c;
          i++;
          j--;
     }
}

void my_itoa(int n, char s[]){
     if(s == NULL)
     {
          printf("error: the argument of my_atoi is NULL!");
          exit(0);
     }

     int i=0;
     int sign=0;

     //判断符号
     if((sign=n)<0)
          n=-n;

     //分解生成逆序字符串
     do {
          s[i++]=n%10+'0';
     } while ((n/=10)>0);
     if(sign<0)
          s[i++]='-';

     //结尾注意添加\0
     s[i]='\0';
     rever(s);
}

char tohex(int n)
{

    if(n>=10 && n<=15)
    {
    	return 'A'+n-10;
    }
    return '0'+n;
}

void dec2hex(int n,char s[])
{
	int i=0;
	int mod;
	
	if(n <= 0)
	{
		s[0] = '\0';
		return;
	}
	
	while(n)
	{
		mod = n%16;
		s[i++]=tohex(mod);
		n=n/16;
	}
	
	s[i]='\0';
	
	rever(s);
}

/* Return the UNIX time in microseconds */
long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

/* Return the UNIX time in milliseconds */
long long mstime(void) {
    return ustime()/1000;
}

int
set_blocking(int sd)
{
    int flags;

    flags = fcntl(sd, F_GETFL, 0);
    if (flags < 0) {
        return flags;
    }

    return fcntl(sd, F_SETFL, flags & ~O_NONBLOCK);
}

int
set_nonblocking(int sd)
{
    int flags;

    flags = fcntl(sd, F_GETFL, 0);
    if (flags < 0) {
        return flags;
    }

    return fcntl(sd, F_SETFL, flags | O_NONBLOCK);
}

#endif
