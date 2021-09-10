#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include<stdlib.h>
#include<time.h> 
#include<math.h>
typedef uint8_t byte;
typedef uint32_t word;
typedef uint64_t LL;
const int S=400;//随机算法判定次数，S越大，判错概率越小。即是素数的概率为1-1/4^400，几乎可以确定就是素数。 
 
//计算 (a*b)%c.   a,b都是long long的数，直接相乘可能溢出的
//  a,b,c <2^63
long long mult_mod(long long a,long long b,long long c)
{
    a%=c;
    b%=c;
    long long ret=0;
    while(b)
    {
        if(b&1){ret+=a;ret%=c;}
        a<<=1;
        if(a>=c)a%=c;
        b>>=1;
    }
    return ret;
}
 
//计算  x^n %c
long long pow_mod(long long x,long long n,long long mod)//x^n%c
{
    if(n==1)return x%mod;
    x%=mod;
    long long tmp=x;
    long long ret=1;
    while(n)
    {
        if(n&1) ret=mult_mod(ret,tmp,mod);
        tmp=mult_mod(tmp,tmp,mod);
        n>>=1;
    }
    return ret;
}
 
//以a为基,n-1=x*2^t      a^(n-1)=1(mod n)  验证n是不是合数
//一定是合数返回true,不一定返回false
bool check(long long a,long long n,long long x,long long t)
{
    long long ret=pow_mod(a,x,n);
    long long last=ret;
    int i;
    for(i=1;i<=t;i++)
    {
        ret=mult_mod(ret,ret,n);
        if(ret==1&&last!=1&&last!=n-1) return true;//合数
        last=ret;
    }
    if(ret!=1) return true;
    return false;
}
 
// Miller_Rabin()算法素数判定
//可以判断 <2^63的数
//是素数返回true.(可能是伪素数，但概率极小)
//合数返回false;
 
bool Miller_Rabin(long long n)
{
    if(n<2)return false;
    if(n==2)return true;
    if((n&1)==0) return false;//偶数
    long long x=n-1;
    long long t=0;
    int i;
    while((x&1)==0){x>>=1;t++;}
    for(i=0;i<S;i++)
    {
        long long a=rand()%(n-1)+1;//rand()需要stdlib.h头文件
        if(check(a,n,x,t))
            return false;//合数
    }
    return true;
}
//扩展欧几里得算法 
LL exgcd(LL a,LL b,LL *x,LL *y)
{
    if(b==0)
    {
        *x=1;
        *y=0;
        return a;
    }
    LL ret=exgcd(b,a%b,x,y);
    LL t=*x;
    *x=*y;
    *y=t-a/b*(*y);
    return ret;
}

int main(){
	LL i,j,k = 0;
	LL P,Q = 0;
	LL s,t=0;
	LL gcd = 0;
	LL e = 1111110111;
	LL d = 0;
//	printf("%I64d",fin);
	i = pow(10,10);
	j = pow(10,10)+100;
	k=0;
	//找到大于10^10的两个素数 
	for(;i<j;++i){
		if(Miller_Rabin(i)){
			if(k==0){
				P = i;
				++k; 
			}
			else{
				Q = i;
				break;
			}
		}
	}
	LL fin = (P-1)*(Q-1);//得到fin 
	LL N = P*Q;//大整数 
	//得到与fin互素的随机数e，并且通过扩展欧几里得算法，得到了s，t，s即为逆元 
	while(1){
//	printf("%d\n",e);
	gcd = exgcd(e,fin,&s,&t);
	if(gcd==1){//互素 
		break;//s*e+t*fin = 1
	}
	s=0;
	t=0;
	e++;	
}
	
//	puts("找到了"); 
//	printf("%I64d\n%I64d %I64d\n%I64d %I64d\n",gcd,e,fin,s,t);
	while((long long)s<0){
//		printf("%I64d\n",(long long)s);
		s+=fin;
	}
	d = s;//得到密钥 
//	printf("%I64d\n",(long long)s);
	char strd[64];
	char strn[64];
	char strp[64];
	char strq[64];
	char stre[64];
	sprintf(strd,"%I64x",(long long)d);
	sprintf(strn,"%I64x",(long long)N);	
	sprintf(strp,"%I64x",(long long)P);	
	sprintf(strq,"%I64x",(long long)Q);
	sprintf(stre,"%I64x",(long long)e);
	
	printf("私钥d：%s\n写入文件中...\n", strd);
	FILE* fp = fopen("d.txt", "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", "d.txt");
		exit(-1);
	}
	int writecount = fwrite(strd, strlen(strd), 1, fp);
	fclose(fp);
	
	printf("大整数n：%s\n写入文件中...\n", strn);
	fp = fopen("n.txt", "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", "n.txt");
		exit(-1);
	}
	writecount = fwrite(strn, strlen(strn), 1, fp);
	fclose(fp);
	
	printf("随机数e：%s\n写入文件中...\n", stre);
	fp = fopen("e.txt", "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", "e.txt");
		exit(-1);
	}
	writecount = fwrite(stre, strlen(stre), 1, fp);
	fclose(fp);
	
	printf("大素数p：%s\n写入文件中...\n", strp);
	fp = fopen("p.txt", "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", "p.txt");
		exit(-1);
	}
	writecount = fwrite(strp, strlen(strp), 1, fp);
	fclose(fp);
	
	printf("大素数q：%s\n写入文件中...\n", strq);
	fp = fopen("q.txt", "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", "q.txt");
		exit(-1);
	}
	writecount = fwrite(strq, strlen(strq), 1, fp);
	fclose(fp);
	//benchmark();
	printf("恭喜你完成了该程序，请提交代码!");

}


