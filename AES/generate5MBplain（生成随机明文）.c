#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include<math.h>
#define MAX_SIZE 65536
//65536
int main(void)
{
	int i,M,b,j;
	int max;
    FILE *fp;//声明文件指针
    char str[]="";
	M = MAX_SIZE; //输入i,M
	fp = fopen("plaintest.txt","w");//在指定目录下创建.txt文件
    srand(time(NULL)); //初始化时间种子
    max=(int)pow(2,7) - 6; //随机数的最大值
    for(j=0;j<M;j++)
    {
		b=rand()%(16); //区间(0~15)  rand（）% （b - a + 1）+ a
		if(b<2||b>7){
		 	--j; 
		 	continue;
		}
	    fprintf(fp,"%X",b); //把随机数写进文件
    }
    fclose(fp); //关闭文件
    return 0;

} 

