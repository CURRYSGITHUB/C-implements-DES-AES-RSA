#define _CRT_SECURE_NO_WARNINGS
//#include "staticdata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
char Ks[16][49];//总密钥 
//char keytext[16] = {'5','7','6','9','6','C','6','C','6','9','6','1','6','D','5','3'};
void KeySep(const char* keytext){//i指需要返回的是第i个子密钥；keytext是一个十六进制字符串序列。 
	int tBK[17];
	int count = 0;	
	char BK[65];//给定的64位二进制密钥序列
	int i,j,k = 0;
	char PBK[57];//置换后的密钥 
	int temp = 0;
	char C[29];//前28位 
	char D[29];//后28位 
	char T[29];//用于循环移位的暂存 
	char CD[57];//合并的密钥 
	/*十六进制转位十进制数值*/
	for(i=0;i<16;++i){
		
		switch(keytext[i]){
			case '0':
				tBK[i] = 0;
				break;
			case '1':
				tBK[i] = 1;
				break;
			case '2':
				tBK[i] = 2;
				break;
			case '3':
				tBK[i] = 3;
				break;			
			case '4':
				tBK[i] = 4;
				break;
			case '5':
				tBK[i] = 5;
				break;			
			case '6':
				tBK[i] = 6;
				break;
			case '7':
				tBK[i] = 7;
				break;			
			case '8':
				tBK[i] = 8;
				break;
			case '9':
				tBK[i] = 9;
				break;			
			case 'A':
				tBK[i] = 10;
				break;
			case 'B':
				tBK[i] = 11;
				break;			
			case 'C':
				tBK[i] = 12;
				break;
			case 'D':
				tBK[i] = 13;
				break;			
			case 'E':
				tBK[i] = 14;
				break;
			case 'F':
				tBK[i] = 15;
				break;
		}
	} 
	//转为二进制字符序列
	count=0;
	for(i=0;i<16;++i){
		temp = tBK[i];		
		for(j=0;j<4;++j){
			BK[count] = HX[temp][j];
			++count;
		}
	}
	//对BK执行PC-1置换（置换矩阵去除了奇偶校验位，故无须手动删除） 
	count=0;
	for(i=0;i<8;++i){
		for(j=0;j<7;++j){
			temp = PC1[i][j];
			PBK[count] = BK[temp-1];
			++count;
		}
	} 

	//分为前后28位
	for(i=0;i<28;++i){
		C[i] = PBK[i];
		D[i] = PBK[i+28];
	} 
	//开始分发密钥
	for(i=0;i<16;++i){
		
		switch(LS[i]){//根据LS移位 
			case 1:
				//C
				//printf("%s\n",C);
				T[0] = C[0];
				for(j=0;j<28-1;++j){
					C[j] = C[j+1]; 
				}
				C[27] = T[0];
				//printf("%s\n",C);
				//D
				//printf("%s\n",D);
				T[0] = D[0];
				for(j=0;j<28-1;++j){
					D[j] = D[j+1]; 
				}
				D[27] = T[0];
				//printf("%s\n",D);				
				break;
			case 2:
				//C
				//printf("%s\n",C);
				T[0] = C[0];
				T[1] = C[1];
				for(j=0;j<28-2;++j){
					C[j] = C[j+2];
				}
				C[26] = T[0];
				C[27] = T[1];
			//	printf("%s\n",C);
				//D
				//printf("%s\n",D);
				T[0] = D[0];
				T[1] = D[1];
				for(j=0;j<28-2;++j){
					D[j] = D[j+2];
				}
				D[26] = T[0];
				D[27] = T[1];
				//printf("%s\n",D);
				break;
		}
		//合并密钥 
		for(j=0;j<56;++j){
			if(j<28){
				CD[j] = C[j];
			}
			else{
				CD[j] = D[j-28];
			}
		}
		//通过PC-2置换，生成这一轮的子密钥
		count = 0;
		for(j=0;j<6;++j){
			for(k=0;k<8;++k){
				temp = PC2[j][k];
				Ks[i][count++] = CD[temp-1]; 
			}
		}
		Ks[i][48]='\0';
	//	printf("K%d:%s\n",i,Ks[i]); 
	} 
};

/*int main(){
	KeySep(keytext);
	int i,j=0;
	for(i=0;i<16;i++){
		printf("K%d:%s\n",i+1,Ks[i]);
	}

	return 0;
}*/

