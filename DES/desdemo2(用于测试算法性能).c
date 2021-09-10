#define _CRT_SECURE_NO_WARNINGS
#define MAX_SIZE 65536
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include"DES（单个DES模型）.c"
const char* DES_MODE[] = { "ECB","CBC","CFB","OFB" };

char* plainfile = NULL;
char* keyfile = NULL;
char* vifile = NULL;
char* mode = NULL;
char* cipherfile = NULL;

char* plaintext = NULL;
char* keytext = NULL;
char* vitext = NULL;
char* ciphertext = NULL;
char* ciphertext2 = NULL;
char * mvXor(const char* M,const char *V);
int cipher[MAX_SIZE*4];
char wordss[MAX_SIZE];
int begintime1,endtime1;//加密时间 
int begintime2,endtime2; //解密时间 
void print_usage() {
	printf("\n非法输入,支持的参数有以下：\n-p plainfile 指定明文文件的位置和名称\n-k keyfile  指定密钥文件的位置和名称\n-v vifile  指定初始化向量文件的位置和名称\n-m mode  指定加密的操作模式(ECB,CBC,CFB,OFB)\n-c cipherfile 指定密文文件的位置和名称。\n");
	exit(-1);
}

bool readfile2memory(const char* filename, char** memory) {
	FILE* fp = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (size % 2 != 0) {
		printf("%s:文件字节数不为偶数！\n", filename);
		fclose(fp);
		return false;
	}
	char* tmp = malloc(size);
	memset(tmp, 0, size);

	fread(tmp, size, 1, fp);
	if (ferror(fp)) {
		printf("读取%s出错了！\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}

	*memory = malloc(size / 2 + 1);
	memset(*memory, 0, size / 2 + 1);

	char parsewalker[3] = { 0 };
	int i;
	for (i = 0; i < size; i += 2) {
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);
		printf("debug info : %c\n", (*memory)[i / 2]);
		printf("%d",i);
	}

	free(tmp);

	return true;
}
char * mvXor(const char* M,const char *V){
	int i,j,k,z = 0;
	int temp;
	int tDP[17] = {0};//十六进制明文转为十进制数值序列 
	char BP[65];//64位二进制明文序列 
	char BV[65];//64为二进制向量序列 
	int xor[65];
	int count;
	/*十六进制字符转为十进制数值*/
//	printf("%d",strlen(M));
	if(strlen(M)==16){
		for(i=0;i<16;++i){
			switch(M[i]){
				case '0':
					tDP[i] = 0;
					break;
				case '1':
					tDP[i] = 1;
					break;
				case '2':
					tDP[i] = 2;
					break;
				case '3':
					tDP[i] = 3;
					break;			
				case '4':
					tDP[i] = 4;
					break;
				case '5':
					tDP[i] = 5;
					break;			
				case '6':
					tDP[i] = 6;
					break;
				case '7':
					tDP[i] = 7;
					break;			
				case '8':
					tDP[i] = 8;
					break;
				case '9':
					tDP[i] = 9;
					break;			
				case 'A':
					tDP[i] = 10;
					break;
				case 'B':
					tDP[i] = 11;
					break;			
				case 'C':
					tDP[i] = 12;
					break;
				case 'D':
					tDP[i] = 13;
					break;			
				case 'E':
					tDP[i] = 14;
					break;
				case 'F':
					tDP[i] = 15;
					break;
			}
		} 
		//转为二进制字符序列
		count = 0;
		for(i=0;i<16;++i){
			temp = tDP[i];		
			for(j=0;j<4;++j){
				BP[count] = HX[temp][j];
				++count;
			}
		}
	}
	else if(strlen(M)==64){
		for(i=0;i<64;++i){
			BP[i] = M[i];
		}
	}
	else if(strlen(M)!=16&&strlen(M)!=64){
		puts("xorerror");
		return NULL;
	}	
	for(i=0;i<16;++i){
		switch(V[i]){
			case '0':
				tDP[i] = 0;
				break;
			case '1':
				tDP[i] = 1;
				break;
			case '2':
				tDP[i] = 2;
				break;
			case '3':
				tDP[i] = 3;
				break;			
			case '4':
				tDP[i] = 4;
				break;
			case '5':
				tDP[i] = 5;
				break;			
			case '6':
				tDP[i] = 6;
				break;
			case '7':
				tDP[i] = 7;
				break;			
			case '8':
				tDP[i] = 8;
				break;
			case '9':
				tDP[i] = 9;
				break;			
			case 'A':
				tDP[i] = 10;
				break;
			case 'B':
				tDP[i] = 11;
				break;			
			case 'C':
				tDP[i] = 12;
				break;
			case 'D':
				tDP[i] = 13;
				break;			
			case 'E':
				tDP[i] = 14;
				break;
			case 'F':
				tDP[i] = 15;
				break;
		}
	} 
	//转为二进制字符序列
	count = 0;
	for(i=0;i<16;++i){
		temp = tDP[i];		
		for(j=0;j<4;++j){
			BV[count] = HX[temp][j];
			++count;
		}
	}
	//xor
	for(i=0;i<64;++i){
		if(BV[i]==BP[i]){
			xor[i] = 0;
		}
		else{
			xor[i] = 1;
		}
	}
	//二进制数值转十六进制字符 
	char *words = malloc(40);
	int w=0;
	count = 0;
	for(i=0;i<16;++i){
		w=0;
		for(j=0;j<4;++j){
			w+=xor[count++]*pow(2,3-j);
		}
		sprintf(words+i,"%X",w);
	}
	return words;
	
}


void ECB(const char* plaintext, const char* keytext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	char K[17]; 
	int i,j,k,z = 0;
	int count = strlen(plaintext);
	uint8_t M[count*2+1];//十六进制明文 
	for (i = 0; i < count; ++i) {
		sprintf(M+i*2,"%2X", plaintext[i]);
	}
	count = strlen(keytext);
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
	printf("%d\n",M[1]);
	count = strlen(M);
	int Flag = count/16;//分组个数
	char DM[Flag][17];
	char DC[Flag][65];
	k = 0; 
	for(i=0;i<Flag;++i){
		for(j=0;j<16;++j){
			DM[i][j] = M[k];
			++k;
		}
		DM[i][j] = '\0';
	}
	//printf("%s%s\n",M1,M2);
	*ciphertext=(char*)malloc(sizeof(char)*count*4);
	char*M1 = malloc(sizeof(char)*16);
//	char*C1 = malloc(sizeof(char)*64);
	int TAG = 1600;
	begintime1 = clock();
	for(z=0;z<TAG;++z){
		for(i=0;i<Flag;++i){
			M1 = DM[i];
			DESEk(M1,K,ciphertext);
			memcpy(DC[i],*ciphertext,64);
			DC[i][64] = '\0';
		}
		printf("第%d次加密\n",z);		
	}
	endtime1= clock();
	char CI[count*4+1];
	k = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<64;++j){
			CI[k] = DC[i][j];
			++k;
		}
	}
	CI[k] = '\0';
	*ciphertext = CI;
	printf("密文：%s\n",*ciphertext);
//10010101100010010010000010110001001101011000111011110001100101110010101110011110111001000101010010001101110000001000111010001010

}



void CBC(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	char *VM=malloc(32);//向量和明文异或后的序列 
	char K[17];
	char V[65] = {'\0'};
	int i,j,k,z = 0;
	int count = strlen(plaintext);
	char M[count*2+1];//十六进制明文 
	for (i = 0; i < count; ++i) {
		sprintf(M+i*2,"%2X", plaintext[i]);
	}
	count = strlen(keytext);
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
	count = strlen(vitext);
	for (i = 0; i < count; ++i) {
		sprintf(V+i*2,"%2X", vitext[i]);
	}
//	printf("%s\n",V);
	count = strlen(M);
	int Flag = count/16;//分组个数
	char DM[Flag][17];
	char DC[Flag][65];
	k = 0; 
	for(i=0;i<Flag;++i){
		for(j=0;j<16;++j){
			DM[i][j] = M[k];
			++k;
		}
		DM[i][j] = '\0';
	}
	
	*ciphertext=(char*)malloc(sizeof(char)*count*4);
	char*M1 = malloc(sizeof(char)*16);
	char*C1 = malloc(sizeof(char)*64);
	int TAG = 1600;
	begintime1 = clock();
	for(z=0;z<TAG;++z){
		for(i=0;i<Flag;++i){
			M1 = DM[i];
			//第一分组明文与初始向量异或 （十六进制异或）
			VM = mvXor(V,M1);
			DESEk(VM,K,ciphertext);
			//得到第一组密文，二进制字符串 
			memcpy(DC[i],*ciphertext,64);
			DC[i][64] = '\0';
			memcpy(V,DC[i],64);
		}
		printf("第%d次加密\n",z);	
	} 
	endtime1 = clock();
	char CI[count*4+1];
	k = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<64;++j){
			CI[k] = DC[i][j];
			++k;
		}
	}
	CI[k] = '\0';
	*ciphertext = CI;
	printf("密文：%s\n",*ciphertext);
//01011110101100010101101110010001010100000110101110011010111001111100111010110110010110010101010010101110000100010101111000000011
}

void CFB(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	const int s = 8;
	int b = 16;
	int Flag = 0;
	char *VM=malloc(20);
	char rs[65];
	char word[17];
	int temp;
	int i,j,k = 0;
	int mc = 0;
	int count = strlen(plaintext);
	char M[count*2+1];
	for (i = 0; i < count; ++i) {
		sprintf(M+i*2,"%2X", plaintext[i]);
	}
	count = strlen(keytext);
	char K[count*2+1];
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
	count = strlen(vitext);
	char V[count*2+1];//初始向量的十六进制序列 
	for (i = 0; i < count; ++i) {
		sprintf(V+i*2,"%2X", vitext[i]);
	}
	/*十六进制字符转为十进制数值*/
	mc = strlen(M);//十六进制明文总长度 
	int tDP[mc+1];
	printf("模式中十六进制明文的总大小为：%d个字符",mc);
	for(i=0;i<mc;++i){
		switch(M[i]){
			case '0':
				tDP[i] = 0;
				break;
			case '1':
				tDP[i] = 1;
				break;
			case '2':
				tDP[i] = 2;
				break;
			case '3':
				tDP[i] = 3;
				break;			
			case '4':
				tDP[i] = 4;
				break;
			case '5':
				tDP[i] = 5;
				break;			
			case '6':
				tDP[i] = 6;
				break;
			case '7':
				tDP[i] = 7;
				break;			
			case '8':
				tDP[i] = 8;
				break;
			case '9':
				tDP[i] = 9;
				break;			
			case 'A':
				tDP[i] = 10;
				break;
			case 'B':
				tDP[i] = 11;
				break;			
			case 'C':
				tDP[i] = 12;
				break;
			case 'D':
				tDP[i] = 13;
				break;			
			case 'E':
				tDP[i] = 14;
				break;
			case 'F':
				tDP[i] = 15;
				break;
		}
	}
	char BM[mc*4+1]; 
	count = 0;
	for(i=0;i<mc;++i){
		temp = tDP[i];
		for(j=0;j<4;++j){
			BM[count] = HX[temp][j];
			++count;			
		}
	}
	BM[mc*4] = '\0'; 
	//以上得到128位二进制字符串BM 
	Flag = (strlen(M)*4)/s;//分组个数 
	char DM[Flag][s+1];//总明文 
	char DC[Flag][s+1];//总密文 
	int cd[65];//进制转化的辅助 
//	printf("%s\n%s\n%s\n%s\n",plaintext,keytext,M,K);
		//将明文分组 
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			DM[i][j] = BM[count];
			count++;
		}
		DM[i][j] = '\0';
	}
	//printf("%s%s\n",M1,M2);
	*ciphertext=(char*)malloc(sizeof(char)*mc*4);
	//CFB模式
	begintime1=clock(); 
	VM = V; //VM类似于移位寄存器 
	int TAG;
	for(TAG=0;TAG<1600;++TAG){// TAG = (5*2^20*20*20)/2^16

		for(i=0;i<Flag;++i){
			DESEk(VM,K,ciphertext);
			memcpy(rs,*ciphertext,s*2);//加密结果放入选择寄存器
			for(j=0;j<s;++j){
				if(DM[i][j]==rs[j]){
					DC[i][j]='0';
				}
				else{
					DC[i][j]='1'; 
				}
			}
			DC[i][s]='\0';
			if(i<Flag-1){
				//移位寄存器左移s位 
				for(j=0;j<64-s;++j){
					DV[j] = DV[j+s];
				}
				//将上一轮s位密文加入 
				for(j=0;j<s;++j){
					DV[64-s+j] = DC[i][j];
				}
				//在将DV化为十六进制序列。
				//二进制字符转数值存储
				for(j=0;j<64;++j){
					cd[j] = DV[j]-48;
				}
				//二进制数值转十六进制字符 cd为二进制数值序列 
				int w=0;
				count = 0;
				for(j=0;j<16;++j){
					w=0;
					for(k=0;k<4;++k){
						w+=cd[count++]*pow(2,3-k);
					}
					sprintf(VM+j,"%X",w);
				}
//				printf("%s",VM);	
			}			
		}
		printf("第%d次加密\n",TAG);
	}
	endtime1=clock();
	char CI[8*Flag+1];
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			CI[count++] = DC[i][j];
		}
	}
	CI[8*Flag] = '\0';
	*ciphertext = CI;
	printf("密文：%s\n",*ciphertext);
}//11110111000011110000000101011000010010101100111101001101100101100110101011011100000101000011111010110010010000001100100101100010


void OFB(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~

	const int s = 8;
	int b = 16;
	int Flag = 0;
	char *VM=malloc(20);
	char rs[65];
	char word[17];
	int temp;
	int i,j,k = 0;
	int mc = 0;
	int count = strlen(plaintext);
	char M[count*2+1];
	for (i = 0; i < count; ++i) {
		sprintf(M+i*2,"%2X", plaintext[i]);
	}
	count = strlen(keytext);
	char K[count*2+1];
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
	count = strlen(vitext);
	char V[count*2+1];//初始向量的十六进制序列 
	for (i = 0; i < count; ++i) {
		sprintf(V+i*2,"%2X", vitext[i]);
	}
	/*十六进制字符转为十进制数值*/
	mc = strlen(M);//十六进制明文总长度 
	int tDP[mc+1];
	printf("模式中十六进制明文的总大小为：%d个字符",mc);
	for(i=0;i<mc;++i){
		switch(M[i]){
			case '0':
				tDP[i] = 0;
				break;
			case '1':
				tDP[i] = 1;
				break;
			case '2':
				tDP[i] = 2;
				break;
			case '3':
				tDP[i] = 3;
				break;			
			case '4':
				tDP[i] = 4;
				break;
			case '5':
				tDP[i] = 5;
				break;			
			case '6':
				tDP[i] = 6;
				break;
			case '7':
				tDP[i] = 7;
				break;			
			case '8':
				tDP[i] = 8;
				break;
			case '9':
				tDP[i] = 9;
				break;			
			case 'A':
				tDP[i] = 10;
				break;
			case 'B':
				tDP[i] = 11;
				break;			
			case 'C':
				tDP[i] = 12;
				break;
			case 'D':
				tDP[i] = 13;
				break;			
			case 'E':
				tDP[i] = 14;
				break;
			case 'F':
				tDP[i] = 15;
				break;
		}
	}
	char BM[mc*4+1]; 
	count = 0;
	for(i=0;i<mc;++i){
		temp = tDP[i];
		for(j=0;j<4;++j){
			BM[count] = HX[temp][j];
			++count;			
		}
	}
	BM[mc*4] = '\0'; 
	//以上得到128位二进制字符串BM 
	Flag = (strlen(M)*4)/s;//分组个数 
	char DM[Flag][s+1];//总明文 
	char DC[Flag][s+1];//总密文 
	int cd[65];//进制转化的辅助 
//	printf("%s\n%s\n%s\n%s\n",plaintext,keytext,M,K);
		//将明文分组 
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			DM[i][j] = BM[count];
			count++;
		}
		DM[i][j] = '\0';
	}
	//printf("%s%s\n",M1,M2);
	*ciphertext=(char*)malloc(sizeof(char)*mc*4);
	//CFB模式 
	begintime1=clock();
	VM = V; //VM类似于移位寄存器 
	int TAG;
	for(TAG=0;TAG<1600;++TAG){// TAG = (5*2^20*20*20)/2^16

		for(i=0;i<Flag;++i){
			DESEk(VM,K,ciphertext);
			memcpy(rs,*ciphertext,s*2);//加密结果放入选择寄存器
			for(j=0;j<s;++j){
				if(DM[i][j]==rs[j]){
					DC[i][j]='0';
				}
				else{
					DC[i][j]='1'; 
				}
			}
			DC[i][s]='\0';
			if(i<Flag-1){
				//移位寄存器左移s位 
				for(j=0;j<64-s;++j){
					DV[j] = DV[j+s];
				}
				//将上一轮s位密文加入 
				for(j=0;j<s;++j){
					DV[64-s+j] = rs[j];
				}
				//在将DV化为十六进制序列。
				//二进制字符转数值存储
				for(j=0;j<64;++j){
					cd[j] = DV[j]-48;
				}
				//二进制数值转十六进制字符 cd为二进制数值序列 
				int w=0;
				count = 0;
				for(j=0;j<16;++j){
					w=0;
					for(k=0;k<4;++k){
						w+=cd[count++]*pow(2,3-k);
					}
					sprintf(VM+j,"%X",w);
				}
//				printf("%s",VM);	
			}			
		}
		printf("第%d次加密\n",TAG);
	}
	endtime1=clock();
	char CI[8*Flag+1];
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			CI[count++] = DC[i][j];
		}
	}
	CI[8*Flag] = '\0';
	*ciphertext = CI;
	printf("密文：%s\n",*ciphertext);

}

//各个模式的解密模型 
void ECBd(const char* plaintext,const char*keytext,char**ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	char K[17]; 
	int i,j,k,z = 0;
	int count = strlen(plaintext);
	char M[count+1];//十六进制明文 
	for (i = 0; i < count; ++i) {
		M[i] = plaintext[i]; 
	}
	count = strlen(keytext);
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
//	printf("%s\n%s\n%s\n%s\n",plaintext,keytext,M,K);
	count = strlen(M);
	int Flag = count/16;//分组个数
	char DM[Flag][17];
	char DC[Flag][65];
	k = 0; 
	for(i=0;i<Flag;++i){
		for(j=0;j<16;++j){
			DM[i][j] = M[k];
			++k;
		}
		DM[i][j] = '\0';
	}
	//printf("%s%s\n",M1,M2);
	*ciphertext=(char*)malloc(sizeof(char)*count*4);
	char*M1 = malloc(sizeof(char)*16);
//	char*C1 = malloc(sizeof(char)*64);
	int TAG = 1600;
	begintime2 = clock();
	for(z=0;z<TAG;++z){
		for(i=0;i<Flag;++i){
			M1 = DM[i];
			DESEk(M1,K,ciphertext);
			memcpy(DC[i],*ciphertext,64);
			DC[i][64] = '\0';
		}
		printf("解密第%d次\n",z);		
	}
	endtime2 = clock();
	char CI[count*4+1];
	k = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<64;++j){
			CI[k] = DC[i][j];
			++k;
		}
	}
	CI[k] = '\0';
	*ciphertext = CI;
	printf("  明文为：%s\n",*ciphertext);
//10010101100010010010000010110001001101011000111011110001100101110010101110011110111001000101010010001101110000001000111010001010

}
void CBCd(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext){
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	char VM[65];
	char *VM1=malloc(32);
	char K[17];
	char V[65] = {'\0'};
	int i,j,k,z = 0;
	int count = strlen(plaintext);
	char M[count+1];//十六进制明文 
	for (i = 0; i < count; ++i) {
		M[i] = plaintext[i]; 
	}
	count = strlen(keytext);
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
	count = strlen(vitext);
	for (i = 0; i < count; ++i) {
		sprintf(V+i*2,"%2X", vitext[i]);
	}
//	printf("%s\n",V);
	count = strlen(M);
	int Flag = count/16;//分组个数
	char DM[Flag][17];
	char DC[Flag][17];
	k = 0; 
	for(i=0;i<Flag;++i){
		for(j=0;j<16;++j){
			DM[i][j] = M[k];
			++k;
		}
		DM[i][j] = '\0';
	}
	
	*ciphertext=(char*)malloc(sizeof(char)*count*4);
	char*M1 = malloc(sizeof(char)*16);
	char*C1 = malloc(sizeof(char)*64);
	int TAG = 1600;
	begintime2 = clock();
	for(z=0;z<TAG;++z){
		for(i=0;i<Flag;++i){														
			M1 = DM[i];
			DESEk(M1,K,ciphertext);
			memcpy(VM,*ciphertext,64);
			VM[64] = '\0';
//			printf("%d\n%d\n",strlen(VM),strlen(V));
			VM1 = mvXor(VM,V);
			memcpy(DC[i],VM1,16);
			DC[i][16] = '\0';
			memcpy(V,M1,16); 
		}
		printf("第%d次解密\n",z);	
	} 
	endtime2 = clock();
	char CI[count*4+1];
	k = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<16;++j){
			CI[k] = DC[i][j];
			++k;
		}
	}
	CI[k] = '\0';
	*ciphertext = CI;
	printf("密文：%s\n",*ciphertext);
}
void CFBd(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext){
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	const int s = 8;
	int b = 16;
	int Flag = 0;
	char *VM=malloc(20);
	char rs[65];
	char word[17];
	int temp;
	int i,j,k = 0;
	int mc = 0;
	int count = strlen(plaintext);
	char M[count+1];//十六进制明文 
	for (i = 0; i < count; ++i) {
		M[i] = plaintext[i]; 
	}
	count = strlen(keytext);
	char K[count*2+1];
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
	count = strlen(vitext);
	char V[count*2+1];//初始向量的十六进制序列 
	for (i = 0; i < count; ++i) {
		sprintf(V+i*2,"%2X", vitext[i]);
	}
	/*十六进制字符转为十进制数值*/
	mc = strlen(M);//十六进制明文总长度 
	int tDP[mc+1];
	printf("模式中十六进制明文的总大小为：%d个字符",mc);
	for(i=0;i<mc;++i){
		switch(M[i]){
			case '0':
				tDP[i] = 0;
				break;
			case '1':
				tDP[i] = 1;
				break;
			case '2':
				tDP[i] = 2;
				break;
			case '3':
				tDP[i] = 3;
				break;			
			case '4':
				tDP[i] = 4;
				break;
			case '5':
				tDP[i] = 5;
				break;			
			case '6':
				tDP[i] = 6;
				break;
			case '7':
				tDP[i] = 7;
				break;			
			case '8':
				tDP[i] = 8;
				break;
			case '9':
				tDP[i] = 9;
				break;			
			case 'A':
				tDP[i] = 10;
				break;
			case 'B':
				tDP[i] = 11;
				break;			
			case 'C':
				tDP[i] = 12;
				break;
			case 'D':
				tDP[i] = 13;
				break;			
			case 'E':
				tDP[i] = 14;
				break;
			case 'F':
				tDP[i] = 15;
				break;
		}
	}
	char BM[mc*4+1]; 
	count = 0;
	for(i=0;i<mc;++i){
		temp = tDP[i];
		for(j=0;j<4;++j){
			BM[count] = HX[temp][j];
			++count;			
		}
	}
	BM[mc*4] = '\0'; 
	//以上得到128位二进制字符串BM 
	Flag = (strlen(M)*4)/s;//分组个数 
	char DM[Flag][s+1];//总明文 
	char DC[Flag][s+1];//总密文 
	int cd[65];//进制转化的辅助 
//	printf("%s\n%s\n%s\n%s\n",plaintext,keytext,M,K);
		//将明文分组 
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			DM[i][j] = BM[count];
			count++;
		}
		DM[i][j] = '\0';
	}
	//printf("%s%s\n",M1,M2);
	*ciphertext=(char*)malloc(sizeof(char)*mc*4);
	//CFB模式
	begintime2=clock(); 
	VM = V; //VM类似于移位寄存器 
	int TAG;
	for(TAG=0;TAG<1600;++TAG){

		for(i=0;i<Flag;++i){
			DESEk(VM,K,ciphertext);
			memcpy(rs,*ciphertext,s*2);//加密结果放入选择寄存器
			for(j=0;j<s;++j){
				if(DM[i][j]==rs[j]){
					DC[i][j]='0';
				}
				else{
					DC[i][j]='1'; 
				}
			}
			DC[i][s]='\0';
			if(i<Flag-1){
				//移位寄存器左移s位 
				for(j=0;j<64-s;++j){
					DV[j] = DV[j+s];
				}
				//将上一轮s位密文加入 
				for(j=0;j<s;++j){
					DV[64-s+j] = DM[i][j];
				}
				//在将DV化为十六进制序列。
				//二进制字符转数值存储
				for(j=0;j<64;++j){
					cd[j] = DV[j]-48;
				}
				//二进制数值转十六进制字符 cd为二进制数值序列 
				int w=0;
				count = 0;
				for(j=0;j<16;++j){
					w=0;
					for(k=0;k<4;++k){
						w+=cd[count++]*pow(2,3-k);
					}
					sprintf(VM+j,"%X",w);
				}
//				printf("%s",VM);	
			}			
		}
		printf("第%d次解密\n",TAG);
	}
	endtime2=clock();
	char CI[8*Flag+1];
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			CI[count++] = DC[i][j];
		}
	}
	CI[8*Flag] = '\0';
	*ciphertext = CI;
	printf("明文：%s\n",*ciphertext);	
} 
void OFBd(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~

	const int s = 8;
	int b = 16;
	int Flag = 0;
	char *VM=malloc(20);
	char rs[65];
	char word[17];
	int temp;
	int i,j,k = 0;
	int mc = 0;
	int count = strlen(plaintext);
	char M[count+1];//十六进制明文 
	for (i = 0; i < count; ++i) {
		M[i] = plaintext[i]; 
	}
	count = strlen(keytext);
	char K[count*2+1];
	for (i = 0; i < count; ++i) {
		sprintf(K+i*2,"%2X", keytext[i]);
	}
	count = strlen(vitext);
	char V[count*2+1];//初始向量的十六进制序列 
	for (i = 0; i < count; ++i) {
		sprintf(V+i*2,"%2X", vitext[i]);
	}
	/*十六进制字符转为十进制数值*/
	mc = strlen(M);//十六进制明文总长度 
	int tDP[mc+1];
	printf("模式中十六进制明文的总大小为：%d个字符",mc);
	for(i=0;i<mc;++i){
		switch(M[i]){
			case '0':
				tDP[i] = 0;
				break;
			case '1':
				tDP[i] = 1;
				break;
			case '2':
				tDP[i] = 2;
				break;
			case '3':
				tDP[i] = 3;
				break;			
			case '4':
				tDP[i] = 4;
				break;
			case '5':
				tDP[i] = 5;
				break;			
			case '6':
				tDP[i] = 6;
				break;
			case '7':
				tDP[i] = 7;
				break;			
			case '8':
				tDP[i] = 8;
				break;
			case '9':
				tDP[i] = 9;
				break;			
			case 'A':
				tDP[i] = 10;
				break;
			case 'B':
				tDP[i] = 11;
				break;			
			case 'C':
				tDP[i] = 12;
				break;
			case 'D':
				tDP[i] = 13;
				break;			
			case 'E':
				tDP[i] = 14;
				break;
			case 'F':
				tDP[i] = 15;
				break;
		}
	}
	char BM[mc*4+1]; 
	count = 0;
	for(i=0;i<mc;++i){
		temp = tDP[i];
		for(j=0;j<4;++j){
			BM[count] = HX[temp][j];
			++count;			
		}
	}
	BM[mc*4] = '\0'; 
	//以上得到128位二进制字符串BM 
	Flag = (strlen(M)*4)/s;//分组个数 
	char DM[Flag][s+1];//总明文 
	char DC[Flag][s+1];//总密文 
	int cd[65];//进制转化的辅助 
//	printf("%s\n%s\n%s\n%s\n",plaintext,keytext,M,K);
		//将明文分组 
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			DM[i][j] = BM[count];
			count++;
		}
		DM[i][j] = '\0';
	}
	//printf("%s%s\n",M1,M2);
	*ciphertext=(char*)malloc(sizeof(char)*mc*4);
	//CFB模式 
	begintime2=clock();
	VM = V; //VM类似于移位寄存器 
	int TAG;
	for(TAG=0;TAG<1600;++TAG){// TAG = (5*2^20*20*20)/2^16

		for(i=0;i<Flag;++i){
			DESEk(VM,K,ciphertext);
			memcpy(rs,*ciphertext,s*2);//加密结果放入选择寄存器
			for(j=0;j<s;++j){
				if(DM[i][j]==rs[j]){
					DC[i][j]='0';
				}
				else{
					DC[i][j]='1'; 
				}
			}
			DC[i][s]='\0';
			if(i<Flag-1){
				//移位寄存器左移s位 
				for(j=0;j<64-s;++j){
					DV[j] = DV[j+s];
				}
				//将上一轮s位密文加入 
				for(j=0;j<s;++j){
					DV[64-s+j] = rs[j];
				}
				//在将DV化为十六进制序列。
				//二进制字符转数值存储
				for(j=0;j<64;++j){
					cd[j] = DV[j]-48;
				}
				//二进制数值转十六进制字符 cd为二进制数值序列 
				int w=0;
				count = 0;
				for(j=0;j<16;++j){
					w=0;
					for(k=0;k<4;++k){
						w+=cd[count++]*pow(2,3-k);
					}
					sprintf(VM+j,"%X",w);
				}
//				printf("%s",VM);	
			}			
		}
		printf("第%d次解密\n",TAG);
	}
	endtime2=clock();
	char CI[8*Flag+1];
	count = 0;
	for(i=0;i<Flag;++i){
		for(j=0;j<s;++j){
			CI[count++] = DC[i][j];
		}
	}
	CI[8*Flag] = '\0';
	*ciphertext = CI;
	printf("明文：%s\n",*ciphertext);
}

int main() {
	/*
	-p plainfile 指定明文文件的位置和名称
	-k keyfile  指定密钥文件的位置和名称
	-v vifile  指定初始化向量文件的位置和名称
	-m mode  指定加密的操作模式
	-c cipherfile 指定密文文件的位置和名称。
	
	*/
	plainfile = "des_plain.txt"; 
	keyfile = "des_key.txt";
	vifile = "des_iv.txt";
	mode = "ECB";
	cipherfile = "des_Cipher.txt";
	if (plainfile == NULL || keyfile == NULL || mode == NULL || cipherfile == NULL) {
		print_usage();
	}

	if (strcmp(mode, "ECB") != 0 && vifile == NULL) {
		print_usage();
	}

	printf("解析参数完成！\n");
	printf("参数为明文文件的位置和名称:%s\n", plainfile);
	printf("参数为密钥文件的位置和名称:%s\n", keyfile);
	if (strcmp(mode, "ECB") != 0) {
		printf("参数为初始化向量文件文件的位置和名称:%s\n", vifile);
	}
	printf("参数为密文文件的位置和名称:%s\n", cipherfile);
	printf("参数为加密的模式:%s\n", mode);

	printf("现在开始读取文件！\n");

	printf("读取明文文件...\n");
	bool read_result = readfile2memory(plainfile, &plaintext);
	if (read_result == false) {
		printf("读取明文文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取明文文件成功！\n");

	printf("读取密钥文件...\n");
	read_result = readfile2memory(keyfile, &keytext);
	if (read_result == false) {
		printf("读取密钥文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取密钥文件成功！\n");

	if (strcmp(mode, "ECB") != 0) {
		printf("读取初始向量文件...\n");
		read_result = readfile2memory(vifile, &vitext);
		if (read_result == false) {
			printf("读取初始向量文件失败，请检查路径及文件是否存在\n");
			exit(-1);
		}
		printf("读取初始向量文件成功！\n");
	}

	if (strcmp(mode, "ECB") == 0) {
		puts("开始加密"); 
		ciphertext = (char*)malloc(sizeof(char)*128);
		ECB(plaintext, keytext, &ciphertext);
	}
	else if (strcmp(mode, "CBC") == 0) {
		ciphertext = (char*)malloc(sizeof(char)*128);
		CBC(plaintext, keytext, vitext, &ciphertext);
	}
	else if (strcmp(mode, "CFB") == 0) {
		CFB(plaintext, keytext, vitext, &ciphertext);
	}
	else if (strcmp(mode, "OFB") == 0) {
		OFB(plaintext, keytext, vitext, &ciphertext);
	}
	else {
		//不应该能到达这里
		printf("致命错误！！！\n");
		exit(-2);
	}


	if (ciphertext == NULL) {
		printf("同学，ciphertext没有分配内存哦，需要补补基础~\n失败，程序退出中...");
		exit(-1);
	}

	if (ciphertext[strlen(ciphertext)]!=NULL) {
		printf("同学，ciphertext没有以NULL为结尾哦，或者cipher弄错了，请再检查一下~\n失败，程序退出中...");
		exit(-1);
	}
	int w;
	//二进制字符转数值存储
	w = strlen(ciphertext);
	int i;
	int j;
	for(i=0;i<w;++i){
		cipher[i] = ciphertext[i]-48;
	}
	//二进制数值转十六进制字符 
	int ws=0;
	int count = 0;
	for(i=0;i<w/4;++i){
		ws=0;
		for(j=0;j<4;++j){
			ws+=cipher[count++]*pow(2,3-j);
		}
		sprintf(wordss+i,"%X",ws);
	}

	
//	printf("加解密出来的字符串为:%s\n", ciphertext);

	//ciphertext = *head;
//	printf("加解密出来的字符串为:%s\n", ciphertext);
//	printf("%d\n",strlen(ciphertext));
//	printf("%d\n",strlen(ciphertext));
	printf("加解密出来的字符串为%s\n",wordss);
	printf("16进制表示为:");
    count = strlen(wordss);
//	char* cipherhex = malloc(count * 2 + 1);
//	memset(cipherhex, 0, count * 2 + 1);
//	for (i = 0; i < count; i++) {
//		sprintf(cipherhex + i * 2, "%2X", cipher[i]);
//	}
	printf("%s\n写入文件中...\n", wordss);

	FILE* fp = fopen(cipherfile, "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", cipherfile);
		exit(-1);
	}

	int writecount=fwrite(wordss, 1, count, fp);
	if (writecount != count) {
		printf("写入文件出现故障，请重新尝试！");
		exit(-1);
	}
	ciphertext2 = (char*)malloc(sizeof(char)*128);
//	ECBd(wordss,keytext,&ciphertext2); 
//	CBCd(wordss,keytext,vitext,&ciphertext2); 
	OFBd(wordss,keytext,vitext,&ciphertext2);
	printf("恭喜你完成了该程序，请提交代码!");
	printf("\n\nCFB加密时间：%dms\n", endtime1-begintime1);
	printf("OFB解密时间：%dms\n",endtime2-begintime2);
	printf("总时间：%dms\n",endtime1-begintime1+endtime2-begintime2);
	return 0;
}
