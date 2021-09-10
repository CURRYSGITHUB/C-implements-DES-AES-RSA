#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "Operation.c"
typedef uint8_t byte;
typedef uint32_t word;
byte expk[4][44];//总密钥 
const byte A0 = 0x02;
const byte A1 = 0x01;
const byte A2 = 0x01;
const byte A3 = 0x03;
char HX[16][4] = {'0','0','0','0',
				  '0','0','0','1',
				  '0','0','1','0',
				  '0','0','1','1',
				  '0','1','0','0',
				  '0','1','0','1',
				  '0','1','1','0',
				  '0','1','1','1',
				  '1','0','0','0', 
				  '1','0','0','1',
				  '1','0','1','0',
				  '1','0','1','1',
				  '1','1','0','0',
				  '1','1','0','1',
				  '1','1','1','0',
				  '1','1','1','1'};
	//S盒
const uint8_t sbox[256] = {
    	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    /*0*/ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    /*1*/ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    /*2*/ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    /*3*/ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    /*4*/ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    /*5*/ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    /*6*/ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    /*7*/ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    /*8*/ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    /*9*/ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    /*A*/ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    /*B*/ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    /*C*/ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    /*D*/ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    /*E*/ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    /*F*/ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
//Rcon
const uint8_t Rcon[11] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c};
//const uint8_t pm[] = {"Network Security"};
void strHexxor(byte*plain,byte*iv,byte*output){
	//将十六进制数值序列转换为字符串序列 
//	printf("%d\n%d",strlen(plain),strlen(iv));
//	if(strlen(plain)!=strlen(iv)){
//		puts("异或双方长度不一致");
//		return;
//	}
	int count = strlen(plain);//应该传进来一个长度才行，这样的化如果有中间0就断了 
	int i,j,k;
	byte strphex[count*2+1];
	memset(strphex, 0, count*2);
	for (i = 0; i < count; i++) {
		sprintf(strphex+i*2 , "%2x", plain[i]);
	}
	for(i=0;i<2*count;++i){
		if(strphex[i]==' '){
			strphex[i]='0';
		}
	}
	strphex[count*2]='\0';
	
//	printf("%s\n",strhex);
	count = strlen(plain);
	byte strvhex[count*2+1];
	memset(strvhex, 0, count*2);
	for (i = 0; i < count; i++) {
		sprintf(strvhex+i*2 , "%2x", iv[i]);
	}
	for(i=0;i<2*count;++i){
		if(strvhex[i]==' '){
			strvhex[i]='0';
		}
	}
	strvhex[count*2]='\0';
	//得到字符串序列strphex strvhex;
	//转为相应得二进制字符串序列
	count = strlen(strphex);
	char Bp[count*4+1];
	char Bv[count*4+1];
	int temp;
	int tDP[count+1];//十六进制明文转为十进制数值序列 	 
	/*十六进制字符转为十进制数值*/
//	printf("%s\n",strphex);
	for(i=0;i<count;++i){
		switch(strphex[i]){
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
			case 'a':
				tDP[i] = 10;
				break;
			case 'b':
				tDP[i] = 11;
				break;			
			case 'c':
				tDP[i] = 12;
				break;
			case 'd':
				tDP[i] = 13;
				break;			
			case 'e':
				tDP[i] = 14;
				break;
			case 'f':
				tDP[i] = 15;
				break;
		}
	}
 
	//转为二进制字符序列
//	printf("%c\n%c\n%c\n%c\n",HX[14][0],HX[14][1],HX[14][2],HX[14][3]);
	k = 0;
	for(i=0;i<count;++i){
		temp = tDP[i];		
		for(j=0;j<4;++j){
			Bp[k] = HX[temp][j];
			++k;
		}
	}
	Bp[count*4] = '\0';
//	printf("%s\n",strvhex);
	count = strlen(strvhex);
	for(i=0;i<count;++i){
		switch(strvhex[i]){
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
			case 'a':
				tDP[i] = 10;
				break;
			case 'b':
				tDP[i] = 11;
				break;			
			case 'c':
				tDP[i] = 12;
				break;
			case 'd':
				tDP[i] = 13;
				break;			
			case 'e':
				tDP[i] = 14;
				break;
			case 'f':
				tDP[i] = 15;
				break;
		}
	}
 
	//转为二进制字符序列
//	printf("%c\n%c\n%c\n%c\n",HX[14][0],HX[14][1],HX[14][2],HX[14][3]);
	k = 0;
	for(i=0;i<count;++i){
		temp = tDP[i];		
		for(j=0;j<4;++j){
			Bv[k] = HX[temp][j];
			++k;
		}
	}
	Bv[count*4] = '\0';
//	printf("%s\n%s\n",Bp,Bv);
	//得到两个二进制字符序列 Bp Bv
	//开始异或

	if(strlen(Bv)!=strlen(Bp)){
		puts("不匹配");
		return; 
	}
	count = strlen(Bv);
	int xorB [count];
	for(i=0;i<count;++i){
		if(Bv[i]==Bp[i]){
			xorB[i]= 0;
		}
		else{
			xorB[i]= 1;
		}
	}

	//得到异或后的二进制数值序列xorB
	//将其转为 相应十六进制数值序列
	count = strlen(plain);
	byte out[count+1];
	int u,v,w;
	for(i=0;i<count;++i){
		u=0;
		v=0;
		w=0;
		for(j=0;j<8;++j){
			if(j<4){
				temp = xorB[i*8+j];
				u += pow(2,3-j)*temp;
			}
			else{
				temp = xorB[i*8+j];
				v += pow(2,7-j)*temp;
			}
		}
		out[i] = HEX[u]*0x10 + HEX[v];
//		printf("%x ",out[i]);
	}
	out[count]='\0';

	for(i=0;i<count;++i){
		output[i] = out[i];
	}
	output[count]='\0';
}
void StringToHex(char *str, unsigned char *strhex){
	uint8_t i,cnt = 0;
	char *p = str;             //直针p初始化为指向str
	uint8_t len = strlen(str); //获取字符串中的字符个数
	while(*p != '\0') {        //结束符判断
		for (i = 0; i < len; i ++)  //循环判断当前字符是数字还是小写字符还是大写字母
		{
			if ((*p >= '0') && (*p <= '9')) //当前字符为数字0~9时
				strhex[cnt] = 0x30 + (int)(*p - '0');//转为十六进制
			
			if ((*p >= 'A') && (*p <= 'Z')) //当前字符为大写字母A~Z时
				strhex[cnt] = 0x41 + (int)(*p - 'A');//转为十六进制
			
			if ((*p >= 'a') && (*p <= 'z')) //当前字符为小写字母a~z时
				strhex[cnt] = 0x61 + (int)(*p - 'a');  //转为十六进制
			
			if(*p == ' '){
				strhex[cnt] = 0x20;
			}
			if(*p == '.'){
				strhex[cnt] = 0x2E;
			}
		
			p ++;    //指向下一个字符
			cnt ++;  
		}
	}
}
void MStringToHex(char *str, unsigned char *strhex,uint64_t len){
	uint8_t i,cnt = 0;
	char *p = str;             //直针p初始化为指向str
	while(*p != '\0') {        //结束符判断
		for (i = 0; i < len; i ++)  //循环判断当前字符是数字还是小写字符还是大写字母
		{
			if ((*p >= '0') && (*p <= '9')) //当前字符为数字0~9时
				strhex[cnt] = 0x30 + (int)(*p - '0');//转为十六进制
			
			if ((*p >= 'A') && (*p <= 'Z')) //当前字符为大写字母A~Z时
				strhex[cnt] = 0x41 + (int)(*p - 'A');//转为十六进制
			
			if ((*p >= 'a') && (*p <= 'z')) //当前字符为小写字母a~z时
				strhex[cnt] = 0x61 + (int)(*p - 'a');  //转为十六进制
			
			if(*p == ' '){
				strhex[cnt] = 0x20;
			}
			if(*p == '.'){
				strhex[cnt] = 0x2E;
			}
		
			p ++;    //指向下一个字符
			cnt ++;  
		}
	}
}
void SubBytes(const byte*plaintext,byte*output){//记得给output分配空间。可以用数组？ 
	//plaintext为明文128位十六进制数值序列
	byte state;
	int i,j = 0;
//	byte out1[17]={'\0'};
//	*output = malloc(sizeof(byte)*20);
	for(i = 0;i<16;++i){
//		printf("%x\n",plaintext[i]);
		state = plaintext[i];
//		printf("%x\n",state);
		output[i] = sbox[state];
//		printf("%x\n",output[i]);
	}
	output[16] = '\0';
//	*output = out1;
}
void ShiftRows(const byte*plaintext,byte*output){
	byte state[4][5];
	byte substate[4][5];
//	byte out1[17]={'\0'};
	int i,j,k = 0;
	for(i=0;i<4;++i){
		for(j=0;j<4;++j){
			state[j][i] = plaintext[k];
			++k;
		}
		state[i][4] = '\0';
	}
	for(i=0;i<4;++i){
		for(j=0;j<4;++j){
			if(i==0){
				substate[i][j] = state[i][j];
			}
			else if(i==1){
				substate[i][(j+3)%4] = state[i][j];
			}
			else if(i==2){
				substate[i][(j+2)%4] = state[i][j];
			}
			else if(i==3){
				substate[i][(j+1)%4] = state[i][j];
			}
		}
		substate[i][4] = '\0';
	}
	k=0;
	for(i = 0;i<4;++i){
		for(j=0;j<4;++j){
			output[k] = substate[j][i];
			++k;
		}
	}
	output[16] = '\0';	
}
void MixColumns(const byte*plaintext,byte*output){
	byte state[4][5];//明文矩阵 
	byte substate[4][5];//列混合变换后的矩阵 
//	byte out1[17]={'\0'};
	byte d0,d1,d2,d3;
	byte b0,b1,b2,b3;
	int u,v,w;
	int i,j,k = 0;
	//明文赋值到矩阵state 
	for(i=0;i<4;++i){
		for(j=0;j<4;++j){
			state[j][i] = plaintext[k];
			++k;
		}
		state[i][4] = '\0';
	}
	
	//进行四次列混合
	char dd0[9]={'\0'};
	char dd1[9]={'\0'};
	char dd2[9]={'\0'};
	char dd3[9]={'\0'};
	char xx0[9]={'\0'};
	char xx1[9]={'\0'};
	char xx2[9]={'\0'};
	char xx3[9]={'\0'};
	byte x0;
	byte x1;
	byte x2;
	byte x3;	 
	char *x0ptr = NULL;
	char *x1ptr = NULL;
	char *x2ptr = NULL;
	char *x3ptr = NULL;
	for(i=0;i<4;++i){
		//求d0 
		b0 = state[0][i];
		b1 = state[1][i];
		b2 = state[2][i];
		b3 = state[3][i];

		x0 = bytexbyte(A0,b0);
		x1 = bytexbyte(A3,b1);
		x2 = bytexbyte(A2,b2);
		x3 = bytexbyte(A1,b3);
		x0ptr = hex2b(x0);//转二进制序列 
		memcpy(xx0,x0ptr,8);
		x1ptr = hex2b(x1);
		memcpy(xx1,x1ptr,8);
		x2ptr = hex2b(x2);
		memcpy(xx2,x2ptr,8);
		x3ptr = hex2b(x3);
		memcpy(xx3,x3ptr,8);
		
		x0ptr = bxor(xx0,xx1);//异或 
		memcpy(xx0,x0ptr,8);
		x1ptr = bxor(xx2,xx3);
		memcpy(xx1,x1ptr,8);
		
		x2ptr = bxor(xx0,xx1);//得到d0 
		memcpy(dd0,x2ptr,8);
		
		//求d1 		
		b0 = state[0][i];
		b1 = state[1][i];
		b2 = state[2][i];
		b3 = state[3][i];
		
		x0 = bytexbyte(A1,b0);
		x1 = bytexbyte(A0,b1);
		x2 = bytexbyte(A3,b2);
		x3 = bytexbyte(A2,b3);
		
		x0ptr = hex2b(x0);//转二进制序列 
		memcpy(xx0,x0ptr,8);
		x1ptr = hex2b(x1);
		memcpy(xx1,x1ptr,8);
		x2ptr = hex2b(x2);
		memcpy(xx2,x2ptr,8);
		x3ptr = hex2b(x3);
		memcpy(xx3,x3ptr,8);
		
		x0ptr = bxor(xx0,xx1);//异或 
		memcpy(xx0,x0ptr,8);
		x1ptr = bxor(xx2,xx3);
		memcpy(xx1,x1ptr,8);
		
		x2ptr = bxor(xx0,xx1);//得到d1 
		memcpy(dd1,x2ptr,8);
		
		//求d2 		
		b0 = state[0][i];
		b1 = state[1][i];
		b2 = state[2][i];
		b3 = state[3][i];
		//(唯一不同)
		x0 = bytexbyte(A2,b0);
		x1 = bytexbyte(A1,b1);
		x2 = bytexbyte(A0,b2);
		x3 = bytexbyte(A3,b3);
		
		x0ptr = hex2b(x0);//转二进制序列 
		memcpy(xx0,x0ptr,8);
		x1ptr = hex2b(x1);
		memcpy(xx1,x1ptr,8);
		x2ptr = hex2b(x2);
		memcpy(xx2,x2ptr,8);
		x3ptr = hex2b(x3);
		memcpy(xx3,x3ptr,8);
		
		x0ptr = bxor(xx0,xx1);//异或 
		memcpy(xx0,x0ptr,8);
		x1ptr = bxor(xx2,xx3);
		memcpy(xx1,x1ptr,8);
		
		x2ptr = bxor(xx0,xx1);//得到d2 
		memcpy(dd2,x2ptr,8);
		
		//求d3 		
		b0 = state[0][i];
		b1 = state[1][i];
		b2 = state[2][i];
		b3 = state[3][i];
		
		x0 = bytexbyte(A3,b0);
		x1 = bytexbyte(A2,b1);
		x2 = bytexbyte(A1,b2);
		x3 = bytexbyte(A0,b3);
		
		x0ptr = hex2b(x0);//转二进制序列 
		memcpy(xx0,x0ptr,8);
		x1ptr = hex2b(x1);
		memcpy(xx1,x1ptr,8);
		x2ptr = hex2b(x2);
		memcpy(xx2,x2ptr,8);
		x3ptr = hex2b(x3);
		memcpy(xx3,x3ptr,8);
		
		x0ptr = bxor(xx0,xx1);//异或 
		memcpy(xx0,x0ptr,8);
		x1ptr = bxor(xx2,xx3);
		memcpy(xx1,x1ptr,8);
		
		x2ptr = bxor(xx0,xx1);//得到d1 
		memcpy(dd3,x2ptr,8);
		
		//得到一列的输出dd0、dd1、dd2、dd3(是二进制字符串)
		//将所得到的二进制字符串序列转为相应的十六进制数值 
		//1
		u = 0;
		v = 0;
		w = 0;
		for(u=0;u<8;++u){
			if(u<4){
				if(dd0[u]=='1'){
					v += pow(2,3-u);
				}
			}
			else{
				if(dd0[u]=='1'){
					w += pow(2,7-u);
				}
			}
		}
		substate[0][i] = HEX[v]*0x10 + HEX[w];
		//2
		u = 0;
		v = 0;
		w = 0;
		for(u=0;u<8;++u){
			if(u<4){
				if(dd1[u]=='1'){
					v += pow(2,3-u);
				}
			}
			else{
				if(dd1[u]=='1'){
					w += pow(2,7-u);
				}
			}
		}
		substate[1][i] = HEX[v]*0x10 + HEX[w];
		//3
		u = 0;
		v = 0;
		w = 0;
		for(u=0;u<8;++u){
			if(u<4){
				if(dd2[u]=='1'){
					v += pow(2,3-u);
				}
			}
			else{
				if(dd2[u]=='1'){
					w += pow(2,7-u);
				}
			}
		}
		substate[2][i] = HEX[v]*0x10 + HEX[w];
		//4
		u = 0;
		v = 0;
		w = 0;
		for(u=0;u<8;++u){
			if(u<4){
				if(dd3[u]=='1'){
					v += pow(2,3-u);
				}
			}
			else{
				if(dd3[u]=='1'){
					w += pow(2,7-u);
				}
			}
		}
		substate[3][i] = HEX[v]*0x10 + HEX[w];	
	}
	//赋给output 
	k=0;
	for(i = 0;i<4;++i){
		for(j=0;j<4;++j){
			output[k] = substate[j][i];
			++k;
		}
	}
	output[16] = '\0';
}
void AddRoundKey(const byte*plaintext,const byte* inputkey, byte*output){//plaintext和inputkey都是十六进制数值 
	byte inputk[17]={'\0'};
	byte statek[4][5];
	byte cipher[17]; 
	byte a,b,c;
	char *pa = NULL;
	char tpa[9];
	char *pb = NULL;
	char tpb[9];
	char tpc[9];
	int i,j,k = 0;
	int u,v,w = 0;

	for(i=0;i<16;++i){
		a = inputkey[i];
		b = plaintext[i];
//		printf("%x\n%x",a,b);
		pa = hex2b(a);
		memcpy(tpa,pa,8);
//		printf("%s",tpa);
		tpa[8] = '\0';
		pb = hex2b(b);
		memcpy(tpb,pb,8);
		//异或 
		pa = bxor(tpa,tpb);
		memcpy(tpc,pa,8);
		//将tpc中的八位二进制字符串转化为十六进制数值，保存在cipher中； 
		u = 0;
		v = 0;
		w = 0;
		for(u=0;u<8;++u){
			if(u<4){
				if(tpc[u]=='1'){
					v += pow(2,3-u);
				}
			}
			else{
				if(tpc[u]=='1'){
					w += pow(2,7-u);
				}
			}
		}
		output[i] = HEX[v]*0x10 + HEX[w];
//		puts("");
//		printf("%x ",cipher[i]);	 
	}
	output[16] = '\0';
//	puts("");
//	*output = cipher;	
}
void KeyExpansion(const byte*key){
	int i,j,k=0;
	int u,v,w=0;
	byte q1,q2,q3,q4;//前一组子密钥的第一列 
	byte k1,k2,k3,k4;//前一组子密钥的最后列 
	byte r1,r2,r3,r4;//rcon[]
	//用于异或操作 
	char *pa = NULL;
	char *pb = NULL;
	char tpa[9];
	char tpb[9];
	char tpc[9];
	char tpd[9]; 
	
	char tpe[9];
	char tpf[9];
	char tpg[9];
	char tph[9]; 
	
	char bpa[9];
	
	byte temp;
	int flag = 0;
	int count = 0;
	for(i=0;i<11;++i){
		if(flag==0){
			for(j=0;j<4;++j){
				for(k=0;k<4;++k){
					expk[k][j] = key[count];
					++count;
				}
			}
			flag = 1;//表示第一轮结束 
		}
		else if(flag == 1){
			//上一组子密钥的第一列密钥赋值给q序列 
			q1 = expk[0][4*(i-1)];
			q2 = expk[1][4*(i-1)];
			q3 = expk[2][4*(i-1)];
			q4 = expk[3][4*(i-1)];
			//上一组子密钥的最后一列密钥赋值给k序列
			k1 = expk[0][4*i-1]; 
			k2 = expk[1][4*i-1];
			k3 = expk[2][4*i-1];
			k4 = expk[3][4*i-1];
			//得到rcon序列
			r1 = Rcon[i-1];
//			printf("%x",r1);
			r2 = 0x00;
			r3 = 0x00;
			r4 = 0x00;
			
			//换位操作；
			temp = k1;
			k1 = k2;
			k2 = k3;
			k3 = k4;
			k4 = temp; 
			
			//s盒置换操作
			k1 = sbox[k1];
			k2 = sbox[k2];
			k3 = sbox[k3];
			k4 = sbox[k4];
			
			//异或操作
			//分别转二进制; 
			pa = hex2b(q1);
			memcpy(tpa,pa,8);
			pa = hex2b(q2);
			memcpy(tpb,pa,8);
			pa = hex2b(q3);
			memcpy(tpc,pa,8);
			pa = hex2b(q4);
			memcpy(tpd,pa,8);
			
			pa = hex2b(k1);
			memcpy(tpe,pa,8);
			pa = hex2b(k2);
			memcpy(tpf,pa,8);
			pa = hex2b(k3);
			memcpy(tpg,pa,8);
			pa = hex2b(k4);
			memcpy(tph,pa,8);
			
			//异或一个赋值一个 
			//1 
			pb = bxor(tpa,tpe);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q1 = HEX[v]*0x10 + HEX[w];
			//2 
			pb = bxor(tpb,tpf);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q2 = HEX[v]*0x10 + HEX[w];
			//3
			pb = bxor(tpc,tpg);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q3 = HEX[v]*0x10 + HEX[w];
			//4
			pb = bxor(tpd,tph);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q4 = HEX[v]*0x10 + HEX[w];
			
			//得到k序列和q序列异或后的序列q 
			//与rcon异或 
			pa = hex2b(r1);
			memcpy(tpa,pa,8);
			pa = hex2b(q1);
			memcpy(tpb,pa,8);
			pb = bxor(tpa,tpb);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q1 = HEX[v]*0x10 + HEX[w];
			
			//装入矩阵
//			printf("%x",q1);
			expk[0][4*i] = q1;
			expk[1][4*i] = q2;
			expk[2][4*i] = q3;
			expk[3][4*i] = q4;
			
			//将其余三列装入
			//一 
			q1 = expk[0][4*i-3];
			q2 = expk[1][4*i-3];
			q3 = expk[2][4*i-3];
			q4 = expk[3][4*i-3];
			
			k1 = expk[0][4*i];
			k2 = expk[1][4*i];
			k3 = expk[2][4*i];
			k4 = expk[3][4*i];
			
			//异或操作
			//分别转二进制; 
			pa = hex2b(q1);
			memcpy(tpa,pa,8);
			pa = hex2b(q2);
			memcpy(tpb,pa,8);
			pa = hex2b(q3);
			memcpy(tpc,pa,8);
			pa = hex2b(q4);
			memcpy(tpd,pa,8);
			
			pa = hex2b(k1);
			memcpy(tpe,pa,8);
			pa = hex2b(k2);
			memcpy(tpf,pa,8);
			pa = hex2b(k3);
			memcpy(tpg,pa,8);
			pa = hex2b(k4);
			memcpy(tph,pa,8);
			
			//异或一个赋值一个 
			//1 
			pb = bxor(tpa,tpe);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q1 = HEX[v]*0x10 + HEX[w];
			//2 
			pb = bxor(tpb,tpf);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q2 = HEX[v]*0x10 + HEX[w];
			//3
			pb = bxor(tpc,tpg);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q3 = HEX[v]*0x10 + HEX[w];
			//4
			pb = bxor(tpd,tph);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q4 = HEX[v]*0x10 + HEX[w];
			
			expk[0][4*i+1] = q1;
			expk[1][4*i+1] = q2;
			expk[2][4*i+1] = q3;
			expk[3][4*i+1] = q4;
			

			//二 
			q1 = expk[0][4*i-2];
			q2 = expk[1][4*i-2];
			q3 = expk[2][4*i-2];
			q4 = expk[3][4*i-2];
			
			k1 = expk[0][4*i+1];
			k2 = expk[1][4*i+1];
			k3 = expk[2][4*i+1];
			k4 = expk[3][4*i+1];
			
			//异或操作
			//分别转二进制; 
			pa = hex2b(q1);
			memcpy(tpa,pa,8);
			pa = hex2b(q2);
			memcpy(tpb,pa,8);
			pa = hex2b(q3);
			memcpy(tpc,pa,8);
			pa = hex2b(q4);
			memcpy(tpd,pa,8);
			
			pa = hex2b(k1);
			memcpy(tpe,pa,8);
			pa = hex2b(k2);
			memcpy(tpf,pa,8);
			pa = hex2b(k3);
			memcpy(tpg,pa,8);
			pa = hex2b(k4);
			memcpy(tph,pa,8);
			
			//异或一个赋值一个 
			//1 
			pb = bxor(tpa,tpe);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q1 = HEX[v]*0x10 + HEX[w];
			//2 
			pb = bxor(tpb,tpf);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q2 = HEX[v]*0x10 + HEX[w];
			//3
			pb = bxor(tpc,tpg);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q3 = HEX[v]*0x10 + HEX[w];
			//4
			pb = bxor(tpd,tph);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q4 = HEX[v]*0x10 + HEX[w];
			
			expk[0][4*i+2] = q1;
			expk[1][4*i+2] = q2;
			expk[2][4*i+2] = q3;
			expk[3][4*i+2] = q4;
			
			//三 
			q1 = expk[0][4*i-1];
			q2 = expk[1][4*i-1];
			q3 = expk[2][4*i-1];
			q4 = expk[3][4*i-1];
			
			k1 = expk[0][4*i+2];
			k2 = expk[1][4*i+2];
			k3 = expk[2][4*i+2];
			k4 = expk[3][4*i+2];
			
			//异或操作
			//分别转二进制; 
			pa = hex2b(q1);
			memcpy(tpa,pa,8);
			pa = hex2b(q2);
			memcpy(tpb,pa,8);
			pa = hex2b(q3);
			memcpy(tpc,pa,8);
			pa = hex2b(q4);
			memcpy(tpd,pa,8);
			
			pa = hex2b(k1);
			memcpy(tpe,pa,8);
			pa = hex2b(k2);
			memcpy(tpf,pa,8);
			pa = hex2b(k3);
			memcpy(tpg,pa,8);
			pa = hex2b(k4);
			memcpy(tph,pa,8);
			
			//异或一个赋值一个 
			//1 
			pb = bxor(tpa,tpe);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q1 = HEX[v]*0x10 + HEX[w];
			//2 
			pb = bxor(tpb,tpf);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q2 = HEX[v]*0x10 + HEX[w];
			//3
			pb = bxor(tpc,tpg);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q3 = HEX[v]*0x10 + HEX[w];
			//4
			pb = bxor(tpd,tph);
			memcpy(bpa,pb,8);
			u = 0;
			v = 0;
			w = 0;
			for(u=0;u<8;++u){
				if(u<4){
					if(bpa[u]=='1'){
						v += pow(2,3-u);
					}
				}
				else{
					if(bpa[u]=='1'){
						w += pow(2,7-u);
					}
				}
			}
			q4 = HEX[v]*0x10 + HEX[w];
			
			expk[0][4*i+3] = q1;
			expk[1][4*i+3] = q2;
			expk[2][4*i+3] = q3;
			expk[3][4*i+3] = q4;
			
		}	
	}
	
}


/*int main(){
	int i,j,k = 0;
	int u,v,w=0;
	int count = 0;
	uint8_t pp[17];
	uint8_t kk[17];
	uint8_t out1[17];
	StringToHex(mmm,pp);//字符串转换为十六进制数值 
	pp[16]='\0';
//	printf("%x\n",pp[1]);
	StringToHex(kkk,kk);
	kk[16]='\0';
//	printf("%x\n",kk[0]);
	KeyExpansion(kk);//密钥扩展
//	for(i=0;i<44;i++){
//		for(j=0;j<4;++j){
//			printf("%x",expk[j][i]);
//		}
//		puts("");
//	}
	//预处理明密异或 
//	printf("%x\n",kk[0]);
//	pp[12] = 0x20;
	for(i=0;i<16;++i){
		printf("%x ",pp[i]);
	}
	puts("");
	for(i=0;i<16;++i){
		printf("%x ",kk[i]);
	}
	puts("");

	AddRoundKey(pp,kk,out1);
	memcpy(pp,out1,16);
	//前9轮
	for(i=0;i<9;++i){
		SubBytes(pp,out1);
		memcpy(pp,out1,16);
		ShiftRows(pp,out1);
		memcpy(pp,out1,16);
		MixColumns(pp,out1);
		memcpy(pp,out1,16);
		count = 0;
		for(j=0;j<4;++j){
			for(k=0;k<4;++k){
				kk[count] = expk[k][j+i*4+4];
				++count;
			}
		}
		kk[16]='\0';
		AddRoundKey(pp,kk,out1);

		memcpy(pp,out1,16);
	}

	//最后一轮加密
	SubBytes(pp,out1);
	memcpy(pp,out1,16);
	ShiftRows(pp,out1);
	memcpy(pp,out1,16);
	count=0;
	for(j=0;j<4;++j){
		for(k=0;k<4;++k){
			kk[count] = expk[k][40+j];
			++count;
		}
	}
	AddRoundKey(pp,kk,out1);
	memcpy(pp,out1,16); 

	for(i=0;i<16;++i){
		printf("%x",pp[i]);
	}
	return 0;
}*/

