#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <math.h>
typedef uint8_t byte;
typedef uint32_t word;
uint8_t HEX[17]={0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,'\0'};

	 
//将十六进制数值转换为二进制字符串，8bit 
char* hex2b(byte hex){
	char bchar[9]={'\0'};
	char temp[10];
	int i = 0;
	sprintf(temp,"%x",hex);
	if(strlen(temp)==1){
		strcat(bchar,"0000");
	}
	for(i=0;i<2;++i){
		switch(temp[i]){
			case '0':
				strcat(bchar,"0000");
				break;
			case '1':
				strcat(bchar,"0001");
				break;
			case '2':
				strcat(bchar,"0010");
				break;
			case '3':
				strcat(bchar,"0011");
				break;			
			case '4':
				strcat(bchar,"0100");;
				break;
			case '5':
				strcat(bchar,"0101");
				break;			
			case '6':
				strcat(bchar,"0110");
				break;
			case '7':
				strcat(bchar,"0111");
				break;			
			case '8':
				strcat(bchar,"1000");
				break;
			case '9':
				strcat(bchar,"1001");
				break;			
			case 'a':
				strcat(bchar,"1010");
				break;
			case 'b':
				strcat(bchar,"1011");
				break;			
			case 'c':
				strcat(bchar,"1100");
				break;
			case 'd':
				strcat(bchar,"1101");
				break;			
			case 'e':
				strcat(bchar,"1110");
				break;
			case 'f':
				strcat(bchar,"1111");
				break;
		}
	}
	return bchar; 
}
//二进制字节异或运算 
char* bxor(char *a,char *b){
	char c[9];
	int i = 0;
	for(i=0;i<8;++i){
		if(a[i]==b[i]){
			c[i] = '0';
		}
		else{
			c[i] = '1';
		}
	}
	c[8] = '\0';
	return c; 
}


//十六进制字节乘法 (返回的是十进制)
byte bytexbyte(byte a,byte b){
	// 转换为二进制
	char *Ba = NULL;
	char TBa[10] = {'\0'};
	char *Bb = NULL;
	char TBb[10] = {'\0'};
	char *tBa = NULL;
	char *tBb = NULL;
	int i,j,flag = 0;
	int x[9];//8bit对应位需要xtime的次数 
	int c[9]={100,100,100,100,100,100,100,100,100};//记录x[9]中的不为零的位置； 100为空标记 
	if(a>=b){
		flag = 0;
	}
	else{
		flag = 1;
	}
	Ba = hex2b(a);
	memcpy(TBa,Ba,8);
	Bb = hex2b(b);
	memcpy(TBb,Bb,8);
	tBa = malloc(sizeof(char)*16);
	tBb = malloc(sizeof(char)*16);
	memcpy(tBa,TBa,8);
	memcpy(tBb,TBb,8);
	j = 0;
	if(flag==0){//a>=b
	 	for(i=0;i<8;++i){
	 		if(TBb[i]=='0'){
	 			x[i] = 0;
			}
			else{
				x[i] = 7-i;
				c[j] = i;
				++j;
			}
		}
	}
	else{//b>a
		j=0;
	 	for(i=0;i<8;++i){
	 		if(TBa[i]=='0'){
	 			x[i] = 0;
			}
			else{
				x[i] = 7-i;
				c[j] = i;
				++j;
			}
		}
	}
	i = 0;
	j = 0;
	
	//开始x乘法并累记异或 
	int xtime = 0;//x乘的次数 
	int temp = 0;
	int u,v,w = 0;
	char IB[9] = {'0','0','0','1','1','0','1','1','\0'};
	char answer[9] = {'\0'};
	int answerflag = 0;
	char *tanswer=NULL;
	char *TBaptr = NULL;
	char *TBbptr = NULL;
	while(c[i]!=100){
		temp = c[i];
		xtime = x[temp];
		
		if(flag==0){//a>=b
			while(xtime!=0){
				//进行一次x乘
				if(TBa[0]=='1'){//高位为1 
					for(u=0;u<7;++u){
						TBa[u] = TBa[u+1];
					}
					TBa[u] = '0';
					TBaptr = bxor(IB,TBa);
					memcpy(TBa,TBaptr,8);						
				}
				else{//高位为0 
					//左移添0
					for(u=0;u<7;++u){
						TBa[u] = TBa[u+1];
					}
					TBa[u] = '0';
				}
				--xtime;
			}
			if(answerflag == 0){
				memcpy(answer,TBa,8);
				answer[8] = '\0';
				memcpy(TBa,tBa,8);//还原Ba 
				answerflag = 1; 
			}
			else{
				tanswer = bxor(answer,TBa);
				memcpy(answer,tanswer,8);
				answer[8] = '\0';
				memcpy(TBa,tBa,8);
			}
		}
		
		if(flag==1){//b>a
			while(xtime!=0){
				//进行一次x乘
				if(TBb[0]=='1'){//高位为1 
					for(u=0;u<7;++u){
						TBb[u] = TBb[u+1];
					}
					TBb[u] = '0';
					TBbptr = bxor(IB,TBb);
					memcpy(TBb,TBbptr,8);						
				}
				else{//高位为0 
					//左移添0
					for(u=0;u<7;++u){
						TBb[u] = TBb[u+1];
					}
					TBb[u] = '0';
				}
				--xtime;
			}
			if(answerflag == 0){
				memcpy(answer,TBb,8);
				answer[8] = '\0';
				memcpy(TBb,tBb,8);//还原Bb 
				answerflag = 1; 
			}
			else{
				tanswer = bxor(answer,TBb);
				memcpy(answer,tanswer,8);
				answer[8] = '\0';
				memcpy(TBb,tBb,8);
			}
		}
		++i;
	}
	//最终得到字节相乘结果answer，为八位二进制字符序列。
	//将二进制字符序列转化为十六进制数值
	byte answerHex;
	u = 0;
	v = 0;
	w = 0;
	for(u=0;u<8;++u){
		if(u<4){
			if(answer[u]=='1'){
				v += pow(2,3-u);
			}
		}
		else{
			if(answer[u]=='1'){
				w += pow(2,7-u);
			}
		}
	}
	answerHex = HEX[v]*0x10 + HEX[w];
	free(tBa);
	free(tBb);
	return answerHex;
}


/*int main(){
	char xx0[9]={'\0'};
	char xx1[9]={'\0'};
	char xx2[9]={'\0'};
	char xx3[9]={'\0'};
	byte a = 0x90;
	byte b = 0x90;
	byte c = 0xab;
	byte x0 = bytexbyte(0x02,0x9e);
	byte x1 = bytexbyte(0x03,0x09);
	byte x2 = bytexbyte(0x01,0x0d);
	byte x3 = bytexbyte(0x01,0x0b);	 
//	byte c = bytexbyte(a,b);
	char *x0ptr = hex2b(x0);
	strcpy(xx0,x0ptr);
	char *x1ptr = hex2b(x1);
	strcpy(xx1,x1ptr);
	char *x2ptr = hex2b(x2);
	strcpy(xx2,x2ptr);
	char *x3ptr = hex2b(x3);
	strcpy(xx3,x3ptr);
	
	x0ptr = bxor(xx0,xx1);
	strcpy(xx0,x0ptr);
	x1ptr = bxor(xx2,xx3);
	strcpy(xx1,x1ptr);
	x2ptr = bxor(xx0,xx1);
	x2ptr = strcpy(&a,x2ptr);
//	printf("%x\n%x\n%x\n%x\n",x0,x1,x2,x3);
	printf("%s\n%c",x2ptr,a);
	return 0;
}
*/
