#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include<stdlib.h>
#include<time.h> 
typedef uint8_t byte;
typedef uint32_t word;
typedef uint64_t LL;

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
byte MaxN[64] = {0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf}; 
int division(const byte*PM,const byte*N,const int n1,const int n3,byte*answer,byte*mod){
	//PM/N，n1,n3分别为PM和N的大小，也是相应的有效数个数，answer为商，mod为余数。
	//返回mod的有效数个数 
	if(n1<n3){
		puts("被除数小");
		memset(answer,0x0,64);
		memset(mod,0x0,64);
		memcpy(mod+64-n1,PM,n1);
		return n1; 
	}
	if(n1==n3){
		puts("除数数目等于被除数数目"); 
	}
	byte count[1] = {0x01};//计数器
	int i,j,k = 0;
	byte answ[n1-n3+1];
	byte temp[64];//缓存 
	byte temp1[64];//缓存 
	//缓存置0 
	for(i=0;i<64;++i){
		temp[i] = 0x00;
		temp1[i] = 0x00;
	}
	for(i=0;i<n1-n3+1;++i){
		answ[i] = 0x00;
	}
	//载入缓存
	for(i=0;i<n3;++i){
		temp[63-i] = PM[n3-1-i];
		temp1[63-i] = PM[n3-1-i];
	} 
	//开始除法
//	printf("%x",temp[63]);
	int efn3 = n3;//temp有效数位个数 (高位0);
	int s,t = 0;
	k=0;
	for(i=n3-1;i<n1;++i){
		if(efn3==n3){//两者有效位相同； 
			j = compare0x(temp,N,64,n3);//temp总大小就是64，有效位同N，为n3个 
			if(j==1){//temp大 
				while(1){
					++count[0];
					t = xmodn(N,count,MaxN,temp,n3,1,64);//此处temp保存的是 N*count 后的值，t为temp此时的有效位
					s = 64 - t;//temp的高位0数量(s一定小于等于efn3) 
					j = compare0x(temp,temp1+s,64,t);//temp1为没开始N*count前的temp值 
					if(j==1){//N*count > temp1 
						count[0]--;
						answ[k] = count[0];//倍数大了，上一轮即为合适值 
						++k;

						t = xmodn(N,count,MaxN,temp,n3,1,64);
						s = 64 - t;//高位0的个数						
						memcpy(temp,temp+s,t);
						memset(temp+t,0x0,s);
						
						efn3 = sub0x(temp1,temp,efn3,64,t);//temp1一直暂存着temp前一次操作的值 
						//memcpy进行移位取值操作 
						memcpy(temp,temp1+1,63);
						temp[63] = PM[n3-1+k];
						memcpy(temp1,temp,64);
						++efn3;
						count[0]=0x01;
						s = 0; 
						break;
					}
					else if(j==0){
						continue;
					}
					else if(j==-1){
						puts("也要注意");
						answ[k] = count[0];
						++k;
						memset(temp,0x0,64);
						temp[63] = PM[n3-1+k];
						memcpy(temp1,temp,64);
						efn3 = 1;
						count[0]=0x01;
						break; 
					}
				}		
			}
			else if(j==0){//temp小
				answ[k] = 0x0;
				++k;
				memcpy(temp1,temp+1,63);
				temp1[63] = PM[n3-1+k];
				memcpy(temp,temp1,64);
				++efn3;
			}
			else if(j==-1){//相等
				puts("注意"); 
				answ[k] = 0x1;
				++k;
				memset(temp,0x0,64);
				temp[63] = PM[n3-1+k];
				memcpy(temp1,temp,64);
				efn3 = 1;
			}
		}
		else if(efn3>n3){
			j = n3;
			while(j<efn3){
				++count[0];
				j = xmodn(N,count,MaxN,temp,n3,1,64);//此处temp保存的是 N*count 后的值，j为temp此时的有效位
			}
			if(j==efn3){
				s = 64 - j;
				j = compare0x(temp1,temp+s,64,j);//temp总大小就是64，有效位同N，为n3个 
				if(j==1){//temp1大 
					while(1){
						++count[0];
						t = xmodn(N,count,MaxN,temp,n3,1,64);//此处temp保存的是 N*count 后的值，t为temp此时的有效位
						s = 64 - t;
						j = compare0x(temp,temp1+s,64,t);//temp1为没开始N*count前的temp值 
						if(j==1){//N*count > temp1 
							count[0]--;
							answ[k] = count[0];//倍数大了，上一轮即为合适值 
							++k;
	
							t = xmodn(N,count,MaxN,temp,n3,1,64);
							s = 64 - t;//高位0的个数						
							memcpy(temp,temp+s,t);
							memset(temp+t,0,s);
							
							efn3 = sub0x(temp1,temp,efn3,64,t);//temp1一直暂存着temp前一次操作的值 
							//memcpy进行移位取值操作 
							memcpy(temp,temp1+1,63);
							temp[63] = PM[n3-1+k];
							memcpy(temp1,temp,64);
							++efn3;
							count[0]=0x01;
							s = 0; 
							break;
						}
						else if(j==0){
							continue;
						}
						else if(j==-1){
							puts("也要注意二");
							answ[k] = count[0];
							++k;
							memset(temp,0x0,64);
							temp[63] = PM[n3-1+k];
							memcpy(temp1,temp,64);
							efn3 = 1;
							count[0]=0x01;
							break; 
						}
					}		
				}
				else if(j==0){//temp1小
					count[0]--;
					answ[k] = count[0];//倍数大了，上一轮即为合适值 
					++k;

					t = xmodn(N,count,MaxN,temp,n3,1,64);
					s = 64 - t;//高位0的个数						
					memcpy(temp,temp+s,t);
					memset(temp+t,0,s);
					
					efn3 = sub0x(temp1,temp,efn3,64,t);//temp1一直暂存着temp前一次操作的值 
					//memcpy进行移位取值操作 
					memcpy(temp,temp1+1,63);
					temp[63] = PM[n3-1+k];
					memcpy(temp1,temp,64);
					++efn3;
					count[0]=0x01;
					s = 0; 
				}
				else if(j==-1){//相等
					puts("也注意"); 
					answ[k] = count[0];
					++k;
					memset(temp,0x0,64);
					temp[63] = PM[n3-1+k];
					memcpy(temp1,temp,64);
					efn3 = 1;
					count[0] = 0x01;
				}	
			}
								
			else if(j>efn3){
				--count[0];
				answ[k] = count[0];//倍数大了，上一轮即为合适值 
				++k;
				j = xmodn(N,count,MaxN,temp,n3,1,64);
				s = 64 - j;//高位0的个数						
				memcpy(temp,temp+s,j);
				memset(temp+j,0,s);
				efn3 = sub0x(temp1,temp,efn3,64,j);//temp1一直暂存着temp前一次操作的值 
				//memcpy进行移位取值操作 
				memcpy(temp,temp1+1,63);
				temp[63] = PM[n3-1+k];
				memcpy(temp1,temp,64);
				++efn3;
				count[0]=0x01;
				s = 0;	
			}
		}
		else if(efn3<n3){
			answ[k] = 0x0;
			++k;
			memcpy(temp1,temp+1,63);
			temp1[63] = PM[n3-1+k];
			memcpy(temp,temp1,64);
			++efn3;
		}
		
	}
	
	//结果中包含了PM溢出的一个尾数 
	memcpy(temp+1,temp,63);
	temp[0] = 0x00;
	efn3--; //余数的有效数位 
	
	memcpy(answer,answ,n1-n3+1);
	memcpy(mod,temp,64);
	return efn3;
}
int compare0x(const byte*output,const byte*N,const int n1,const int n3){
	//比较output和N的大小，n3为两者的个数(有效)
	//若output大，则返回1，若output小，则返回0,若相等，则返回-1 
	int i,j,k=0;
	for(i=0;i<n3;++i){
		if(output[n1-n3+i]>N[i]){
			return 1;
		}
		if(output[n1-n3+i]<N[i]){
			return 0;
		}
	}
	return -1; 
}
int sub0x(byte*output,const byte*N,const int count,const int n1, const int n3){
	//output减N，返回output的有效位个数，count为output有效位个数，n3为N的大小,n1为output的大小； 
	//默认output是大的一方，即count>n3
	if(count<n3){
		puts("不能相减");
		return; 
	}

	int cn = count;//有效位 
	int ca = n1;//总大小 
	byte out[ca];
	int i,j,k = 0;
//	printf("%d\n",ca);

	//置零,初始化存储差的数组out 
	for(i=0;i<ca;++i){
		out[i]=0x00;
	}
	//开始减法
	byte A = 0x00;//个位 
	byte C = 0x00;//借位
	int ff = 0;
	int n = n3-1;
	for(i=ca-1;i>ca-cn-1;--i){
		if(output[i]!=0){
			output[i] = output[i] - C;			
		}
		else if(output[i]==0){
			if(C==1){
				output[i] = 0x10 - C;//此处借位后，相减为f，是极大值。 
				ff = 1; 
			}
		}
		if(output[i]<N[n]){
			C=0x01;//借位 
			A = output[i]+0x10-N[n];
//			printf("%x\n",A);
		}
		if(output[i]>=N[n]){
			if(ff==1){
				C=0x01;
				ff=0;
			}
			else if(ff==0){
				C=0x00;
			}
			A = output[i]-N[n];
		}
		--n;
		if(n<0){//被减数减完了 
			out[ca-1] = A;
			ca = i;//记录最后进行减法的位 
			break;
		}
		out[ca-1] = A;
		--ca;
	}
	while(output[ca-1]==0){
		if(C==0){
			break;
		}
		if(C==1){
			A = 0x10 - C;
//			printf("%x\n",A);
			out[ca-1] = A;
			--ca;
			C=0x01;
		}
	}
	output[ca-1] = output[ca-1] - C;
	for(i=ca-1;i>-1;--i){
		A = output[i];
//		printf("%x\n",A);
		out[i] = A;
	}
	int flag=0;//记录高位有多少零 
	for(i=0;i<n1;++i){
		if(out[i]==0x00){
			++flag;
		}
		else{
			break;
		}
	}
	cn = n1 - flag;//有效数位;
	
//	for(i=0;i<ca;++i){
//		printf("%x",out[i]);
//	}
	
	//将out赋值给output
	for(i=0;i<n1;++i){
		output[i] = out[i];
	}
	return cn ;
}
int xmodn(const byte*P,const byte*M,const byte*N, byte*output, const int n1,const int n2,const int n3){//默认n1>=n2 
// 将P与M进行mod n的乘法运算，N为模数，三者都是十六进制数值，结果放在output(大小为n3)里。n1为p的十六进制位数，n2为M的位数,n3为模数的位数。最终返回output的有效位数。
	int count = n1+n2;
	byte out[count+1];
	int i,j,k=0;
	//置零,初始化存储乘积的数组out 
	for(i=0;i<count+1;++i){
		out[i]=0x00;
	}
	//开始乘法 
	byte A = 0x00;//个位 
	byte C = 0x00;//进位
	byte T = 0x00;//单个乘积
	count = n1+n2;
	byte A1 = 0x00;//个位 
	byte C1 = 0x00;//进位
	int flag = 0;//指示轮数 
	int temp = 0;//保存count值 
	for(i=n2-1;i>-1;--i){
		for(j=n1-1;j>-1;--j){
			T = P[j]*M[i];
//			printf("%x\n",T);
			A = T%0x10 + C;
//			printf("%x\n",A);
			C = T/0x10 + A/0x10;
//			printf("%x\n",C);
			A = A%0x10;
//			printf("%x\n",A);
			out[count] += A;
			temp = count; 
			while(out[count]/0x10 != 0x00){//产生进位 
//				printf("%x\n",out[count]);
				A1 = out[count]%0x10;
				C1 = out[count]/0x10;
				out[count] = A1;
				--count;
				out[count] += C1; 				
			}
			count = temp; 
			--count; 
		}
		++flag;
		 
		out[count] += C;
//		for(k=0;k<5;++k){
//			printf("%x",out[k]);
//		}
//		puts("");
		while(out[count]/0x10 != 0x00){//产生进位 
			A1 = out[count]%0x10;
			C1 = out[count]/0x10;
			out[count] = A1;
			--count;
			out[count] += C1; 				
		}
						
		A = 0x00;//个位 
		C = 0x00;//进位
		T = 0x00;//单个乘积
		count = n1+n2 - flag;
	}
	//得到原始乘积out

	i = 0;
	flag = 0;
	while(out[i]==0x00){
		++flag;
		++i;
	}
	//得到高位0的个数flag；
	count = n1 + n2 + 1 - flag;//得到原始乘积的有效位个数
	temp = count;
	byte outs[count];
	for(i=0;i<count;++i){
		outs[i] = out[flag];
		++flag;
	}
	
//	for(k=0;k<temp;++k){
//		printf("%x ",outs[k]);
//	}
//	puts("");

	//若个数大于等于模N的个数,则开始判断是否进行模运算 
	while(count>n3){
		count = sub0x(outs,N,count,temp,n3);//temp为outs的大小，count为outs的有效位。
//		for(k=0;k<temp;++k){
//			printf("%x ",outs[k]);
//		} 
		puts("go");
	}
	

	while(count==n3){
		i = compare0x(outs,N,temp,n3);//temp为outs的大小，count为outs的有效位。此处有效位同n3 
		if(i==1){//out大 
			count = sub0x(outs,N,count,temp,n3);//减去一个N，结果保存在outs中，返回outs中有效个数
		}
		if(i==0){//out小
			break; 
		}
		if(i==-1){//相等
			puts("error"); 
		}		
	}
	
	if(count<=n3){
		for(i=0;i<count;++i){
			output[n3-1-i]=outs[temp-1-i];
		}
		return count;
	} 
}


int main(){
	byte p[24] = {0x6,0x3,0x7,0x2,0x7,0x9,0x7,0x0,0x7,0x4,0x6,0xf,0x6,0x7,0x7,0x2,0x6,0x1,0x7,0x0,0x6,0x8,0x7,0x9};//63727970746F677261706879
//	printf("%d",sizeof(p));
	byte d[26] = {0x6,0x3,0xC,0x3,0x2,0x6,0x4,0xA,0x0,0xB,0xF,0x3,0xA,0x4,0xF,0xC,0x0,0xF,0xF,0x0,0x9,0x4,0x0,0x9,0x3,0x5};//63C3264A0BF3A4FC0FF0940935
	byte n[26] = {0x7,0x3,0x2,0x9,0x9,0xB,0x4,0x2,0xD,0xB,0xD,0x9,0x5,0x9,0xC,0xD,0xB,0x3,0xF,0xB,0x1,0x7,0x6,0xB,0xD,0x1}; //73299B42DBD959CDB3FB176BD1 
	unsigned long long e = 0x10001;
	char nd[104];
	int i,j,s,t= 0;
	int choice;
	int tp;
	uint64_t k = 0x0;
//	byte p[3] = {0x0,0x3,0x1};

	byte out[64];
	for(i=0;i<64;++i){
		out[i]=0x00;
	}
	//将私钥d转为二进制序列，准备使用模平方乘法 
	for(i=0;i<26;++i){
		tp = d[i];
		for(j=0;j<4;++j){
			nd[4*i+j] = HX[tp][j];
		}
	}
	
	byte tempp[26];
	memset(tempp,0x00,26);
	i = xmodn(p,p,MaxN,out,24,24,64);
	s = i;
	memcpy(out,out+64-i,i);
	memset(out+i,0x0,64-i);
	t = sizeof(n);
	byte answer[64];
	memset(answer,0x0,64);
	byte mod[64];
	memset(mod,0x0,64);
	printf("请选择相应功能（输入1，为数据加密；输入2，为数字签名。） : ");
	scanf("%d",&choice);
	puts("");
	
	if(choice == 2){
		//数字签名(模平方乘法 )
		//a=p[]
		//temmp保存上一轮的mod 
		for(k=0;k<104;++k){
			printf("第%d次\n",k); 
			if(nd[k]=='1'){
				if(k==0){
					memcpy(tempp,p,24);
					i = 24;
				}
				else{//tempp^2*p 
					//tempp平方 
					s = i;//s保存temp的有效位 
					i = xmodn(tempp,tempp,MaxN,out,s,s,64);//i保存out的有效位 
					memcpy(out,out+64-i,i);
					memset(out+i,0x0,64-i);
					//求out的mod
					i = division(out,n,i,t,answer,mod);//i保存mod的有效位
		//			printf("%x",mod[63]);
					memset(tempp,0x0,26);
					memcpy(tempp,mod+64-i,i);//tempp保存mod 
					memset(answer,0x0,64);
					memset(mod,0x0,64);
					memset(out,0x0,64);
					//*p
	
					i = xmodn(p,tempp,MaxN,out,24,i,64);//i保存out的有效位
					memcpy(out,out+64-i,i);
					memset(out+i,0x0,64-i);
					i = division(out,n,i,t,answer,mod);//i保存mod的有效位 
					memset(tempp,0x0,26);
					memcpy(tempp,mod+64-i,i);//tempp保存mod 
	
					memset(answer,0x0,64);
					memset(mod,0x0,64);
					memset(out,0x0,64);	
					//i 为 tempp的有效位 
				}
			}
			else if(nd[k]=='0'){
				if(k==0){
					tempp[0] = 0x1;
					i = 1;
				}
				else{//tempp^2
					//tempp平方 
					s = i;//s保存tempp的有效位 
					i = xmodn(tempp,tempp,MaxN,out,s,s,64);//i保存out的有效位 
					memcpy(out,out+64-i,i);
					memset(out+i,0x0,64-i);
					//求out的mod
					i = division(out,n,i,t,answer,mod);//i保存mod的有效位 
					memset(tempp,0x0,26);
					memcpy(tempp,mod+64-i,i);//tempp保存mod 
					memset(answer,0x0,64);
					memset(mod,0x0,64);
					memset(out,0x0,64);
					//i 为 tempp的有效位	
				}
			}
		}
		printf("明文：");
		for(j=0;j<24;++j){
			printf("%x",p[j]);
		}
		printf("\n私钥：  d = ");
		for(j=0;j<26;++j){
			printf("%x",d[j]);
		}
		printf("\n 大整数 n = ");
		for(j=0;j<26;++j){
			printf("%x",n[j]);
		}	 
		printf("\n数字签名结果为：  "); 
		for(j=0;j<i;++j){
			printf("%x",tempp[j]);
		} 	
	} 

		
		
	else if(choice==1){
		//数据加密 （未用模重复平方法） 
		for(k=0x0;k<e-0x1;++k){
			printf("第%d次\n",k);
			i = division(out,n,s,t,answer,mod);
			if(k == 0xffff){
				break;
			}
			memset(tempp,0x0,26);
			memcpy(tempp,mod+64-i,i);
			memset(out,0x0,64);
			s = i;
			i = xmodn(tempp,p,MaxN,out,s,24,64);
			s = i;
			memcpy(out,out+64-i,i);
			memset(out+i,0x0,64-i);
			memset(answer,0x0,64);
			memset(mod,0x0,64);
		}
		s = i;
//		printf("%d\n",i);
//		puts("");
//		for(j=0;j<s-t+1;j++){
//			printf("%x ",answer[j]);
//		}
//		puts("");
		memcpy(mod,mod+64-i,i);
		memset(mod+i,0x0,64-i);
		printf("明文：");
		for(j=0;j<24;++j){
			printf("%x",p[j]);
		}
		printf("\n公钥：e = %I64x",e);
		printf("   n = ");
		for(j=0;j<26;++j){
			printf("%x",n[j]);
		}	
		printf("\n数据加密的结果为："); 
		for(j=0;j<i;++j){
			printf("%x",mod[j]);
		} 	
	}

	return 0; 
}
