#include <stdio.h>
#include <netinet/in.h>
#include <stdint.h>
int main(int argc, char* argv[])
{
	FILE* fd1 = fopen(argv[1],"r");
	FILE* fd2 = fopen(argv[2],"r");
	uint32_t a1, a2,sum; 

	fread(&a1, sizeof(uint32_t), 1, fd1);
    	fread(&a2, sizeof(uint32_t), 1,fd2);
	//a1 = a1 >> 16;
	//a2 = a2 >> 16;
	
	a1=htonl(a1);
	a2=htonl(a2);
	
	sum=a1+a2;
	
	int int_a1=a1;
	int int_a2=a2;
	
	
	printf("%d",int_a1);
	printf("(0x%x) + ",a1);
	printf("%d",int_a2);
	printf("(0x%x) = ",a2);
	printf("%d",int_a1+int_a2);
	printf("(0x%x)",a1+a2);
	fclose(fd1);
	fclose(fd2);
	return 0;
}
