#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void strarrfree(char **array, int num)
{
//	char **pArray = array;

int i;
for(i=0;i<num;i++){
//	while (*array != NULL){
    printf("free %d\n", i);
    free(array[i]);
//	free(*array);
//        *array = NULL;
//		array++;
	}
//	free(*array);
    free(array);
}

void strarrprint(char **array, int num)
{
//	while (*array != NULL)
//	{
//		//puts(*array);
//		printf("result %s\n", *array);
//		array++;
//	}

    int i;
    for(i=0;i<num;i++){
        printf("result %s\n", array[i]);
    }
}

char **explode(const char *delim, char source[], int* num) {
	int i = 0;
	char *pch;
	char **array;
	int n = 0; //保存字符数组个数
	int size = 0;//保存当前字符串长度
	int count = 0;
	
	char *tmp;
	tmp = source;
	while( (tmp = strstr(tmp, delim)) != NULL ){
		n++;
		tmp += strlen(delim);
	}

    *num = n;

	array = (char **)malloc( (n + 1) * sizeof(char *) );
	if(array == NULL){
		printf("malloc error...\n");
		return NULL;
	}
	
	do {
		if((i > 0) || (count > 0)) {
			memmove(source, pch, strlen(source) - (pch - source) + 1);
		}
		pch = strstr(source, delim);
		if(pch == NULL) {
			size = strlen(source);
			if(size == 0){
				count++;
				continue;
			}
			array[i] = (char *)malloc( size * sizeof(char) + 1 );
			if(array[i] == NULL){
				printf("malloc error...\n");
				count++;
				continue;
			}
			strncpy(array[i], source, strlen(source));
		} else {
			size = pch - source;
			if(size == 0){
				pch += strlen(delim);
				count++;
				continue;
			}
			array[i] = (char *)malloc( size * sizeof(char) + 1 );
			if(array[i] == NULL){
				printf("malloc error...\n");
				break;
			}
			strncpy(array[i], source, pch-source);
			pch += strlen(delim);
		}
		count++;
		i++;
	} while (pch != NULL);

	return array;
} 

int time_to_str() {
     time_t t;
    struct tm *p;
    t=1384936600;
    p=gmtime(&t);
    char s[100];
    strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", p);
}

int strtotime(char datetime[]) {  
    struct tm tm_time;  
    int unixtime;  
    strptime(datetime, "%Y", &tm_time);  
    //strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm_time);  
       
    unixtime = mktime(&tm_time);  
    return unixtime;  
} 

int main(int argc, char **argv)
{
    
	char **array;
	char *de = "),";
	char str[] = "('2018-01','a'),('2018-02','b'),('2018-03','b')";
	printf("source string: %s\n\n", str);

    int num = 0;
	array = explode(de, str, &num);
	if(array == NULL){
		printf("explode error!\n");
		return -1;
	}
strarrprint(array, num+1);
printf("%d\n", num);
	strarrfree(array, num+1);
	return 0;
}