
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 
//返回一个 char *arr[], size为返回数组的长度
char **explode(const char *delim, char source[]) {
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

void strarrprint(char **array)
{
	while (*array != NULL)
	{
		//puts(*array);
		printf("%s\n", *array);
		array++;
	}
}

int main() {
 char* msg = "('2017-01', 'abc'),('2017-02', 'def')";
char** arr = explode("),", msg);

strarrprint(array);
}