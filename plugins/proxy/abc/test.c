#include <stdio.h>
/*
 * https://github.com/erans/redissnowflake/blob/oligarch/stats.h
 * */
#include <stdlib.h>
#include "snowflake.h"
int main(){
	int region_id = 1;
	int worker_id= 2;
	snowflake_init(1,2);
	long int res = snowflake_id();
	printf("%ld\n", res);
	return 0;
}

