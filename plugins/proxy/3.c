/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */
 

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/** 
 * @page page-plugin-proxy Proxy plugin
 *
 * The MySQL Proxy implements the MySQL Protocol in its own way. 
 *
 *   -# connect @msc
 *   client, proxy, backend;
 *   --- [ label = "connect to backend" ];
 *   client->proxy  [ label = "INIT" ];
 *   proxy->backend [ label = "CONNECT_SERVER", URL="\ref proxy_connect_server" ];
 * @endmsc
 *   -# auth @msc
 *   client, proxy, backend;
 *   --- [ label = "authenticate" ];
 *   backend->proxy [ label = "READ_HANDSHAKE", URL="\ref proxy_read_handshake" ];
 *   proxy->client  [ label = "SEND_HANDSHAKE" ];
 *   client->proxy  [ label = "READ_AUTH", URL="\ref proxy_read_auth" ];
 *   proxy->backend [ label = "SEND_AUTH" ];
 *   backend->proxy [ label = "READ_AUTH_RESULT", URL="\ref proxy_read_auth_result" ];
 *   proxy->client  [ label = "SEND_AUTH_RESULT" ];
 * @endmsc
 *   -# query @msc
 *   client, proxy, backend;
 *   --- [ label = "query result phase" ];
 *   client->proxy  [ label = "READ_QUERY", URL="\ref proxy_read_query" ];
 *   proxy->backend [ label = "SEND_QUERY" ];
 *   backend->proxy [ label = "READ_QUERY_RESULT", URL="\ref proxy_read_query_result" ];
 *   proxy->client  [ label = "SEND_QUERY_RESULT", URL="\ref proxy_send_query_result" ];
 * @endmsc
 *
 *   - network_mysqld_proxy_connection_init()
 *     -# registers the callbacks 
 *   - proxy_connect_server() (CON_STATE_CONNECT_SERVER)
 *     -# calls the connect_server() function in the lua script which might decide to
 *       -# send a handshake packet without contacting the backend server (CON_STATE_SEND_HANDSHAKE)
 *       -# closing the connection (CON_STATE_ERROR)
 *       -# picking a active connection from the connection pool
 *       -# pick a backend to authenticate against
 *       -# do nothing 
 *     -# by default, pick a backend from the backend list on the backend with the least active connctions
 *     -# opens the connection to the backend with connect()
 *     -# when done CON_STATE_READ_HANDSHAKE 
 *   - proxy_read_handshake() (CON_STATE_READ_HANDSHAKE)
 *     -# reads the handshake packet from the server 
 *   - proxy_read_auth() (CON_STATE_READ_AUTH)
 *     -# reads the auth packet from the client 
 *   - proxy_read_auth_result() (CON_STATE_READ_AUTH_RESULT)
 *     -# reads the auth-result packet from the server 
 *   - proxy_send_auth_result() (CON_STATE_SEND_AUTH_RESULT)
 *   - proxy_read_query() (CON_STATE_READ_QUERY)
 *     -# reads the query from the client 
 *   - proxy_read_query_result() (CON_STATE_READ_QUERY_RESULT)
 *     -# reads the query-result from the server 
 *   - proxy_send_query_result() (CON_STATE_SEND_QUERY_RESULT)
 *     -# called after the data is written to the client
 *     -# if scripts wants to close connections, goes to CON_STATE_ERROR
 *     -# if queries are in the injection queue, goes to CON_STATE_SEND_QUERY
 *     -# otherwise goes to CON_STATE_READ_QUERY
 *     -# does special handling for COM_BINLOG_DUMP (go to CON_STATE_READ_QUERY_RESULT) 

 */

#ifdef HAVE_SYS_FILIO_H
/**
 * required for FIONREAD on solaris
 */
#include <sys/filio.h>
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <execinfo.h>

#include <errno.h>

#include <glib.h>
#include <pthread.h>

#ifdef HAVE_LUA_H
/**
 * embedded lua support
 */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#endif

/* for solaris 2.5 and NetBSD 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif


#include <mysqld_error.h> /** for ER_UNKNOWN_ERROR */

#include <math.h>
#include <openssl/evp.h>

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"
#include "network-mysqld-lua.h"

#include "network-conn-pool.h"
#include "network-conn-pool-lua.h"

#include "sys-pedantic.h"
#include "network-injection.h"
#include "network-injection-lua.h"
#include "network-backend.h"
#include "glib-ext.h"
#include "lua-env.h"

#include "proxy-plugin.h"
#include "proxy-percentile.h"
#include "proxy-sql-log.h"

#include "lua-load-factory.h"

#include "chassis-timings.h"
#include "chassis-gtimeval.h"
#include "sql-tokenizer.h"
#include "chassis-event-thread.h"
#include "chassis-filter.h"
#include "chassis-options-utils.h"



#define C(x) x, sizeof(x)-1
#define C_S(x) x, strlen(x)
#define S(x) x->str, x->len

#define PROXY_CHECK_STATE_THREAD        "check_state"
#define PROXY_CHECK_STATE_WAIT_TIMEOUT  4
#define RETRY_TIMES                     3
#define SLEEP_DELAY                     1

#define CR_UNKNOWN_ERROR        2000
#define CR_CONN_HOST_ERROR      2003
#define CR_UNKNOWN_HOST         2005
#define CR_SERVER_GONE_ERROR    2006
#define CR_OUT_OF_MEMORY        2008
#define CR_SERVER_LOST          2013
#define ER_ACCESS_DENIED_ERROR  1045

#define IS_UNSUPPORTED_COM_TYPE(type)  ((type) == COM_CHANGE_USER || \
                                         (type) == COM_SET_OPTION || \
                                         (type) == COM_STMT_CLOSE || \
                                         (type) == COM_STMT_PREPARE || \
                                         (type) == COM_STMT_EXECUTE)

static gboolean online = TRUE;
static gchar op = COM_QUERY;


typedef struct {
    guint                     port;
    volatile backend_state_t  state;
    guint64                   bkid;
    backend_type_t            type;
    gchar                     *ip;
    network_backend_t         *backend;
    gchar                     *name; 
} backend_info;

typedef struct {
    gchar* db_name;
    gchar* table_name;
    gchar* column_name;
    guint table_num;
	guint split_table_method; //1 哈希取模(int) 2 哈希取模(string) 3 time(年月) 4 区间
} db_table_t;

gint64 query_stat = 0;

typedef enum {
    TX_ISO_UNKNOWN = -1,
    TX_ISO_READ_UNCOMMITED = 0,
    TK_ISO_READ_COMMITED,
    TK_ISO_REPEATABLE_READ,
    TK_ISO_SERIAL
} tx_iso_type;

char *tx_iso_levels[]= {
    "READ-UNCOMMITTED",
    "READ-COMMITTED",
    "REPEATABLE-READ" ,
    "SERIALIZABLE"
};

char *charset[248] = {[1]="big5", [8]="latin1", [24]="gb2312", [28]="gbk",
                        [33]="utf8", [45]="utf8mb4",\
                        [63]="binary", [224]="utf8mb4"};
/* filter API */
static int filter_pre(GPtrArray *tokens, network_mysqld_con* con, gchar *sql_raw);
static void filter_post(network_mysqld_con *con, injection *inj);

static gchar *show_proxy_address(void *ex_param);
static gchar *show_charset(void *ex_param);
static gchar *show_select_where_limit(void *ex_param);
static gint assign_select_where_limit(const char *newval, void *ex_param);
static gint assign_shard_tables(const char *newval, void *ex_param);
static gchar *shard_tables_show_save(void *ex_param);
static gint add_shard_tables(chassis_plugin_config *config, gchar **shard_tables);
static int assign_check_state_conn_timeout(const char *newval, void *ex_param);
static gchar *show_check_state_conn_timeout(void *ex_param);
static int assign_check_state_interval(const char *newval, void *ex_param);
static gchar *show_check_state_interval(void *ex_param);

static int assign_check_state_retry_times(const char *newval, void *ex_param);
static gchar *show_check_state_retry_times(void *ex_param);
static int assign_check_state_sleep_delay(const char *newval, void *ex_param);
static gchar *show_check_state_sleep_delay(void *ex_param);

static int assign_table_suffix(const char *newval, void *ex_param);
static gchar *show_table_suffix(void *ex_param);
static int assign_table_prefix(const char *newval, void *ex_param);
static gchar *show_table_prefix(void *ex_param);
static void tbl_name_wrap_free(tbl_name_wrap *tnw);
static tbl_name_wrap *tbl_name_wrap_new();



/* plugin thread */
static plugin_thread_t *plugin_thread_t_new(GThread *thr);
static void plugin_thread_t_free(plugin_thread_t *plugin_threads);

/* check_state thread fn */
static void *check_state(void *user_data);

chassis_plugin_config *config = NULL;

plugin_thread_info pti[] = {
      { PROXY_CHECK_STATE_THREAD, check_state, NULL},
      { PROXY_SQL_LOG_THREAD, log_manager, NULL},
      { PROXY_PERCENTILE_THREAD, check_percentile, NULL},
      { NULL, NULL}
};

static void
init_pti(plugin_thread_info *pti, chassis *chas)
{
    gint i = 0;
    for (i = 0; pti[i].plugin_thread_names != NULL; i++) {
        if (strcmp(pti[i].plugin_thread_names, PROXY_CHECK_STATE_THREAD) == 0) {
            pti[i].thread_args = (void *)chas;
        } else if (strcmp(pti[i].plugin_thread_names, PROXY_PERCENTILE_THREAD) == 0) {
            pti[i].thread_args = (void *)(config->percentile_controller);
        } else if (strcmp(pti[i].plugin_thread_names, PROXY_SQL_LOG_THREAD) == 0) {
            pti[i].thread_args = (void *)(config->sql_log_mgr);
        }
    }
}

/*
zhangming 2018/1/12 19:54
增加一个参数gint* token_id,  因为select /delete 返回都是1
*/
guint get_table_index(GPtrArray* tokens, gint* d, gint* t, gint* token) {
    *d = *t = -1;

    sql_token** ts = (sql_token**)(tokens->pdata);
    guint len = tokens->len;

    guint i = 1, j;
    while (ts[i]->token_id == TK_COMMENT && ++i < len);
    if (i >= len) return 0;

    sql_token_id token_id = ts[i]->token_id;
	*token = token_id;

    if (token_id == TK_SQL_SELECT || token_id == TK_SQL_DELETE) {
        for (; i < len; ++i) {
            if (ts[i]->token_id == TK_SQL_FROM) {
                for (j = i+1; j < len; ++j) {
                    if (ts[j]->token_id == TK_SQL_WHERE) break;

                    if (ts[j]->token_id == TK_LITERAL) {
                        if (j + 2 < len && ts[j+1]->token_id == TK_DOT) {
                            *d = j;
                            *t = j + 2;
                        } else {
                            *t = j;
                        }

                        break;
                    }
                }

                break;
            }
        }

        return 1;
    } else if (token_id == TK_SQL_UPDATE) {
        for (; i < len; ++i) {
            if (ts[i]->token_id == TK_SQL_SET) break;

            if (ts[i]->token_id == TK_LITERAL) {
                if (i + 2 < len && ts[i+1]->token_id == TK_DOT) {
                    *d = i;
                    *t = i + 2;
                } else {
                    *t = i;
                }

                break;
            }
        }

        return 2;
    } else if (token_id == TK_SQL_INSERT || token_id == TK_SQL_REPLACE) {
        for (; i < len; ++i) {
            gchar* str = ts[i]->text->str;
            if (strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0) break;

            sql_token_id token_id = ts[i]->token_id;
            if (token_id == TK_LITERAL && i + 2 < len && ts[i+1]->token_id == TK_DOT) {
                *d = i;
                *t = i + 2;
                break;
            } else if (token_id == TK_LITERAL || token_id == TK_FUNCTION) {
                if (i == len - 1) {
                    *t = i;
                    break;
                } else {
					/*
					zhangming 2018/7/7 15:21
					只要当前元素+1是 values或( ,就是认为当前元素为表名
					*/
                    str = ts[i+1]->text->str;
                    token_id = ts[i+1]->token_id;
                    if (strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0 || token_id == TK_OBRACE || token_id == TK_SQL_SET) {
                        *t = i;
                        break;
                    }
                }
            }
        }

        return 3;
    }

    return 0;
}


/*
 zhangming 2018/1/1 22:30
 twiter snowflake id 不唯一递增生成器
*/
long int snowflake_id() {
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int millisecs = tp.tv_sec * 1000 + tp.tv_usec / 1000 - SNOWFLAKE_EPOCH;
    long int id = 0L;

    // Catch NTP clock adjustment that rolls time backwards and sequence number overflow
    if ((snowflake_global_state.seq > snowflake_global_state.seq_max ) || snowflake_global_state.time > millisecs) {
        ++app_stats.waits;
        while (snowflake_global_state.time >= millisecs) {
            gettimeofday(&tp, NULL);
            millisecs = tp.tv_sec * 1000 + tp.tv_usec / 1000 - SNOWFLAKE_EPOCH;
        }
    }

    if (snowflake_global_state.time < millisecs) {
        snowflake_global_state.time = millisecs;
        snowflake_global_state.seq = 0L;
    }


    id = (millisecs << snowflake_global_state.time_shift_bits)
            | (snowflake_global_state.region_id << snowflake_global_state.region_shift_bits)
            | (snowflake_global_state.worker_id << snowflake_global_state.worker_shift_bits)
            | (snowflake_global_state.seq++);

    if (app_stats.seq_max < snowflake_global_state.seq)
        app_stats.seq_max = snowflake_global_state.seq;

    ++app_stats.ids;
    return id;
}

//字符转unix时间戳  
int strtotime(char* datetime) {  
    struct tm tm_time;  
    int unixtime;  
   strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm_time);  
     //    strptime(datetime, "%Y", &tm_time); 
    unixtime = mktime(&tm_time);  
    return unixtime;  
}  

#define SPLIT_TABLE_TYPE_YEAR 4
#define SPLIT_TABLE_TYPE_YEAR_MONTH 5
#define SPLIT_TABLE_TYPE_YEAR_MONTH_DAY 6

int str_format(char* time, GString* result, int type) {
	struct tm tm; 
    char buf[255] = {0};
    strptime(time, "%Y-%m-%d %H:%:M:%S" , &tm);

	switch(type) {
		case 3:
			strftime(buf, sizeof(buf), "%Y", &tm);
			break;
		
		case 4:
			strftime(buf, sizeof(buf), "%Y%m", &tm);
			break;
		
		case 5:
			strftime(buf, sizeof(buf), "%Y%m%d", &tm);
			break;
		
		default:
			break;
	}

    strftime(buf, sizeof(buf), "%Y", &tm);
	g_string_append(result, buf);

	return 0;
}




void print_key_value2(gpointer key, gpointer value, gpointer user_data)
{

  
   g_log_dbproxy(g_message, " print_key_value   %s ---> %s", key, value);
}

void print_key_value(gpointer key, gpointer value, gpointer user_data)
{

    time_t t;
    struct tm *p;
    t=strtotime((char*)key);
    p=gmtime(&t);
    char s[100];
  //  strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", p);
 strftime(s, sizeof(s), "%Y", p);
    user_data = (GHashTable*)user_data;
    g_hash_table_insert(user_data, strdup(s) ,  strdup(key) );
   g_log_dbproxy(g_message, " print_key_value  %s %s ---> %s", s, key, value);
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




void print(gpointer key, gpointer value, gpointer data){
	//https://blog.csdn.net/houwei544/article/details/5981228

  g_log_dbproxy(g_message,"Here are some cities in %s: ", key);
  //g_slist_foreach((GSList*)value, (GFunc)g_printf, NULL);
	
	 GSList* list = (GSList*)value;
	 GSList* iterator = NULL;


	for (iterator = list; iterator; iterator = iterator->next) {
		g_log_dbproxy(g_message,"Current item is '%s'", iterator->data);
	}

}


typedef struct 
{ 
    char *table_split;
     char *value;

}MyData;



GArray* get_column_index(GPtrArray* tokens, gchar* table_name, gchar* column_name, guint sql_type, gint start, GArray* array, int split_table_method) {

//	GArray* get_column_index(GPtrArray* tokens, gchar* table_name, gchar* column_name, guint sql_type, gint start, GHashTable* array, int split_table_method) {
//GArray* get_column_index(GPtrArray* tokens, gchar* table_name, gchar* column_name, guint sql_type, gint start, GPtrArray* array) {
    GArray* columns = g_array_new(FALSE, FALSE, sizeof(guint));

    GHashTable* hash = g_hash_table_new(g_str_hash, g_str_equal);

  //GArray* columns_value = g_array_new(FALSE, FALSE, sizeof(guint));

    sql_token** ts = (sql_token**)(tokens->pdata);
    guint len = tokens->len;
    guint i, j, k;

    if (sql_type == 1) {
        for (i = start; i < len; ++i) {
            if (ts[i]->token_id == TK_SQL_WHERE) {
                for (j = i+1; j < len-2; ++j) {
                    if (ts[j]->token_id == TK_LITERAL && strcasecmp(ts[j]->text->str, column_name) == 0) {
                        if (ts[j+1]->token_id == TK_EQ) {
                            if (ts[j-1]->token_id != TK_DOT || strcasecmp(ts[j-2]->text->str, table_name) == 0) {
                                k = j + 2;
                                g_array_append_val(columns, k);
                                break;
                            }
                        } else if (j + 3 < len && strcasecmp(ts[j+1]->text->str, "IN") == 0 && ts[j+2]->token_id == TK_OBRACE) {
                            k = j + 3;
                            g_array_append_val(columns, k);
                            while ((k += 2) < len && ts[k-1]->token_id != TK_CBRACE) {
                                g_array_append_val(columns, k);
                            }
                            break;
                        }
                    }
                }
                break;
            }
        }
    } else if (sql_type == 2) {
        for (i = start; i < len; ++i) {
            if (ts[i]->token_id == TK_SQL_WHERE) {
                for (j = i+1; j < len-2; ++j) {
                    if (ts[j]->token_id == TK_LITERAL && strcasecmp(ts[j]->text->str, column_name) == 0) {
                        if (ts[j+1]->token_id == TK_EQ) {
                            if (ts[j-1]->token_id != TK_DOT || strcasecmp(ts[j-2]->text->str, table_name) == 0) {
                                k = j + 2;
                                g_array_append_val(columns, k);
                                break;
                            }
                        } else if (j + 3 < len && strcasecmp(ts[j+1]->text->str, "IN") == 0 && ts[j+2]->token_id == TK_OBRACE) {
                            k = j + 3;
                            g_array_append_val(columns, k);
                            while ((k += 2) < len && ts[k-1]->token_id != TK_CBRACE) {
                                g_array_append_val(columns, k);
                            }
                            break;
                        }
                    }
                }
                break;
            }
        }
    } else if (sql_type == 3) {
     

        sql_token_id token_id = ts[start]->token_id;

        if (token_id == TK_SQL_SET) {
            for (i = start+1; i < len-2; ++i) {
                if (ts[i]->token_id == TK_LITERAL && strcasecmp(ts[i]->text->str, column_name) == 0) {
                    k = i + 2;
                    g_array_append_val(columns, k);
                    break;
                }
            }
        } else {
            k = 2;
			int pos_arr[10];
			int pos2_arr[10];
            int single_insert_gap =0;
			   int single_insert_gap2 =0;
			int close_brace_pos = 0;
			int close_open_diff = 0;

            if (token_id == TK_OBRACE) {
                gint found = -1;
				int p =0;
                for (j = start+1; j < len; ++j) {
                    token_id = ts[j]->token_id;
                    if (token_id == TK_CBRACE)  {
						close_brace_pos = j;
						break;
					}
                    if (token_id == TK_LITERAL && strcasecmp(ts[j]->text->str, column_name) == 0) {
                        if (ts[j-1]->token_id != TK_DOT || strcasecmp(ts[j-2]->text->str, table_name) == 0) {
                            found = j;
							//pos_arr[p++] = (found - start +1);
                           //break;
                        }
                    }
                }
				close_open_diff = close_brace_pos - start;

				g_log_dbproxy(g_message, "find column found %d,  start %d, close_open_diff: %d %d", found, start, close_open_diff, start); 
                k = found - start + 1;
                single_insert_gap = k;
				single_insert_gap2 = k-1;
            
                 int value_pos=0;
                for (i = start; i < len; ++i) {
                    gchar* str = ts[i]->text->str;

                    if ((strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0)  ) {
                        value_pos = i;
                    }
                }
                k = value_pos - found;
            }



			
			/*
			zhangming 2018/7/7 19:42
			这个k 就是 分表字段位置与 第一个( 的相对位置
			那么 分表字段里的数据 与 value 的相对位置  和上面是一样的
				
			1         2     3      4   5              6   7        8  9         10  11                12   13      14
 			insert   into  user  (   create_time ,   name  )   values  (   "2018-06-02"  ,      "zm"   )

			第一个(, 即4的位置, 是固定的
			分表字段create_time位置是5,  第一个（往右移动一个位置，就能到达create_time,也就是5的位置, 可见其偏移量为1

			values ,即 11的位置,
			create_time字段对应的值是2018-06-02,那么 与values向右移动两个位置，就能到达2018-06-02的位置, 即加上上面的偏移量 + 1
			
			这里再加一个1, 是因为values 和 "2018-06-02" 之间还有一个 (
			*/
			int len_pos = sizeof(pos_arr)/sizeof(int);
			int m;
			int trans = k;
			int flag= 0;
			int seg = 0;

			GString* sql_new = g_string_new(&op);
            
            /*
            zhangming 2018/7/8 

            1         2    3     4  5                6   7          8  9                 10  11   12   13                14   15   16   17                18   19
            insert   into user (  create_time  )    VALUES  (  "2018-07-07"  )    ,     (     "2019-07-08"  )     ,      (    "2020-01-01"  )     ;
            这里不能len, 只能len-1
           ts[len-1]->text->str 为 最后一个 )
           
            */
            g_log_dbproxy(g_message, "YYYYYYYYYYYYYY   sql lenth %d %s", len, ts[len-1]->text->str); 

			time_t t;
			struct tm *p;
			int nums = 0;

			GString* time = NULL;
			
			int idx = 0;
			for (idx = start; idx < len; ++idx) {
				gchar* str = ts[idx]->text->str;
				if(  strcasecmp(str, "VALUES") == 0  || strcasecmp(str, "VALUE") == 0 ) {
					single_insert_gap = single_insert_gap + idx;
					break;
				} 
			}

			long int unique_id = 0;
			

			for (i = idx; i < len; ++i) {
//            for (i = start; i < len-1; ++i) {
                
				gchar* str = ts[i]->text->str;
				g_log_dbproxy(g_message, "当前数据 %s", str); 

				token_id = ts[i]->token_id;
	
//                if ((strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0) && ts[i+1]->token_id == TK_OBRACE) {

				/*
				zhangming 2018/7/9 17:18
				
				1        2      3       4  5                  6  7         8  9            10   11                             12    13   14    15   16    17                                18   19   20
				insert into user  (  create_time ,   name  )   values   (     "2018-1-1 00:00:01"  ,      "a"   )       ,       (     "2018-3-3 00:00:01"    ,     "b"    )
                 
				21   22    23                                24   25   26
 				,       (      "2018-5-5 00:00:01"     ,    "c"   )
				
				假设分表字段为create_time,

				一. 确定每组数据中create_time字段的值在整个SQL语句中的编号

					那么 values 到 create_time 的距离是 9-5 = 4

					第一个逗号, 必定和第一组数据中create_time字段对应的值 的距离也是4
					那么上面的create_time字段的值的编号为 15 - 4 = 11

					第二个逗号, 必须和第二组数据中create_time字段的值的距离也为4
					即: 第二组数据create_time字段的值 的编号为 21 - 4 = 17
					
					会发现只有两个逗号, 意味着最后一组数据 要单独处理
					对比长度即可, 知道是否为最后一组数据 
					即: 第三组数据create_time字段的值 的编号 为26 + 1 -4 = 23
					+1 是为了补救不存在的逗号
				
				二. 提取每组数据 
				

				*/
//				if ((strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0) && flag ==0 ) {
//					//逗号会有多个, 要计算values后面的逗号 
//					flag = 1;
//
//                    single_insert_gap = single_insert_gap+i;
//                    g_log_dbproxy(g_message, "########### %d", single_insert_gap); 
//					//k += i;
//               
//                    if (k < len) {
////						g_log_dbproxy(g_message, "@@@@@@@@@@@@@@ %s, %d %d", str, k, i); 
////						g_array_append_val(columns, k);
//
//                    //      g_hash_table_insert(name_score, ts[k]->text->str , sql_new->str);
//
//					}
//                    //break;
//				}
				
//				if( ! (strcasecmp(str, "VALUES") == 0  || strcasecmp(str, "VALUE") == 0 )) {
//					continue;
//				} else {
//					single_insert_gap = single_insert_gap+i;
//				}
				
			    /*
                zhangming 2018/7/9 00:35
                这里有个问题
                如果有个insert batch,那么 columns是有值的，因此要判断 GPtrArray* array这个参数，如果有值，说明 是批insert
                */
                if( 0 == nums && i+1 == len ){
                        g_log_dbproxy(g_message, "分表字段的值在整个SQL中的编号为: %d", single_insert_gap); 
						g_array_append_val(columns, single_insert_gap);
						break;
                }
				
				/*
				batch insert 的SQL特征为 (), (), ()
				逗号后面必须有一个左括号

				因为insert into 表名 (columnA, columnB)  ...
				这里也有个逗号, 但没有左括号

				i+1 == len  就是 batch insert 中最后一组数组
				*/
				if (  ( strcasecmp(str, ",") == 0 && strcasecmp(ts[i+1]->text->str, "(") == 0 )  || i+1 == len) {
					nums++;

					if(i+1 ==len){
						seg = i+1 - k;
						g_string_append_c(sql_new, ')');
					}else{
						 seg = i - k;
					}

					/*
					ts[seg]->text->str 分表字段对应的值
					*/
					time = g_string_new(NULL);
					str_format(ts[seg]->text->str, time, split_table_method);


                    g_log_dbproxy(g_message, "分表字段的值为: %s, 编号为: %d= %d-%d, 该逗号之前分组中的数据为: %s" , ts[seg]->text->str, seg, i , k, sql_new->str);
					
					/*
					组合分表名称
					*/
					char table_depart[200] = {0};
                    sprintf(table_depart, "%s_%s", table_name, time->str);
					g_string_free(time, TRUE);

					/*
					逗号前面这组数据
					*/
                    g_log_dbproxy(g_message, "分表名称: %s, 值: %s", table_depart, sql_new->str);
			//g_hash_table_insert(array, strdup(table_depart),  g_slist_append(g_hash_table_lookup(array, table_depart), strdup(sql_new->str)));

					g_string_free(sql_new, TRUE);

					sql_new = g_string_new(&op);
	
//				    g_log_dbproxy(g_message, "!!!!!!!!!! %d = %d + %d ", seg, i,  trans); 
					
					/*
					批量插入的columns, 只为和单条insert 区分开
					*/
					g_array_append_val(columns, seg);

				} else if (  i == len-1) {
//                        g_string_append_printf(sql_new, "%s", str);
//					    g_log_dbproxy(g_message, "ffffffffffffffffffffffff %s %d %s", sql_new->str, len,   ts[len-1]->text->str); 
                    //    g_array_append_val(columns_value, sql_new);
                }
                else {

                    if(strcmp(str, ",") == 0 ||strcmp(str, "(") == 0 || strcmp(str, ")") == 0 ) {
						/*
						如果当前值为 , ( ) 则不需要加引号
						同时, 如果当前值为左括号(,  插入snowflake_id
						*/
                        g_string_append_printf(sql_new , "%s", str);
						if(strcmp(str, "(") == 0) {
							//分表中的 uuid
							unique_id = snowflake_id();
							g_string_append_printf(sql_new, "%ld, ", unique_id);
							
							char msg[100] = {0};
							g_log_dbproxy(g_message, "bbbbbbbbbbbbbbbbbb "); 
							sprintf(msg, "%d_%d_%d", i + single_insert_gap2, i, i + close_open_diff);
							 char* a = strdup(msg);
						 g_array_append_val(array, a);
						}
                    } else {
						/*
						否则加上引号
						*/
					    g_string_append_printf(sql_new, "'%s'", str);
                    }
					g_log_dbproxy(g_message, "当前值为%s", sql_new->str); 

				} 
            }
			  for (i = 0; i < array->len; i++) {
					g_log_dbproxy(g_message,"AAAAAAAAAAAAAAAAAAAA %s", g_array_index(array, char*, i));
				}
        }
//		GHashTableIter iter;
//		gpointer key, value;
//
//		g_hash_table_iter_init (&iter, hash);
//		while (g_hash_table_iter_next (&iter, &key, &value)){
//			 // do something with key and value
//			 g_log_dbproxy(g_message, "LLLLLLLLLLLLLLLLLLLLLLL %s", key);
//
//			GSList* list = (GSList*)value;
//			GSList* iterator = NULL;
//
//
//			for (iterator = list; iterator; iterator = iterator->next) {
//				g_log_dbproxy(g_message,"LLLLLLLLLLLLLLLLLLLLLLL %s", iterator->data);
//			}
//		}
    //     char* abc= g_hash_table_lookup(name_score, "2018-07-07");
  //   g_log_dbproxy(g_message, "g_hash_table_lookup  %s", abc); 


         
    }

    return columns;
}

long get_tick(char *str_time) {  
    struct tm stm;  
    int iY, iM, iD, iH, iMin, iS;  
  
    memset(&stm,0,sizeof(stm));  
  
    iY = atoi(str_time);  
    iM = atoi(str_time+5);  
    iD = atoi(str_time+8);  
    iH = atoi(str_time+11);  
    iMin = atoi(str_time+14);  
    iS = atoi(str_time+17);  
  
    stm.tm_year=iY-1900;  
    stm.tm_mon=iM-1;  
    stm.tm_mday=iD;  
    stm.tm_hour=iH;  
    stm.tm_min=iMin;  
    stm.tm_sec=iS;  
  
    /*printf("%d-%0d-%0d %0d:%0d:%0d\n", iY, iM, iD, iH, iMin, iS);*/  
  
    return mktime(&stm);  
}  

int strpos( char* str, char c ) {
	char* ptr=strrchr(str, c);  
	if(ptr == NULL) {
		return  0;
	}
	//g_log_dbproxy(g_message, "111111global sql  is %s,  %d", ptr, (ptr-str)); 
	return ptr-str;
}

/*
作用: 普通字符串替换
参数: rep 被替换的字符串 with 要替换的字符串
参考: https://github.com/hazbo/str_replace/blob/master/C/1/main.c
注意: 一定释放内存
*/
char* str_replace(char* orig, char* rep, char* with)
{
    char *result;
    char *ins;
    char *tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig)
        return NULL;
    if (!rep)
        rep = "";
    len_rep = strlen(rep);
    if (!with)
        with = "";
    len_with = strlen(with);

    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

int judge_int(char* str){
	int i;
	for (i = 0; i < strlen(str); ++i) {
		//printf("%d\n", str[i]);
		if (str[i] >= 48 && str[i] <= 59) {
			//printf("YES\n");
		} else {
			return 1;
		}
	}
	return 0;
}


void print_key_value3(gpointer key, gpointer value , gpointer user_data)
{

    g_string_append_printf(user_data, "%s,", (char*)value);
    printf("%s -------------------->%s\n",(char*)key,(char*)value);
}

void destroy(gpointer key, gpointer value, gpointer data)  {
    g_log_dbproxy(g_message, "释放hast table中的list: %s\n", ((GSList*)value)->data);
    g_slist_free(value);
}

//GHashTable* split_column
//GPtrArray* combine_sql(GPtrArray* tokens, gint table, GArray* columns, guint num, gboolean has_suffix, gint sql_type, gint split_table_method, gint token_id,  GHashTable* split_column) {

	GPtrArray* combine_sql(GPtrArray* tokens, gint table, GArray* columns, guint num, gboolean has_suffix, gint sql_type, gint split_table_method, gint token_id,  GArray* split_column) {
	g_log_dbproxy(g_message, "处理SQL, split_table_method is %d table pos is %d", split_table_method, table); 
    GPtrArray* sqls = g_ptr_array_new();

    sql_token** ts = (sql_token**)(tokens->pdata);
    guint len = tokens->len;
    guint i;
	
	/*
	int region_id = 1;
	int worker_id= 2;
	snowflake_init(region_id, worker_id);
	*/

	long int unique_id = 0;

	unsigned int count = 0;
	char* origin_table_name = NULL;
	
	/*
	zhangming 2018/3/1 14:52
	sql_type 2 为update
	               1 为select 或 delete, 需要 通过TK_SQL_DELETE 这个token_id来判断

	zhangming 2018/7/7 20:04
	columns->len  等于 1 说明 当insert时，只插入一条数据
	*/
    if (columns->len == 1 || (columns->len == 0 && (2 == sql_type || 1 == sql_type ) ) ) {

		/*
		zhangming 2018/7/7 20:08
		*/
        GString* sql = g_string_new(&op);

        if (ts[1]->token_id == TK_COMMENT) {
            g_string_append_printf(sql, "/*%s*/", ts[1]->text->str);
        } else {
            g_string_append(sql, ts[1]->text->str);
        }
        for (i = 2; i < len; ++i) {
            sql_token_id token_id = ts[i]->token_id;

            if (token_id != TK_OBRACE) g_string_append_c(sql, ' '); 

            if (i == table) {
				if (1 == split_table_method) {
					//哈希取模(int)
					if(columns->len == 1){
						g_string_append_printf(sql, has_suffix ? "%s%lld" : "%s_%lld",
                                    ts[i]->text->str, strtoll(ts[g_array_index(columns, guint, 0)]->text->str, NULL, 10) % num);
					}else {
						g_string_append_printf(sql, "%s", ts[i]->text->str);
					}
				} else if (2 == split_table_method) {
					//哈希取模(string)
					
					if(columns->len == 1){
						long  hash_id;
						GString* tmp;
						tmp = ts[g_array_index(columns, guint, 0)]->text;
						hash_id = g_string_hash(tmp);
						g_log_dbproxy(g_message, "%s g_string_hash  is %d , mod is %d", tmp->str, hash_id, hash_id % num); 

						g_string_append_printf(sql, has_suffix ? "%s%lld" : "%s_%lld", ts[i]->text->str, hash_id % num);
					} else {
						g_string_append_printf(sql, "%s", ts[i]->text->str);
					}
				}else if (3 == split_table_method || 4 == split_table_method || 5 == split_table_method ) {
					//基于时间分段
					GString* tmp;
					int val;
					val = g_array_index(columns, guint, 0);
					tmp = ts[val]->text;
					g_log_dbproxy(g_message, "分表字段值: %s  在sql中的下标%d", tmp->str , val); 


                    GString* time = NULL;
					time = g_string_new(NULL);
					str_format(tmp->str, time, split_table_method);

                    g_log_dbproxy(g_message, "时间分表表名: %s_%s", ts[i]->text->str, time->str); 
					g_string_append_printf(sql, has_suffix ? "%s%lld" : "%s_%s", ts[i]->text->str, time->str);
				}
				
				origin_table_name = strdup(sql->str);
                
            } else if (token_id == TK_STRING) {
                g_string_append_printf(sql, "'%s'", ts[i]->text->str);
				g_log_dbproxy(g_message, "查询条件: %s", ts[i]->text->str); 
            } else if (token_id == TK_COMMENT) {
                g_string_append_printf(sql, "/*%s*/", ts[i]->text->str);
            } else if (3 == sql_type && token_id == TK_SQL_SET){
				/*
				zhangming 2018/1/1  23:42
				针对 insert into abc set uid=7, name="test_7";
				todo 如果字段里的值也有set呢,以后再验证

				zhangming 2018/7/9 14:53
				不存在以上问题,   字段里的值 是一个整体
				*/
				unique_id = snowflake_id();
				g_string_append_printf(sql, "set id=%ld, ", unique_id);
			}else {
                
				if(strcmp(ts[i]->text->str, "revoke") == 0){
					g_string_append(sql, "`revoke`");
				} else {
					g_string_append(sql, ts[i]->text->str);
				}

				g_log_dbproxy(g_message, "当前值为: %s", ts[i]->text->str); 
				
				/*
				zhangming 2018/1/1  23:46
				针对 insert into abc (uid,name) values (3,"test_3"), (5,"test_5");
				todo 如果字段里的值也有)呢,以后再验证


                zhangming 2018/7/9 21:44
                不存在此问题, 同上
				*/
			
				gchar* str = ts[i]->text->str;

				if(0 == count && strcmp(str, "(") == 0 ) {
					g_string_append(sql, "id,");
					count++;
				}else if(1 == count && strcmp(str, "(") == 0 ) {
					unique_id = snowflake_id();
					g_string_append_printf(sql, "%ld,", unique_id);
				}
            }
        }
		
		g_log_dbproxy(g_message, "单条insert sql: %s", sql->str); 
		/*
		zhangming 2018/1/12 19:50
		3	插入
		2  update
		1	select/delete
		*/
		if(3 == sql_type ||  2 == sql_type || TK_SQL_DELETE ==  token_id) {
			g_log_dbproxy(g_message, "=============== %s", origin_table_name); 
			char c= '_';  
			int pos = 0;
			pos = strpos(origin_table_name, c);
			if(pos >0) {
				//char* suffix = strrstr(origin_table_name, "_");
				//g_log_dbproxy(g_message, "suffix sql is %s", suffix); 
				//
				//if(suffix+1 >){
				
				//}
				
				char* tmp = (char*)malloc(sizeof(char)*20);
				memset(tmp, 0, 20);
				memcpy(tmp, origin_table_name+pos+1, strlen(origin_table_name) - pos);
				
				int is_int =0;
				is_int = judge_int(tmp);
				g_log_dbproxy(g_message, "^^^^ is %s, origin_table_name is %s, is_int is %d, split_table_method is %d", tmp, origin_table_name, is_int, split_table_method); 
				free(tmp);
				if(is_int == 0 ){
					/*
					现在不需要大表了, 太 low了
					char* res = (char*)malloc(sizeof(char) * 100);
					memset(res, 0, 100);
					memcpy(res, origin_table_name, pos);
					g_log_dbproxy(g_message, "original table name is %s, global table name  is   %s, pos is %d", origin_table_name,  res,  pos); 
					
					char* abc = strdup(sql->str);
					g_log_dbproxy(g_message, "original sql is %s", abc); 

					char* global_sql = str_replace(abc, origin_table_name, res);
					g_log_dbproxy(g_message, "global sql  is %s", global_sql); 
					
					GString* sql2 = g_string_new(global_sql);
					//g_string_append(sql2, global_sql);

					free(global_sql);
					free(abc);
					free(res);
					free(origin_table_name);

					g_ptr_array_add(sqls, sql2);

					*/
				}else{
					if(3 != split_table_method){
						/*
						update xes_flume_conf set department="技术开发部-基础架构组-wz" where department="技术开发部-基础架构组"
						这样的 修改大表, 要发送到所有的小表中去
						*/
						g_log_dbproxy(g_message, "small sql is %s", origin_table_name); 
						
						for(i = 0; i < num; i++){
							GString* tmp_sql = g_string_new(NULL);
							g_string_append_printf(tmp_sql, "%s_%d", origin_table_name, i);
							g_log_dbproxy(g_message, "tmp_sql->str is %s", tmp_sql->str); 
							
							char* tmp_sql2 = str_replace(sql->str, origin_table_name, tmp_sql->str);
							g_log_dbproxy(g_message, "tmp_sql2 is %s", tmp_sql2); 
							
							/*
							zhangming 2018/1/22 18:18
							g_ptr_array_add时, 不能释放到掉sql2
							*/
							GString* sql2 = g_string_new(tmp_sql2);
							g_log_dbproxy(g_message, "small sql is %s", sql2->str); 

							g_ptr_array_add(sqls, sql2);

							free(tmp_sql2);
							g_string_free(tmp_sql, TRUE);
						}
						free(origin_table_name);
						
					}
				}
			}
		}
        g_ptr_array_add(sqls, sql);
		
    } else {
		


        /*
        批量插入
        分表字段类型为时间
        年
        年-月
        年-月-日
        */

        if(3 == sql_type) {
		    if (3 == split_table_method || 4 == split_table_method || 5 == split_table_method ) {
				
//                GString* columns_str = NULL;
//                columns_str = g_string_new(NULL);
//    //				g_string_append_printf(columns_str, "%s", "(id,");    
//                g_string_append(columns_str, "(id,");
//
//                for (i = 5; i < len; ++i) {
//
//                    gchar* str = ts[i]->text->str;
//                     if (ts[i]->token_id == TK_STRING) {
//                      //  g_log_dbproxy(g_message, "BBBBBB %s", ts[i+1]->text->str);
//                      //  g_string_append_printf(columns_str, "'%s'", ts[i+1]->text->str);
//                    }else{
//                        /*
//                        zhangming 2018/7/8 23:22 
//                        (   左括号
//                        )   右括号
//                        create_time  字段
//                        */
//                        g_string_append(columns_str, ts[i]->text->str);
//                    }
//
//                    if (ts[i]->token_id == TK_CBRACE) {
//                        break;
//                    }  
//                }
//                /*
//                todo 加上 ·· (tab旁边那个键)
//                */
//                g_log_dbproxy(g_message, "批量insert sql column: %s", columns_str->str);
//		
//
//                GString* sql = NULL;
//                GHashTableIter iter;
//                gpointer key, value;
//
//                g_hash_table_iter_init (&iter, split_column);
//            
//                /*
//                遍历处理批insert中的各个数据项
//                */
//                while (g_hash_table_iter_next (&iter, &key, &value)) {
//                    // do something with key and value
//                    g_log_dbproxy(g_message, "hash_table循环: 数据表: %s", key);
//
//                    GSList* list = (GSList*)value;
//                    GSList* iterator = NULL;
//
//                    /*
//                    todo
//                    list循环: 数据表对应的数据: 'values'(598153816369791744, 'zm5','2018-07-09 00:00:05')
//
//                    */
//                    for (iterator = list; iterator; iterator = iterator->next) {
//                        g_log_dbproxy(g_message,"list循环: 数据表对应的数据: %s", iterator->data);
//
//                        sql = 	 g_string_new(&op);
//    //                  g_string_append_printf(sql, "insert into	%s %s values %s", key, columns_str->str, "(100, '2018-07-07 12:00:01')");
//                        g_string_append_printf(sql, "INSERT INTO %s %s VALUES %s", key, columns_str->str, strdup(strstr(iterator->data, "(")));
//    //							g_string_append_printf(sql, " insert into %s %s values %s", key, columns_str->str, strdup(iterator->data));
//
//                        g_log_dbproxy(g_message,"链表循环: 最终SQL: %s", sql->str);
//                        
//                        g_ptr_array_add(sqls, sql);
//                    }
//                }
//
//                /*
//                释放hash table / list
//                */
//                g_hash_table_foreach(split_column, destroy, NULL);
//                g_hash_table_destroy(split_column);
				


				GArray* mt[num];
				unsigned long ul;
				
				g_log_dbproxy(g_message, "分表类型为: %d, columns个数: %d", split_table_method, columns->len);
                
                GHashTable* hash = NULL;
                hash = g_hash_table_new(g_str_hash, g_str_equal);

               
                int i=0;
             
                

				
                g_log_dbproxy(g_message, "33333");
			
           

				g_log_dbproxy(g_message, "111111111111111");
				char* msg = NULL;
				unsigned long split_column_pos = 0;
				unsigned long open_pos = 0;
				unsigned long close_pos = 0;
				GString* tmp = NULL;
				GString* sql = NULL;
				sql = 	 g_string_new(&op);
					GString* time = NULL;
				int j;
                	long int unique_id = 0;
				for (i = 0; i < split_column->len; ++i) {
					msg = g_array_index(split_column, char*, i);
					
					split_column_pos = strtoull(strsep(&msg, "_"), NULL, 10);
					open_pos = strtoull(strsep(&msg, "_"), NULL, 10);
					close_pos = strtoull(msg, NULL, 10);

					time = g_string_new(NULL);
					str_format(ts[split_column_pos]->text->str, time, split_table_method);
					
				    
					

					tmp = g_string_new(NULL);
                    sql_token_id token_id;
					for (j = open_pos; j <= close_pos; ++j) {

                      
                        token_id = ts[j]->token_id;

                        if( token_id == TK_OBRACE || token_id == TK_CBRACE || strcmp(ts[j]->text->str, ",") == 0) {
                            g_string_append_printf(tmp, "%s", ts[j]->text->str);
                            if (token_id == TK_OBRACE) {
                                unique_id = snowflake_id();
							    g_string_append_printf(tmp, "%ld, ", unique_id);
                            }
                        }else {
                            g_string_append_printf(tmp, "'%s'", ts[j]->text->str);
                        }
					}
                    g_log_dbproxy(g_message, "CCCCCCCCCCCCCC %s", tmp->str); 

                     g_hash_table_insert(hash, time->str, g_slist_append(g_hash_table_lookup(hash, time), tmp->str));
					
				}


                GString* columns_str = NULL;
                columns_str = g_string_new(NULL);
                //				g_string_append_printf(columns_str, "%s", "(id,");    
                g_string_append(columns_str, "(id,");

                for (i = 5; i < len; ++i) {

                    gchar* str = ts[i]->text->str;
                    if (ts[i]->token_id == TK_STRING) {
                    //  g_log_dbproxy(g_message, "BBBBBB %s", ts[i+1]->text->str);
                    //  g_string_append_printf(columns_str, "'%s'", ts[i+1]->text->str);
                    }else{
                    /*
                    zhangming 2018/7/8 23:22 
                    (   左括号
                    )   右括号
                    create_time  字段
                    */
                    g_string_append(columns_str, ts[i]->text->str);
                    }

                    if (ts[i]->token_id == TK_CBRACE) {
                        break;
                    }  
                }

                         g_log_dbproxy(g_message, "ddddddd %s", columns_str->str); 

                 GHashTableIter iter;
                gpointer key, value;

                g_hash_table_iter_init (&iter, hash);
                            /*
                遍历处理批insert中的各个数据项
                */
                while (g_hash_table_iter_next (&iter, &key, &value)) {
                    // do something with key and value
                    g_log_dbproxy(g_message, "hash_table循环: 数据表: %s", key);

                    GSList* list = (GSList*)value;
                    GSList* iterator = NULL;

                     for (iterator=list; iterator; iterator=iterator->next) {
                        g_string_append_printf(sql, "INSERT INTO %s_%s %s VALUES %s", ts[table]->text->str, key, columns_str->str, strdup(strstr(iterator->data, "(")));
                     }

                }


				//g_string_append(sql, "insert into user(name , create_time) values('zm','2018-7-8 00:00:01'), ('zm2', '2018-7-9 00:00:01')");
				 g_ptr_array_add(sqls, sql);

                g_hash_table_foreach(hash, destroy, NULL);
                g_hash_table_destroy(hash);
		    }
        } else {
				
			{
  
                /*
                zhangming 2018/7/9 23:42
                遍历columns, 计算分表字段对应的value所在的分表
                分表名称为hash_table的key, 
                分表字段对应value 为 hash_table的value
                */

				


//                for (i = 0; i < clen; ++i) {
//                    val = g_array_index(columns, guint, i);
//                                
//                        //	guint64 column_value = strtoull(ts[val]->text->str, NULL, 10);
//                            
//                    time = g_string_new(NULL);
//                    str_format(ts[val]->text->str, time, split_table_method);
//    
//                    g_log_dbproxy(g_message, "TTTTTTTTTTTTT multy %d %s %s", val, ts[val]->text->str, time->str); 
//
//                            //g_array_append_val(strtoull(mt[time->str], NULL, 10), ts[val]->text->str);
//    
//                            //g_hash_table_insert(split_array, time->str, ts[val]->text->str);
//                    g_hash_table_insert(split_array, strdup(time->str),  g_slist_append(g_hash_table_lookup(split_array, time->str), strdup(ts[val]->text->str)));
//    
//                    g_string_free(time, TRUE);
//                }
//    
//                    
//                guint property_index   = g_array_index(columns, guint, 0) - 3;
//                guint start_skip_index = property_index + 1;
//                guint end_skip_index   = property_index + (clen + 1) * 2;
//    
//                g_hash_table_iter_init (&iter, split_array);
//    
//
//                GString* sql = NULL;
//                /*
//                zhangming 2018/7/9 23:42
//                遍历hash table + list 拼凑sql
//                */
//                while (g_hash_table_iter_next (&iter, &key, &value)) {
//                    // do something with key and value
//                    g_log_dbproxy(g_message, "遍历hash_table %s", key);
//
//                    GSList* list = (GSList*)value;
//                    GSList* iterator = NULL;
//                       
//                    GString* tmp = NULL;
//                    GString* tmp2 = NULL;
//                    tmp = g_string_new(" IN ( ");
//                    
//                    /*
//                    hash table中key 对应的value 属于同一个表, 组合
//                    (),(),()这样的形式
//                    */
//                    for (iterator = list; iterator; iterator = iterator->next) {
//                        g_log_dbproxy(g_message, "链表里的数据: %s", iterator->data);
//                        g_string_append_printf(tmp, "'%s',",  strdup(iterator->data));
//                    }
//
//                    g_log_dbproxy(g_message, "组合(未删除最后一个逗号)后: %s %d", tmp->str, tmp->len);
//
//                    g_string_erase(tmp, tmp->len-1, 1);  
//                    g_string_append_c(tmp, ')');
//
//                    g_log_dbproxy(g_message,"组合后: %s %d", tmp->str, tmp->len);
//        
//    
//                    sql = g_string_new(&op);
//                    if (ts[1]->token_id == TK_COMMENT) {
//                        g_string_append_printf(sql, "/*%s*/", ts[1]->text->str);
//                    } else {
//                        g_string_append(sql, ts[1]->text->str);
//                    }
//
//                    for (i = 2; i < len; ++i) {
//                        if (i < start_skip_index || i > end_skip_index) {
//                            if (ts[i]->token_id != TK_OBRACE) g_string_append_c(sql, ' ');
//
//                            if (i == table) {
//                                g_string_append_printf(sql, "%s_%s", ts[i]->text->str, key);
//                                g_log_dbproxy(g_message,"分表: %s_%s", ts[i]->text->str, key);
//                            } else if (i == property_index) {
//                                g_string_append_printf(sql, "%s%s", ts[i]->text->str, tmp->str);
//                                g_log_dbproxy(g_message,"提交拼凑数据: %s %s", ts[i]->text->str, tmp->str);
//                            } else if (ts[i]->token_id == TK_STRING) {
//                                g_string_append_printf(sql, "'%s'", ts[i]->text->str);
//                                 g_log_dbproxy(g_message,"查询字段对应的值: %s", ts[i]->text->str);
//                            } else if (ts[i]->token_id == TK_COMMENT) {
//                                g_string_append_printf(sql, "/*%s*/", ts[i]->text->str);
//                            } else {
//                                g_string_append(sql, ts[i]->text->str);
//                                g_log_dbproxy(g_message,"批量查询, 当前值: %s ", ts[i]->text->str);
//                            }
//                        }
//                    }
//
//                    g_string_free(tmp, TRUE);
//                    g_ptr_array_add(sqls, sql);
//                    g_log_dbproxy(g_message,"批量查询, 遍历list, 最终sql: %s", sql->str);
//                   
//                }

				guint m;
				guint i;
				int val;

				guint k;
				GString* tmp = NULL;
				GString* sql = NULL;
				GString* time = NULL;
				guint clen = columns->len;
		
				if ( 1 !=  split_table_method) {
					num = 3000;
				}

				GArray* mt[num];
				unsigned long ul;
				
				g_log_dbproxy(g_message, "分表类型为: %d, columns个数: %d", split_table_method, columns->len);

				if (  1 == split_table_method ) {
					for (i = 0; i < num; ++i) {
						mt[i] = g_array_new(FALSE, FALSE, sizeof(guint64));
					}
			
					for (i = 0; i < clen; ++i) {
						val = g_array_index(columns, guint, i);
						ul = strtoull(ts[val]->text->str, NULL, 10);
						g_array_append_val(mt[ ul % num], ul);
								
						g_log_dbproxy(g_message, "分表类型为id hash: %d  分表字段的值: %lu", val, ul); 
					   // g_array_append_val(strtoull(mt[column_value % num], NULL, 10), ts[val]->text->str);
					}
				} else {
					for (i = 0; i < 3000; ++i) {
						mt[i] = g_array_new(FALSE, TRUE, sizeof(char*));
					}

					for (i = 0; i < clen; ++i) {
						val = g_array_index(columns, guint, i);
						
						time = g_string_new(NULL);
						str_format(ts[val]->text->str, time, split_table_method);
						g_array_append_val(mt[strtoull(time->str, NULL, 10)], ts[val]->text->str);
								
						g_log_dbproxy(g_message, "分表类型不为id hash: %d %s %s", val, ts[val]->text->str, time->str); 
					}
				}

				guint property_index   = g_array_index(columns, guint, 0) - 3;
                guint start_skip_index = property_index + 1;
                guint end_skip_index   = property_index + (clen + 1) * 2;

			  
				for (m = 0; m < num; ++m) {
					if (mt[m]->len > 0) {
						tmp = g_string_new(" IN ( ");

						if ( 1 == split_table_method) {
							g_string_append_printf(tmp, "%lu", g_array_index(mt[m], guint64, 0));
							 
							for (k = 1; k < mt[m]->len; ++k) {
								g_string_append_printf(tmp, ",'%lu'", g_array_index(mt[m], guint64, k));
							}

						} else {
							 g_string_append_printf(tmp, "'%s'", g_array_index(mt[m], char*, 0));
							
							for (k = 1; k < mt[m]->len; ++k) {
								g_string_append_printf(tmp, ",'%s'", g_array_index(mt[m], char*, k));
							}
						}
                           
						g_string_append_c(tmp, ')');

						sql = g_string_new(&op);
						if (ts[1]->token_id == TK_COMMENT) {
							g_string_append_printf(sql, "/*%s*/", ts[1]->text->str);
						} else {
							g_string_append(sql, ts[1]->text->str);
						}

						for (i = 2; i < len; ++i) {
							if (i < start_skip_index || i > end_skip_index) {
								if (ts[i]->token_id != TK_OBRACE) g_string_append_c(sql, ' ');

								if (i == table) {
									g_string_append_printf(sql, "%s_%u", ts[i]->text->str, m);
								} else if (i == property_index) {
									g_string_append_printf(sql, "%s%s", ts[i]->text->str, tmp->str);
								} else if (ts[i]->token_id == TK_STRING) {
									g_string_append_printf(sql, "'%s'", ts[i]->text->str);
								} else if (ts[i]->token_id == TK_COMMENT) {
									g_string_append_printf(sql, "/*%s*/", ts[i]->text->str);
								} else {
									g_string_append(sql, ts[i]->text->str);
								}
							}
						}
						g_string_free(tmp, TRUE);
						g_ptr_array_add(sqls, sql);

						g_log_dbproxy(g_message,"最终sql: %s", sql->str);
					}
					g_array_free(mt[m], TRUE);
				}
               



        
        
        //				GString* columns_str = NULL;
        //                columns_str = g_string_new(NULL);
        ////				g_string_append_printf(columns_str, "%s", "(id,");    
        //                g_string_append(columns_str, "(id,");
        //                for (i = 1; i < len; ++i) {
        //                    gchar* str = ts[i]->text->str;
        //                     if (ts[i]->token_id == TK_STRING) {
        //                      //  g_log_dbproxy(g_message, "BBBBBB %s", ts[i+1]->text->str);
        //                      //  g_string_append_printf(columns_str, "'%s'", ts[i+1]->text->str);
        //                    }else{
        //                        /*
        //                        zhangming 2018/7/8 23:22 
        //                        (   左括号
        //                        )   右括号
        //                        create_time  字段
        //                        */
        //                        g_string_append(columns_str, ts[i]->text->str);
        //                    }
        //                    
        //
        //                    if (ts[i]->token_id == TK_CBRACE) {
        //                        break;
        //                    }  
        //                }
        //				g_log_dbproxy(g_message,"KKKKKKKKKK %s", columns_str->str);

            }
			
//			else
				
//			{
//                //按id批量查询
//                g_log_dbproxy(g_message, "BBBBBBBBBBBBBBBB split_table_method  %d", split_table_method); 
//                GString* time = NULL;
//                for (i = 0; i < clen; ++i) {
//                    int val = g_array_index(columns, guint, i);
//                                
//                    guint64 column_value = strtoull(ts[val]->text->str, NULL, 10);
//                            
//                    g_log_dbproxy(g_message, "TTTTTTTTTTTTT multy %d %s %s", val, ts[val]->text->str, time->str); 
//                    g_array_append_val(strtoull(mt[column_value % num], NULL, 10), ts[val]->text->str);
//                }
//		
//
//                guint property_index   = g_array_index(columns, guint, 0) - 3;
//                guint start_skip_index = property_index + 1;
//                guint end_skip_index   = property_index + (clen + 1) * 2;
//
//
//                g_log_dbproxy(g_message, "SSSSSSSSSSSSS  %d", columns->len); 
//
//                if (1 == split_table_method || 2 == split_table_method ) {
//                    for (m = 0; m < num; ++m) {
//                        if (mt[m]->len > 0) {
//                            GString* tmp = g_string_new(" IN(");
//                            g_string_append_printf(tmp, "%lu", g_array_index(mt[m], guint64, 0));
//                            guint k;
//                            for (k = 1; k < mt[m]->len; ++k) {
//                                g_string_append_printf(tmp, ",%lu", g_array_index(mt[m], guint64, k));
//                            }
//                            g_string_append_c(tmp, ')');
//
//                            GString* sql = g_string_new(&op);
//                            if (ts[1]->token_id == TK_COMMENT) {
//                                g_string_append_printf(sql, "/*%s*/", ts[1]->text->str);
//                            } else {
//                                g_string_append(sql, ts[1]->text->str);
//                            }
//
//                            for (i = 2; i < len; ++i) {
//                                if (i < start_skip_index || i > end_skip_index) {
//                                    if (ts[i]->token_id != TK_OBRACE) g_string_append_c(sql, ' ');
//
//                                    if (i == table) {
//                                        g_string_append_printf(sql, "%s_%u", ts[i]->text->str, m);
//                                    } else if (i == property_index) {
//                                        g_string_append_printf(sql, "%s%s", ts[i]->text->str, tmp->str);
//                                    } else if (ts[i]->token_id == TK_STRING) {
//                                        g_string_append_printf(sql, "'%s'", ts[i]->text->str);
//                                    } else if (ts[i]->token_id == TK_COMMENT) {
//                                        g_string_append_printf(sql, "/*%s*/", ts[i]->text->str);
//                                    } else {
//                                        g_string_append(sql, ts[i]->text->str);
//                                    }
//                                }
//                            }
//                            g_string_free(tmp, TRUE);
//                            g_ptr_array_add(sqls, sql);
//                        }
//                        g_array_free(mt[m], TRUE);
//                    }
//                }
//            }


        }
    }

    return sqls;
}

static gchar * get_origin_tbl_from_shadow(const gchar *raw_tbl_name) {
    gchar *prefix = NULL, *suffix = NULL, *real_table = NULL;
    gboolean is_shadow = FALSE;

    g_rw_lock_reader_lock(&config->tnw->name_wrap_lock);
    if (config->tnw->suffix != NULL) {
        suffix = g_strdup(config->tnw->suffix);
    }
    if (config->tnw->prefix != NULL) {
        prefix = g_strdup(config->tnw->prefix);
    }
    g_rw_lock_reader_unlock(&config->tnw->name_wrap_lock);

    if ((prefix != NULL && suffix == NULL) &&
                    (g_str_has_prefix(raw_tbl_name, prefix))) {
        is_shadow = TRUE;
    } else if ((prefix == NULL && suffix != NULL) &&
                    (g_str_has_suffix(raw_tbl_name, suffix))) {
        is_shadow = TRUE;
    } else if (prefix != NULL && g_str_has_prefix(raw_tbl_name, prefix) &&
            suffix != NULL && g_str_has_suffix(raw_tbl_name, suffix)) {
        is_shadow = TRUE;
    }

    if (is_shadow) {
        gint    str_length = strlen(raw_tbl_name);
        gint    prefix_length = prefix ? strlen(prefix) : 0;
        gint    suffix_length = suffix ? strlen(suffix) : 0;

        real_table = g_strndup(raw_tbl_name + prefix_length, str_length - prefix_length - suffix_length);
        is_shadow = TRUE;
    }
    if (prefix) g_free(prefix);
    if (suffix) g_free(suffix);

    return real_table;
}



GPtrArray* sql_parse(network_mysqld_con* con, GPtrArray* tokens) {
    //1. ��������ͱ���
    gint db, table, token_id;
    guint sql_type = get_table_index(tokens, &db, &table, &token_id);
    if (table == -1) return NULL;
	unsigned int count = 0;
	if (3 == sql_type){
		
		/*
		int region_id = 1;
		int worker_id= 2;
		
		snowflake_init(region_id, worker_id);
		*/
	}

    //2. ������
    gchar       *table_name = NULL;
    gchar       *raw_tbl_name = ((sql_token*)tokens->pdata[table])->text->str;
    gchar       *map_name = NULL;
    gchar       *real_table = get_origin_tbl_from_shadow(raw_tbl_name);
    gboolean    is_shadow = FALSE;

    if (real_table != NULL) is_shadow = TRUE;

    if (db == -1) {
        table_name = g_strdup_printf("%s.%s", con->client->conn_attr.default_db->str, raw_tbl_name);
        map_name = g_strdup_printf("%s.%s", con->client->conn_attr.default_db->str, real_table ? real_table : raw_tbl_name);
    } else {
        table_name = g_strdup_printf("%s.%s", ((sql_token*)tokens->pdata[db])->text->str, raw_tbl_name);
        map_name = g_strdup_printf("%s.%s", ((sql_token*)tokens->pdata[db])->text->str, real_table ? real_table : raw_tbl_name);
    }

    g_free(real_table);

    db_table_t* dt = g_hash_table_lookup(config->dt_table, map_name);
    if (dt == NULL) {
        g_free(table_name);
        g_free(map_name);
        return NULL;
    }

    g_free(map_name);

    if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
       gchar *msg = g_strdup_printf("get sharding table %s", table_name);
       CON_MSG_HANDLE(g_message, con, msg);
       g_free(msg);
    }


	/*
	zhangming 2018/7/7 19:56
	get_column_index 返回的数组指针columns, 是 分表字段对应的值, 在tokens的下标

	假设分表字段是create_time, 按年分
	
	1         2     3       4   5                              6   7           8  9                      10     11      12
 	insert into user  (   create_time, name  )   values   (   "2018-06-02"   ,      "zm"   )
	
	现在在分表字段为create_time, 那么create_time字段对应的值 是 "2018-06-02"
	其下标为9， 保存在columns数组中, 即 columns[9] = "2018-06-02"

	insert 可以批量操作的
	1         2     3       4   5                              6   7           8  9                      10     11      12    13    14   15                      16   17       18
 	insert into user  (   create_time, name  )   values   (   "2018-06-02"   ,      "zm"   )       ,       (     "2018-06-03"     ,      "zm"    )

	此时
	columns[9]="2018-06-02"
	columns[15]="2018-06-03"	

	*/

  
//    GPtrArray *split_column;
//    split_column = g_ptr_array_new();

    GHashTable* split_column = NULL;
    split_column = g_hash_table_new(g_str_hash,g_str_equal);
	
	GArray *array = NULL;
	array = g_array_new(FALSE, TRUE, sizeof(char*));

    GArray* columns = get_column_index(tokens, table_name, dt->column_name, sql_type, table+1, array, dt->split_table_method);
	g_log_dbproxy(g_message, "columns len is %d",columns->len);


    if (columns->len == 0 && 2 != sql_type ) {
        gchar *msg = g_strdup_printf("doesn't get table %s's sharding column from current query", table_name);
        CON_MSG_HANDLE(g_critical, con, msg);
        g_free(msg);
        g_free(table_name);
        g_array_free(columns, TRUE);

        return NULL;
    }
    g_free(table_name);

    //3. ƴ��SQL
    GPtrArray* sqls = combine_sql(tokens, table, columns, dt->table_num, is_shadow, sql_type, dt->split_table_method, token_id, array);
    g_array_free(columns, TRUE);

    if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
        gint i;
        for (i = 0; i < sqls->len; i++) {
            GString *sql = (GString *)g_ptr_array_index(sqls, i);
            CON_MSG_HANDLE(g_message, con, sql->str+1);
        }
    }

    return sqls;
}

network_backend_t* idle_rw(network_mysqld_con* con, gint *backend_ndx) {
    network_backend_t* ret = NULL;
    guint              i = 0;

    network_backends_t* backends = con->srv->backends;

    guint count = network_backends_count(backends);
    for (i = 0; i < count; ++i) {
        network_backend_t* backend = network_backends_get(backends, i);
        if (backend == NULL ||
                    (con->srv->max_backend_tr > 0 &&
                    backend->thread_running >= con->srv->max_backend_tr)) {
               continue;
        }

        if (chassis_event_thread_pool(backend) == NULL) continue;

        if (backend->type == BACKEND_TYPE_RW && IS_BACKEND_UP(backend)) {
                                /*(IS_BACKEND_UP(backend) ||      // without pending backend
                                 *IS_BACKEND_WAITING_EXIT(backend))) {
                                 */
            ret = backend;
            *backend_ndx = i;
            break;
        }
    }

    return ret;
}

network_backend_t* wrr_ro(network_mysqld_con *con, gint *backend_ndx, gchar *backend_tag) {
    network_backends_t* bs = con->srv->backends;
    network_backends_tag    *tag_backends = NULL;
    g_wrr_poll* rwsplit = NULL;
    GPtrArray               *backends = NULL;
    gchar                   *user = NETWORK_SOCKET_USR_NAME(con->client);
    guint ndx_num = 0;
    guint i;

    tag_backends = get_user_backends(bs, bs->pwd_table, user, backend_tag, &bs->user_mgr_lock);
    if (tag_backends == NULL || tag_backends->backends->len == 0) return NULL;

        rwsplit = tag_backends->wrr_poll;
        ndx_num = tag_backends->backends->len;
        backends = tag_backends->backends;

        if (TRACE_SQL(con->srv->log->log_trace_modules)) {
            gchar *msg = g_strdup_printf("query requires sending to slave "
                                    "with tag:%s for user:%s", backend_tag ? backend_tag : "default", user);
            CON_MSG_HANDLE(g_message, con, msg);
            g_free(msg);
        }

    guint max_weight = rwsplit->max_weight;
    guint cur_weight = rwsplit->cur_weight;
    guint next_ndx   = rwsplit->next_ndx;

    // get backend index by slave wrr
    network_backend_t *res = NULL, *temp_res = NULL;
    for(i = 0; i < ndx_num; ++i) {
        network_backend_t *backend = (network_backend_t *)g_ptr_array_index(backends, next_ndx);
        if (backend == NULL || (con->srv->max_backend_tr > 0 &&
                            backend->thread_running >= con->srv->max_backend_tr)) {
            goto next;
        }

        if (chassis_event_thread_pool(backend) == NULL) goto next;

        if (backend->type == BACKEND_TYPE_RO &&
                        /* backend->weight >= cur_weight && */
                        IS_BACKEND_UP(backend)) {   /* without pending backend */
            temp_res = backend;
            if (backend->weight >= cur_weight) {
                res = backend;
                *backend_ndx = i;
            }
        }

    next:
        if (next_ndx >= ndx_num - 1) {
            --cur_weight;
            next_ndx = 0;

            if (cur_weight == 0) cur_weight = max_weight;
        } else {
            ++next_ndx;
        }   

        if (res != NULL) break;
    }

    if (res == NULL && temp_res != NULL) {
        res = temp_res;
    }
    rwsplit->cur_weight = cur_weight;
    rwsplit->next_ndx = next_ndx;
    return res;
}

/**
 * call the lua function to intercept the handshake packet
 *
 * @return PROXY_SEND_QUERY  to send the packet from the client
 *         PROXY_NO_DECISION to pass the server packet unmodified
 */
static network_mysqld_lua_stmt_ret proxy_lua_read_handshake(network_mysqld_con *con) {
    network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION; /* send what the server gave us */
#ifdef HAVE_LUA_H
    network_mysqld_con_lua_t *st = con->plugin_con_state;

    lua_State *L;

    /* call the lua script to pick a backend
       ignore the return code from network_mysqld_con_lua_register_callback, because we cannot do anything about it,
       it would always show up as ERROR 2013, which is not helpful.
     */
    (void)network_mysqld_con_lua_register_callback(con, config->lua_script);

    if (!st->L) return ret;

    L = st->L;

    g_assert(lua_isfunction(L, -1));
    lua_getfenv(L, -1);
    g_assert(lua_istable(L, -1));
    
    lua_getfield_literal(L, -1, C("read_handshake"));
    if (lua_isfunction(L, -1)) {
        /* export
         *
         * every thing we know about it
         *  */

        if (lua_pcall(L, 0, 1, 0) != 0) {
            g_log_dbproxy(g_critical, "(read_handshake) %s", lua_tostring(L, -1));

            lua_pop(L, 1); /* errmsg */

            /* the script failed, but we have a useful default */
        } else {
            if (lua_isnumber(L, -1)) {
                ret = lua_tonumber(L, -1);
            }
            lua_pop(L, 1);
        }
    
        switch (ret) {
        case PROXY_NO_DECISION:
            break;
        case PROXY_SEND_QUERY:
            g_log_dbproxy(g_warning, "(read_handshake) return proxy.PROXY_SEND_QUERY is deprecated, use PROXY_SEND_RESULT instead");
            ret = PROXY_SEND_RESULT;
        case PROXY_SEND_RESULT:
            /**
             * proxy.response.type = ERR, RAW, ...
             */

            if (network_mysqld_con_lua_handle_proxy_response(con, config->lua_script)) {
                /**
                 * handling proxy.response failed
                 *
                 * send a ERR packet
                 */
        
                network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
            }

            break;
        default:
            ret = PROXY_NO_DECISION;
            break;
        }
    } else if (lua_isnil(L, -1)) {
        lua_pop(L, 1); /* pop the nil */
    } else {
        g_log_dbproxy(g_message, "%s", lua_typename(L, lua_type(L, -1)));
        lua_pop(L, 1); /* pop the ... */
    }
    lua_pop(L, 1); /* fenv */

    g_assert(lua_isfunction(L, -1));
#endif
    return ret;
}

/**
 * parse the hand-shake packet from the server
 *
 *
 * @note the SSL and COMPRESS flags are disabled as we can't 
 *       intercept or parse them.
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_handshake) {
    network_packet packet;
    network_socket *recv_sock, *send_sock;
    network_mysqld_auth_challenge *challenge;
    GString *challenge_packet;
    guint8 status = 0;
    int err = 0;

    send_sock = con->client;
    recv_sock = con->server;

    packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
    packet.offset = 0;

    err = err || network_mysqld_proto_skip_network_header(&packet);
    if (err)
    {
        CON_MSG_HANDLE(g_warning, con, "read hand shake's network header failed");
        return NETWORK_SOCKET_ERROR;
    }

    err = err || network_mysqld_proto_peek_int8(&packet, &status);
    if (err)
    {
        CON_MSG_HANDLE(g_warning, con, "read hand shake's execute result failed");
        return NETWORK_SOCKET_ERROR;
    }
    /* handle ERR packets directly */
    if (status == 0xff) {
        /* move the chunk from one queue to the next */
        guint16 errcode;
        gchar *errmsg = NULL;

        // get error message from packet
        packet.offset += 1; // skip 0xff
        err = err || network_mysqld_proto_get_int16(&packet, &errcode);
        if (err) {
            CON_MSG_HANDLE(g_warning, con, "read hand shake get errcode failed");
        }
        if (packet.offset < packet.data->len) {
            err = err || network_mysqld_proto_get_string_len(&packet, &errmsg, packet.data->len - packet.offset);
            if (err) {
                CON_MSG_HANDLE(g_warning, con, "get handshake packets' errmsg failed ");
            }
        }
        if (errmsg) g_free(errmsg);

        network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, g_queue_pop_tail(recv_sock->recv_queue->chunks));

        network_mysqld_con_lua_t *st = con->plugin_con_state;
        /** Currently setting backend to DOWN&UP is only allowed by check_state due to lock issue.
         *  Seems this function is useless and reconsider following code when reuse this function.
         *if (!IS_BACKEND_OFFLINE(st->backend) && !IS_BACKEND_WAITING_EXIT(st->backend)) {
         *   SET_BACKEND_STATE(st->backend, BACKEND_STATE_DOWN);
         *   g_log_dbproxy(g_warning, "set backend (%s) state to DOWN", recv_sock->dst->name->str);
         *}
         */
        if (st != NULL && st->backend != NULL) {
            // Currently don't know the case in which this code would be executed, print log.
            g_log_dbproxy(g_critical, "unexpected code was executed: %d", g_atomic_int_get(&st->backend->connected_clients));
            //g_atomic_int_dec_and_test(&st->backend->connected_clients);
            st->backend = NULL;
            st->backend_ndx = -1;
        }
    //  chassis_gtime_testset_now(&st->backend->state_since, NULL);
        network_socket_free(con->server);
        con->server = NULL;

        return NETWORK_SOCKET_ERROR; /* it sends what is in the send-queue and hangs up */
    }

    challenge = network_mysqld_auth_challenge_new();
    if (network_mysqld_proto_get_auth_challenge(&packet, challenge)) {
        g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
        network_mysqld_auth_challenge_free(challenge);

        return NETWORK_SOCKET_ERROR;
    }

    con->server->challenge = challenge;

    /* we can't sniff compressed packets nor do we support SSL */
    challenge->capabilities &= ~(CLIENT_COMPRESS);
    challenge->capabilities &= ~(CLIENT_SSL);

    switch (proxy_lua_read_handshake(con)) {
    case PROXY_NO_DECISION:
        break;
    case PROXY_SEND_RESULT:
        /* the client overwrote and wants to send its own packet
         * it is already in the queue */
        /* never arrives here */
        g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
        return NETWORK_SOCKET_ERROR;
    default:
        g_log_dbproxy(g_error, "proxy_lua_read_handshake returns invalid value");
        break;
    } 

    challenge_packet = g_string_sized_new(packet.data->len); /* the packet we generate will be likely as large as the old one. should save some reallocs */
    network_mysqld_proto_append_auth_challenge(challenge_packet, challenge);
    network_mysqld_queue_sync(send_sock, recv_sock);
    network_mysqld_queue_append(send_sock, send_sock->send_queue, S(challenge_packet));

    g_string_free(challenge_packet, TRUE);

    g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

    /* copy the pack to the client */
    con->state = CON_STATE_SEND_HANDSHAKE;

    return NETWORK_SOCKET_SUCCESS;
}

static network_mysqld_lua_stmt_ret proxy_lua_read_auth(network_mysqld_con *con) {
    network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
    network_mysqld_con_lua_t *st = con->plugin_con_state;
    lua_State *L;

    /* call the lua script to pick a backend
       ignore the return code from network_mysqld_con_lua_register_callback, because we cannot do anything about it,
       it would always show up as ERROR 2013, which is not helpful. 
    */
    (void)network_mysqld_con_lua_register_callback(con, config->lua_script);

    if (!st->L) return 0;

    L = st->L;

    g_assert(lua_isfunction(L, -1));
    lua_getfenv(L, -1);
    g_assert(lua_istable(L, -1));
    
    lua_getfield_literal(L, -1, C("read_auth"));
    if (lua_isfunction(L, -1)) {

        /* export
         *
         * every thing we know about it
         *  */

        if (lua_pcall(L, 0, 1, 0) != 0) {
            g_log_dbproxy(g_critical, "(read_auth) %s", lua_tostring(L, -1));

            lua_pop(L, 1); /* errmsg */

            /* the script failed, but we have a useful default */
        } else {
            if (lua_isnumber(L, -1)) {
                ret = lua_tonumber(L, -1);
            }
            lua_pop(L, 1);
        }

        switch (ret) {
        case PROXY_NO_DECISION:
            break;
        case PROXY_SEND_RESULT:
            /* answer directly */

            if (network_mysqld_con_lua_handle_proxy_response(con, config->lua_script)) {
                /**
                 * handling proxy.response failed
                 *
                 * send a ERR packet
                 */
        
                network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
            }

            break;
        case PROXY_SEND_QUERY:
            /* something is in the injection queue, pull it from there and replace the content of
             * original packet */

            if (st->injected.queries->length) {
                ret = PROXY_SEND_INJECTION;
            } else {
                ret = PROXY_NO_DECISION;
            }
            break;
        default:
            ret = PROXY_NO_DECISION;
            break;
        }

        /* ret should be a index into */

    } else if (lua_isnil(L, -1)) {
        lua_pop(L, 1); /* pop the nil */
    } else {
        g_log_dbproxy(g_message, "%s", lua_typename(L, lua_type(L, -1)));
        lua_pop(L, 1); /* pop the ... */
    }
    lua_pop(L, 1); /* fenv */

    g_assert(lua_isfunction(L, -1));
#endif
    return ret;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth) {
    /* read auth from client */
    network_packet packet;
    network_socket *recv_sock, *send_sock;
    network_mysqld_auth_response *auth;
    int err = 0;

    recv_sock = con->client;
    send_sock = con->server;

    if (TRACE_CON_STATUS(con->srv->log->log_trace_modules)) {
        CON_MSG_HANDLE(g_message, con, "proxy_read_auth begin");
    }

    packet.data = g_queue_pop_tail(recv_sock->recv_queue->chunks);
    packet.offset = 0;

    err = network_mysqld_proto_skip_network_header(&packet);
    if (err) {
        gchar *msg = "read auth response's network header failed";

        CON_MSG_HANDLE(g_warning, con, msg);
        SEND_INTERNAL_ERR(msg);

        return NETWORK_SOCKET_ERROR;
    }
    auth = network_mysqld_auth_response_new();

    err = network_mysqld_proto_get_auth_response(&packet, auth);
    g_string_free(packet.data, TRUE);

    if (err) {
        gchar *msg = "read auth response package failed";
        CON_MSG_HANDLE(g_warning, con, msg);
        SEND_INTERNAL_ERR(msg);
        network_mysqld_auth_response_free(auth);
        return NETWORK_SOCKET_ERROR;
    }
    if (!(auth->capabilities & CLIENT_PROTOCOL_41)) {
        /* should use packet-id 0 */
        gchar *msg = "4.0 protocol is not supported";
        CON_MSG_HANDLE(g_warning, con, msg);
        SEND_INTERNAL_ERR(msg);
        network_mysqld_auth_response_free(auth);
        return NETWORK_SOCKET_ERROR;
    }

    if (!(auth->capabilities & CLIENT_SECURE_CONNECTION)) {
        gchar *msg = "Old Password Authentication is not supported";
        CON_MSG_HANDLE(g_warning, con, msg);
        SEND_INTERNAL_ERR(msg);
        network_mysqld_auth_response_free(auth);
        return NETWORK_SOCKET_ERROR;
    }

    if ((auth->capabilities & CLIENT_COMPRESS) != 0) {
        gchar *msg = "CLIENT_COMPRESS is not supported";
        CON_MSG_HANDLE(g_warning, con, msg);
        SEND_INTERNAL_ERR(msg);
        network_mysqld_auth_response_free(auth);
        return NETWORK_SOCKET_ERROR;
    }

    con->client->response = auth;

    if (TRACE_CON_STATUS(con->srv->log->log_trace_modules)) {
        GString *auth_str = network_mysqld_auth_response_dump(auth);
        gchar *msg = g_strdup_printf("auth flag: %s", auth_str->str);
        CON_MSG_HANDLE(g_message, con, msg);
        g_free(msg);
        g_string_free(auth_str, TRUE);
    }

    con->client->response->capabilities &= ~CLIENT_PLUGIN_AUTH;
    // 基于MySQL 5.5和5.6的区别，5.5不支持CLIENT_CONNECT_ATTRS、CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA和CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
    con->client->response->capabilities &= ~(0xf00000);

//  g_string_assign_len(con->client->default_db, S(auth->database));

    network_backends_t *bs = con->srv->backends;
    gboolean check_res = FALSE;
    check_res = check_user_host(bs->pwd_table, auth->username->str,
                                NETWORK_SOCKET_SRC_NAME(con->client), &bs->user_mgr_lock);
    if (!check_res) {
        GString *error = g_string_sized_new(64);
        g_string_printf(error, "Access denied(host is forbidden) for user '%s'@'%s' (using password: YES)",
                                    auth->username->str, NETWORK_SOCKET_SRC_IPADDR(recv_sock));
        network_mysqld_con_send_error_full_nolog(recv_sock, S(error), ER_ACCESS_DENIED_ERROR, "28000");
        SEND_ERR_MSG_HANDLE(g_warning, error->str, recv_sock);
        g_string_free(error, TRUE);
        goto funcexit;
    }
	
	g_log_dbproxy(g_message, "NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth)  mysql client connect dbprox info user is  %s", auth->username->str); 
	
	/*
	zhangming 2018/1/14 16:35
	最后两个参数为NULL, 0, 因为这里是 连接dbproxy的 账号, 不用
	*/
    GString *hashed_password = get_hash_passwd(bs->pwd_table, auth->username->str, &bs->user_mgr_lock, NULL, 0);

    if (hashed_password) {
        GString *expected_response = g_string_sized_new(20);
        network_mysqld_proto_password_scramble(expected_response, S(con->challenge), S(hashed_password));
        if (g_string_equal(expected_response, auth->response)) {
            g_string_assign_len(recv_sock->conn_attr.default_db, S(auth->database));

            char *client_charset = NULL;
            if (config->charset == NULL) client_charset = charset[auth->charset];
            else client_charset = config->charset;

            g_string_assign(recv_sock->conn_attr.charset_client,     client_charset);
            g_string_assign(recv_sock->conn_attr.charset_results,    client_charset);
            g_string_assign(recv_sock->conn_attr.charset_connection, client_charset);

            g_string_free(hashed_password, TRUE);
            network_mysqld_con_send_ok(recv_sock);
            g_string_free(expected_response, TRUE);
        } else {
            GString *error = g_string_sized_new(64);
            g_string_printf(error, "Access denied for user '%s'@'%s' (using password: YES)",
                                        auth->username->str, NETWORK_SOCKET_SRC_IPADDR(recv_sock));
            network_mysqld_con_send_error_full_nolog(recv_sock, S(error), ER_ACCESS_DENIED_ERROR, "28000");
            SEND_ERR_MSG_HANDLE(g_warning, error->str, recv_sock);
            g_string_free(error, TRUE);
            g_string_free(hashed_password, TRUE);
            g_string_free(expected_response, TRUE);
            return NETWORK_SOCKET_ERROR;
        }
    } else {
        GString *error = g_string_sized_new(64);
        g_string_printf(error, "Access denied for user '%s'@'%s' (using password: YES)",
                                        auth->username->str, NETWORK_SOCKET_SRC_IPADDR(recv_sock));
        network_mysqld_con_send_error_full_nolog(recv_sock, S(error), ER_ACCESS_DENIED_ERROR, "28000");
        SEND_ERR_MSG_HANDLE(g_warning, error->str, recv_sock);
        g_string_free(error, TRUE);
        return NETWORK_SOCKET_ERROR;
    }

funcexit:
    con->state = CON_STATE_SEND_AUTH_RESULT;
    log_sql_connect(config->sql_log_mgr, con);

    return NETWORK_SOCKET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth_result) {
    GString *packet;
    GList *chunk;
    network_socket *recv_sock, *send_sock;

    recv_sock = con->server;
    send_sock = con->client;

    chunk = recv_sock->recv_queue->chunks->tail;
    packet = chunk->data;

    /* send the auth result to the client */
    if (con->server->is_authed) {
        /**
         * we injected a COM_CHANGE_USER above and have to correct to 
         * packet-id now 
         * if config->pool_change_user is false, we don't inject a COM_CHANGE_USER and jump to send_auth_result directly,
         * will not reach here.
         */
        packet->str[3] = 2;
    }

    /**
     * copy the 
     * - default-db, 
     * - charset,
     * - username, 
     * - scrambed_password
     *
     * to the server-side 
     */
    g_string_assign_len(recv_sock->conn_attr.charset_client, S(send_sock->conn_attr.charset_client));
    g_string_assign_len(recv_sock->conn_attr.charset_connection, S(send_sock->conn_attr.charset_connection));
    g_string_assign_len(recv_sock->conn_attr.charset_results, S(send_sock->conn_attr.charset_results));
    g_string_assign_len(recv_sock->conn_attr.default_db, S(send_sock->conn_attr.default_db));

    if (con->server->response) {
        /* in case we got the connection from the pool it has the response from the previous auth */
        network_mysqld_auth_response_free(con->server->response);
        con->server->response = NULL;
    }
    con->server->response = network_mysqld_auth_response_copy(con->client->response);

    /**
     * recv_sock still points to the old backend that
     * we received the packet from. 
     *
     * backend_ndx = 0 might have reset con->server
     */
/*
    switch (proxy_lua_read_auth_result(con)) {
    case PROXY_SEND_RESULT:
         // we already have content in the send-sock 
         // chunk->packet is not forwarded, free it

        g_string_free(packet, TRUE);
        
        break;
    case PROXY_NO_DECISION:
        network_mysqld_queue_append_raw(
                send_sock,
                send_sock->send_queue,
                packet);

        break;
    default:
        g_log_dbproxy(g_error, "...");
        break;
    }
*/
    if (packet->str[NET_HEADER_SIZE] == MYSQLD_PACKET_OK) {
        network_connection_pool_lua_add_connection(con);
    }/*else {
        network_backend_t* backend = ((network_mysqld_con_lua_t*)(con->plugin_con_state))->backend;
        if (backend->state != BACKEND_STATE_OFFLINE) backend->state = BACKEND_STATE_DOWN;
    }*/
    network_mysqld_queue_append_raw(
            send_sock,
            send_sock->send_queue,
            packet);
    /**
     * we handled the packet on the server side, free it
     */
    g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
    
    /* the auth phase is over
     *
     * reset the packet-id sequence
     */
    network_mysqld_queue_reset(send_sock);
    network_mysqld_queue_reset(recv_sock);

    con->state = CON_STATE_SEND_AUTH_RESULT;

    return NETWORK_SOCKET_SUCCESS;
}

static void modify_session_vars(network_mysqld_con* con) {
    if (con->server == NULL) return;

    char cmd = COM_QUERY;
    network_mysqld_con_lua_t* st = con->plugin_con_state;
    GList *cur_set_vars_client = g_queue_peek_head_link(con->client->conn_attr.set_vars);
    GList *cur_set_vars_server = g_queue_peek_head_link(con->server->conn_attr.set_vars);
    gint cmp_result = -1;
    GString* query = NULL;
    set_var_unit *set_var = NULL;

    if (cur_set_vars_client == NULL && cur_set_vars_server == NULL) return;

    do {
        do {
            if (cur_set_vars_client != NULL && cur_set_vars_server != NULL) {
                cmp_result = set_var_name_compare(cur_set_vars_client->data, cur_set_vars_server->data, NULL);
                set_var = cmp_result > 0 ? cur_set_vars_server->data : cur_set_vars_client->data;
            } else {
                cmp_result = (cur_set_vars_server != NULL) ? 1 : -1;
                set_var = (cur_set_vars_server != NULL) ? cur_set_vars_server->data : cur_set_vars_client->data;
            }

            if (cmp_result != 0 || !set_var_value_eq(cur_set_vars_client->data, cur_set_vars_server->data)) {
                if (query == NULL) {
                    query = g_string_new_len(&cmd, 1);
                    g_string_append(query, "SET ");
                } else {
                    g_string_append(query, ", ");
                }
                set_var_print_set_value(query, set_var, cmp_result > 0);
            }

            if (cmp_result == 0) {
                // cur_set_vars_client和cur_set_vars_server相同，继续遍历cur_set_vars_server和cur_set_vars_client
                cur_set_vars_server = g_list_next(cur_set_vars_server);
                cur_set_vars_client = g_list_next(cur_set_vars_client);
            } else if (cmp_result < 0) {
                // 要么cur_set_vars_server为空，要么当前cur_set_vars_client小于cur_set_vars_server，继续遍历cur_set_vars_client
                cur_set_vars_client = g_list_next(cur_set_vars_client);
            } else {
                // 要么cur_set_vars_client为空，要么当前cur_set_vars_client大于cur_set_vars_server，继续遍历cur_set_vars_server
                cur_set_vars_server = g_list_next(cur_set_vars_server);
            }

        } while (cur_set_vars_server != NULL);
    } while(cur_set_vars_client != NULL);

    if (query != NULL)
    {
        injection* inj = injection_new(INJECTION_IMPLICIT_SET, query);
        inj->resultset_is_needed = TRUE;
        g_queue_push_head(st->injected.queries, inj);
    }
}

static void modify_db(network_mysqld_con* con) {
    char* default_db = con->client->conn_attr.default_db->str;

    if (con->server == NULL) return;

    if (default_db != NULL && strcmp(default_db, "") != 0 && strcmp(default_db, con->server->conn_attr.default_db->str) != 0) {
        char cmd = COM_INIT_DB;
        GString* query = g_string_new_len(&cmd, 1);
        g_string_append(query, default_db);
        injection* inj = injection_new(INJECTION_IMPLICIT_CHANGE_DB, query);
        inj->resultset_is_needed = TRUE;
        network_mysqld_con_lua_t* st = con->plugin_con_state;
        g_queue_push_head(st->injected.queries, inj);
    }
}

static void modify_charset(network_mysqld_con* con) {
    if (con->server == NULL) return;

    network_socket* client = con->client;
    network_socket* server = con->server;
    char cmd = COM_QUERY;
    network_mysqld_con_lua_t* st = con->plugin_con_state;


    if (con->conn_status.set_charset_client->len == 0 && !g_string_equal(client->conn_attr.charset_client, server->conn_attr.charset_client)) {
        GString* query = g_string_new_len(&cmd, 1);
        g_string_append_printf(query, "SET CHARACTER_SET_CLIENT=%s", client->conn_attr.charset_client->str);

        injection* inj = injection_new(INJECTION_IMPLICIT_CHANGE_CHARSET_CLIENT, query);
        inj->resultset_is_needed = TRUE;
        g_queue_push_head(st->injected.queries, inj);
    }
    if (con->conn_status.set_charset_results->len == 0 && !g_string_equal(client->conn_attr.charset_results, server->conn_attr.charset_results)) {
        GString* query = g_string_new_len(&cmd, 1);
        g_string_append_printf(query, "SET CHARACTER_SET_RESULTS=%s", client->conn_attr.charset_results->str);

        injection* inj = injection_new(INJECTION_IMPLICIT_CHANGE_CHARSET_RESULTS, query);
        inj->resultset_is_needed = TRUE;
        g_queue_push_head(st->injected.queries, inj);
    }
    if (con->conn_status.set_charset_connection->len == 0 && !g_string_equal(client->conn_attr.charset_connection, server->conn_attr.charset_connection)) {
        GString* query = g_string_new_len(&cmd, 1);
        g_string_append_printf(query, "SET CHARACTER_SET_CONNECTION=%s", client->conn_attr.charset_connection->str);

        injection* inj = injection_new(INJECTION_IMPLICIT_CHANGE_CHARSET_CONNECTION, query);
        inj->resultset_is_needed = TRUE;
        g_queue_push_head(st->injected.queries, inj);
    }
}


static void modify_autocommit(network_mysqld_con* con) {
    network_mysqld_con_lua_t* st = con->plugin_con_state;

    if (con->server == NULL || con->conn_status.is_set_autocommit) return;

    if (con->client->conn_attr.autocommit_status == AUTOCOMMIT_UNKNOWN
        || (con->client->conn_attr.autocommit_status == AUTOCOMMIT_TRUE && con->server->conn_attr.autocommit_status != AUTOCOMMIT_TRUE)
        || (con->client->conn_attr.autocommit_status == AUTOCOMMIT_FALSE && con->server->conn_attr.autocommit_status != AUTOCOMMIT_FALSE))
    {
        char cmd = COM_QUERY;
        GString* query = g_string_new_len(&cmd, 1);

        g_string_append_printf(query, "SET AUTOCOMMIT=%s",
                (con->client->conn_attr.autocommit_status == AUTOCOMMIT_UNKNOWN) ? ("default") : (con->client->conn_attr.autocommit_status == AUTOCOMMIT_FALSE ? "0" : "1"));

        injection* inj = injection_new(INJECTION_IMPLICIT_SET_AUTOCOMMIT, query);
        inj->resultset_is_needed = TRUE;
        g_queue_push_head(st->injected.queries, inj);
    }
}

static void modify_found_rows(network_mysqld_con* con) {
    network_mysqld_con_lua_t* st = con->plugin_con_state;

    if (con->server == NULL) return;

    if (con->conn_status.is_in_select_calc_found_rows) {
        char cmd = COM_QUERY;
        GString* query = g_string_new_len(&cmd, 1);
        g_string_append_printf(query, "SELECT found_rows();");

        injection* inj = injection_new(INJECTION_IMPLICIT_GET_FOUND_ROWS, query);
        inj->resultset_is_needed = TRUE;
        g_queue_push_tail(st->injected.queries, inj);
    }
}

static void modify_last_insert_id(network_mysqld_con* con) {
    network_mysqld_con_lua_t* st = con->plugin_con_state;
    char cmd = COM_QUERY;

    if (con->server == NULL) return;

    GString* query = g_string_new_len(&cmd, 1);
    g_string_append_printf(query, "SELECT last_insert_id();");

    injection* inj = injection_new(INJECTION_IMPLICIT_LAST_INSERT_ID, query);
    inj->resultset_is_needed = TRUE;
    g_queue_push_tail(st->injected.queries, inj);
}

static void proxy_reinitialize_db_connection(network_mysqld_con* con)
{
    modify_session_vars(con);
    modify_autocommit(con);
    modify_db(con);
    modify_charset(con);
#if 0
    modify_found_rows(con);
#endif
}

/* 跳过语句中的comment */
static guint skip_comment_token(GPtrArray* tokens, guint start_token)
{
    sql_token* token;

    if (start_token >= tokens->len) { return start_token; }
    token = tokens->pdata[start_token];

    while (token->token_id == TK_COMMENT_MYSQL || token->token_id == TK_COMMENT)
    {
        ++start_token;
        if (start_token >= tokens->len) { return start_token; }

        token = tokens->pdata[start_token];
    }

    return start_token;
}

static inline gint parse_commit_rollback(sql_token** ts, GPtrArray* tokens, gint idx) {
    gint type = INVALID_TYPE;
    gint len = tokens->len;

    idx = skip_comment_token(tokens, idx);
    if (0 >= len - idx)
        return DEFAULT_TYPE;

    if (0 < len - idx && strcasecmp(ts[idx]->text->str, "work") == 0) {
        type |= WORK_TYPE;
        idx++;
    }

    idx = skip_comment_token(tokens, idx);
    if (0 < len - idx && strcasecmp(ts[idx]->text->str, "to") == 0)
        return INVALID_TYPE;

    if (0 < len - idx && ts[idx]->token_id == TK_SQL_AND) {
        idx = skip_comment_token(tokens, ++idx);
        if (0 < len - idx && strcasecmp(ts[idx]->text->str, "no") == 0) {
            type |= NO_CHAIN_TYPE;
            idx = skip_comment_token(tokens, ++idx);
        } else
            type |= CHAIN_TYPE;
        if (0 >= len - idx || strcasecmp(ts[idx]->text->str, "chain") != 0)
            return INVALID_TYPE;
        else
            idx = skip_comment_token(tokens, ++idx);
    }

    if (0 < len - idx && strcasecmp(ts[idx]->text->str, "no") == 0) {
        type |= NO_RELEASE_TYPE;
        idx = skip_comment_token(tokens, ++idx);
        if (0 >= len - idx || strcasecmp(ts[idx]->text->str, "release") != 0)
            return INVALID_TYPE;
        idx = skip_comment_token(tokens, ++idx);
    }

    if (0 < len - idx && strcasecmp(ts[idx]->text->str, "release") == 0) {
        type |= RELEASE_TYPE;
        idx = skip_comment_token(tokens, ++idx);
    }

    if (0 < len - idx)
        type = INVALID_TYPE;

    return type;
}

static gboolean check_flags(GPtrArray* tokens, network_mysqld_con* con) {

    con->conn_status.is_in_select_calc_found_rows = FALSE;
    con->conn_status.is_set_autocommit = FALSE;
    con->conn_status.is_savepoint = FALSE;
    con->conn_status.lock_stmt_type = LOCK_TYPE_NONE;
    con->conn_status.is_commit = INVALID_TYPE;
    con->conn_status.is_rollback = INVALID_TYPE;    
    g_string_truncate(con->conn_status.lock_key, 0);
    g_string_truncate(con->conn_status.use_db, 0);
    g_string_truncate(con->conn_status.set_charset_client, 0);
    g_string_truncate(con->conn_status.set_charset_results, 0);
    g_string_truncate(con->conn_status.set_charset_connection, 0);
    if (con->conn_status.set_vars) {
        g_queue_free_full(con->conn_status.set_vars, (GDestroyNotify)set_var_free);
        con->conn_status.set_vars = NULL;
    }

    if (!con->conn_status.is_in_transaction &&
            con->client->conn_attr.autocommit_status != AUTOCOMMIT_TRUE) {
        con->conn_status.is_in_transaction = TRUE;
#ifdef PROXY_DEBUG
        g_log_dbproxy(g_debug, "set con in transaction because of con autocommit_status=false");
#endif
    }

    sql_token** ts = (sql_token**)(tokens->pdata);
    gint len = tokens->len;
    gint i = 1; // 第一个字符为命令类型，比如COM_QUERY
    gchar *set_var_name = NULL;
    gboolean is_session_var = FALSE;

    /* 部分命令可能没有TOKEN，比如COM_STATISTICS */
    if (tokens->len < i) {
        return TRUE;
    }

    i = skip_comment_token(tokens, 1);
    if (len - i > 4 && ts[i]->token_id == TK_SQL_SELECT) {
        guint lock_stmt_type = LOCK_TYPE_NONE;
        i = skip_comment_token(tokens, i+1);
        if (len - i > 5 && strcasecmp(ts[i]->text->str, "GET_LOCK") == 0) {
            lock_stmt_type = LOCK_TYPE_GET;
        } else if (len - i > 3 && strcasecmp(ts[i]->text->str, "RELEASE_LOCK") == 0) {
            lock_stmt_type = LOCK_TYPE_RELEASE;
        }
#if 0
            else if (len - i > 2 && strcasecmp(ts[i]->text->str, "FOUND_ROWS") == 0 ) {
            if (con->conn_status.info_funcs[INFO_FUNC_FOUND_ROWS].field_value >= 0) {
            gint j = 0;
            con->conn_status.is_found_rows = TRUE;
            g_string_free(con->conn_status.info_funcs[INFO_FUNC_FOUND_ROWS].field_name, TRUE);
            con->conn_status.info_funcs[INFO_FUNC_FOUND_ROWS].field_name = g_string_new(NULL);
            for (j = i; j < len; j++) {
                g_string_append_printf(con->conn_status.info_funcs[INFO_FUNC_FOUND_ROWS].field_name,
                                            "%s", ts[j]->text->str);
            }
            return FALSE;
            }
        } else if (len - i > 2 && strcasecmp(ts[i]->text->str, "LAST_INSERT_ID") == 0 ) {
            if (con->conn_status.info_funcs[INFO_FUNC_LAST_INSERT_ID].field_value >= 0) {
            gint j = 0;
            con->conn_status.is_last_insert_id = TRUE;
            g_string_free(con->conn_status.info_funcs[INFO_FUNC_LAST_INSERT_ID].field_name, TRUE);
            con->conn_status.info_funcs[INFO_FUNC_LAST_INSERT_ID].field_name = g_string_new(NULL);
            for (j = i; j < len; j++) {
                g_string_append_printf(con->conn_status.info_funcs[INFO_FUNC_LAST_INSERT_ID].field_name,
                                            "%s", ts[j]->text->str);
            }
            return FALSE;
            }
        } else if (len - i > 2 && strcasecmp(ts[i]->text->str, "ROW_COUNT") == 0 ) {
            gint j = 0;
            con->conn_status.is_row_count = TRUE;
            g_string_free(con->conn_status.info_funcs[INFO_FUNC_ROW_COUNT].field_name, TRUE);
            con->conn_status.info_funcs[INFO_FUNC_ROW_COUNT].field_name = g_string_new(NULL);
            for (j = i; j < len; j++) {
                g_string_append_printf(con->conn_status.info_funcs[INFO_FUNC_ROW_COUNT].field_name,
                                            "%s", ts[j]->text->str);
            }
            return FALSE;

        }
#endif
        if (lock_stmt_type != LOCK_TYPE_NONE) {
            i = skip_comment_token(tokens, i+1);
            if (len - i > 2 && ts[i]->token_id == TK_OBRACE) {
                i = skip_comment_token(tokens, i+1);
                if (len - i > 1) {
                    con->conn_status.lock_stmt_type = lock_stmt_type;
                    g_string_assign(con->conn_status.lock_key, ts[i]->text->str);
                }
            }
        }
    }

    for (i = 1; i < len; ++i) {
        if (ts[i]->token_id == TK_SQL_SQL_CALC_FOUND_ROWS) {
            con->conn_status.is_in_select_calc_found_rows = TRUE;
            break;
        }
    }

    i = skip_comment_token(tokens, 1);
    if (len - i > 1 && ts[i]->token_id == TK_SQL_USE) {
        i = skip_comment_token(tokens, i+1);
        if (len - i > 0) {
            g_string_assign(con->conn_status.use_db, ts[i]->text->str);
        }
    }

    i = skip_comment_token(tokens, 1);
    if (0 < len - i && ts[i]->token_id == TK_LITERAL) {
        if (strcasecmp(ts[i]->text->str, "commit") == 0) {
            con->conn_status.is_commit = parse_commit_rollback(ts, tokens, ++i);
        } else if (strcasecmp(ts[i]->text->str, "rollback") == 0) { 
            con->conn_status.is_rollback = parse_commit_rollback(ts, tokens, ++i);
        } else if (2 == len - i && strcasecmp(ts[i]->text->str, "savepoint") == 0)
            con->conn_status.is_savepoint = TRUE;
    }

    i = skip_comment_token(tokens, 1);
    if (len - i > 2 && ts[i]->token_id == TK_SQL_SET) {
		g_log_dbproxy(g_critical, "len  %d", len);
        while (i < len)
        {
			g_log_dbproxy(g_critical, "^^^^^^  ts[i]->text->str %d %s", i , ts[i]->text->str );
            is_session_var = FALSE;
            i = skip_comment_token(tokens, i+1);
            g_log_dbproxy(g_critical, "^^^^^^ 1111  %d %s", i , ts[i]->text->str );
            if (i < len && strcasecmp(ts[i]->text->str, "option") == 0) {
                i = skip_comment_token(tokens, i+1);
            }

            if (i < len && (strcasecmp(ts[i]->text->str, "GLOBAL") == 0 || strcasecmp(ts[i]->text->str, "@@GLOBAL") == 0)) {
                return FALSE;
            }

            if (i < len && (strcasecmp(ts[i]->text->str, "SESSION") == 0 || strcasecmp(ts[i]->text->str, "LOCAL") == 0))
            {
                is_session_var = TRUE;
                i = skip_comment_token(tokens, i+1);
            }
            else if (len - i > 1 && (strcasecmp(ts[i]->text->str, "@@session") == 0 || strcasecmp(ts[i]->text->str, "@@local") == 0))
            {
                i = skip_comment_token(tokens, i+1);
                if (i < len && ts[i]->token_id == TK_DOT)
                {
                    i = skip_comment_token(tokens, i+1);
                }
            }

            if (i - len >= 0) break;

            set_var_name = ts[i]->text->str;
            if (strncasecmp(set_var_name, "@@", 2) == 0) {
                set_var_name = set_var_name + 2;
            } else if (strncasecmp(set_var_name, "@", 1) == 0) {
                // 不支持用户自定义变量
				/*
					zhangming 2018/1/9 1:25
					但下面还有个判断 逗号的功能, 因为这里禁用了, 所以下面要放行
				*/
                return FALSE;
            }

            if ((strcasecmp(set_var_name, "TRANSACTION") == 0 && !is_session_var)
                || strcasecmp(set_var_name, "CHARACTER") == 0
                || strcasecmp(set_var_name, "PASSWORD") == 0
                || strcasecmp(set_var_name, "INSERT_ID") == 0) {
                return FALSE;
            }

            if (len - i > 3 && strcasecmp(set_var_name, "TRANSACTION") == 0) {
                int tx_iso_type = TX_ISO_UNKNOWN;

                i = skip_comment_token(tokens, i + 1);
                if ((i - len >= 0) || strcasecmp(ts[i]->text->str, "ISOLATION") != 0) break;

                i = skip_comment_token(tokens, i + 1);
                if ((i - len >= 0) || strcasecmp(ts[i]->text->str, "LEVEL") != 0) break;

                i = skip_comment_token(tokens, i + 1);
                if (i - len >= 0) break;

                if (strcasecmp(ts[i]->text->str, "READ") == 0) {
                        i = skip_comment_token(tokens, i + 1);
                        if (len - i > 0) {
                            if (strcasecmp(ts[i]->text->str, "UNCOMMITTED") == 0) {
                                tx_iso_type = TX_ISO_READ_UNCOMMITED;    
                            } else if (strcasecmp(ts[i]->text->str, "COMMITTED") == 0){
                                tx_iso_type = TK_ISO_READ_COMMITED;
                            } 
                        }
                } else if (strcasecmp(ts[i]->text->str, "REPEATABLE") == 0) {
                        i = skip_comment_token(tokens, i + 1);
                        if (len - i > 0) {
                            if (strcasecmp(ts[i]->text->str, "READ") == 0) {
                                tx_iso_type = TK_ISO_REPEATABLE_READ;
                            }
                        }
                } else if (strcasecmp(ts[i]->text->str, "SERIALIZABLE") == 0) {
                    tx_iso_type = TK_ISO_SERIAL;
                }
                
                if ((len - i > 0) && (tx_iso_type != TX_ISO_UNKNOWN)) { 
                    gchar *tx_iso_level = tx_iso_levels[tx_iso_type];
 
                    if (con->conn_status.set_vars == NULL) {
                        con->conn_status.set_vars = g_queue_new();
                    }
                    
                    set_var_queue_insert(con->conn_status.set_vars, "TX_ISOLATION", tx_iso_level, VALUE_IS_STRING);
                }
            } else if (len - i > 2 &&  strcasecmp(set_var_name, "AUTOCOMMIT") == 0) {
                i = skip_comment_token(tokens, i+1);
                if (len - i > 1 && ts[i]->token_id == TK_EQ) {
                    i = skip_comment_token(tokens, i+1);
                    if (len > i) {
                        char* str = ts[i]->text->str;
                        if (strcasecmp(str, "0") == 0 || strcasecmp(str, "OFF") == 0 || strcasecmp(str, "FALSE") == 0) {
                            con->conn_status.is_set_autocommit = TRUE;
                        }
                        else if (strcasecmp(str, "1") == 0 || strcasecmp(str, "ON") == 0 || strcasecmp(str, "TRUE") == 0) {
                            con->conn_status.is_set_autocommit =  TRUE;
                        }
                    }
                }
            } else if (len - i > 1 && strcasecmp(ts[i]->text->str, "NAMES") == 0) {
				g_log_dbproxy(g_critical, "&&&&&&&&&&  ts[i]->text->str %s", ts[i]->text->str);
                i = skip_comment_token(tokens, i + 1);
				g_log_dbproxy(g_critical, "&&&&&&&&&&222222222  ts[i]->text->str %s", ts[i]->text->str);
                if (len - i > 0) {
                    g_string_truncate(con->conn_status.set_charset_client, 0);
                    g_string_truncate(con->conn_status.set_charset_results, 0);
                    g_string_truncate(con->conn_status.set_charset_connection, 0);
                    g_string_assign(con->conn_status.set_charset_client, ts[i]->text->str);
                    g_string_assign(con->conn_status.set_charset_results, ts[i]->text->str);
                    g_string_assign(con->conn_status.set_charset_connection, ts[i]->text->str);
                }
            } else if (len - i > 2 && strcasecmp(set_var_name, "CHARACTER_SET_RESULTS") == 0) {
                i = skip_comment_token(tokens, i + 1);
                if (len - i > 1 && ts[i]->token_id == TK_EQ) {
                    i = skip_comment_token(tokens, i + 1);
                    if (len - i > 0) {
                        g_string_truncate(con->conn_status.set_charset_results, 0);
                        g_string_assign(con->conn_status.set_charset_results, ts[i]->text->str);
                    }
                }
            } else if (len - i > 2 && strcasecmp(set_var_name, "CHARACTER_SET_CLIENT") == 0) {
                i = skip_comment_token(tokens, i + 1);
                if (len - i > 1 && ts[i]->token_id == TK_EQ) {
                    i = skip_comment_token(tokens, i + 1);
                    if (len - i > 0) {
                        g_string_truncate(con->conn_status.set_charset_client, 0);
                        g_string_assign(con->conn_status.set_charset_client, ts[i]->text->str);
                    }
                }
            } else if (len - i > 2 && strcasecmp(set_var_name, "CHARACTER_SET_CONNECTION") == 0) {
                i = skip_comment_token(tokens, i + 1);
                if (len - i > 1 && ts[i]->token_id == TK_EQ) {
                    i = skip_comment_token(tokens, i + 1);
                    if (len - i > 0) {
                        g_string_truncate(con->conn_status.set_charset_connection, 0);
                        g_string_assign(con->conn_status.set_charset_connection, ts[i]->text->str);
                    }
                }
            }  else if (len - i > 2) {
                i = skip_comment_token(tokens, i + 1);
				g_log_dbproxy(g_critical, "$$$$$$$7227 %s ", ts[i]->text->str);
                if (len - i > 1 && ts[i]->token_id == TK_EQ) {
                    i = skip_comment_token(tokens, i + 1);
					g_log_dbproxy(g_critical, "$$$$$$$77 %s ", ts[i]->text->str);
                    if (len - i > 0) {
                        guint set_var_value_extra = 0;

                        // 不支持value为非常量
                        if (strncasecmp(ts[i]->text->str, "@@", 2) == 0){
                            return FALSE;
                        }

                        if (ts[i]->token_id == TK_STRING) {
                            set_var_value_extra |= VALUE_IS_STRING;
                        } else if (ts[i]->token_id == TK_MINUS) {
                            set_var_value_extra |= VALUE_IS_MINUS;
                            i = skip_comment_token(tokens, i + 1);
                        }
						g_log_dbproxy(g_critical, "$$$$$$$888 %s ", ts[i]->text->str);

                        if (len - i > 0) {
                            if (con->conn_status.set_vars == NULL) {
                                con->conn_status.set_vars = g_queue_new();
                            }
                            set_var_queue_insert(con->conn_status.set_vars, set_var_name, ts[i]->text->str, set_var_value_extra);
                        }
                    }
                }
            }

            i = skip_comment_token(tokens, i + 1);
		
		
			
				g_log_dbproxy(g_critical, "$$$$$$$666  %d ", i);
	
            if (i < len && ts[i]->token_id == TK_SEMICOLON) {
				
                break;
            }

//
            if (i < len && ts[i]->token_id != TK_COMMA) {
				/*
				zhangming 2018/1/9 1:06
				即使没有逗号, 也应该返回TRUE

				例如 set @var=1, 的长度为 5+1 = 6  (@var1 算一个长度)
				这里i 为5, 5<6, 而且 5 这个位置的token_id 就是逗号,所以继续, 
				                                                          不是逗号, return false, 语法不对, 
				但@已经被禁用使用了，这里必须 注释掉 return False;
				
				*/
				g_log_dbproxy(g_critical, "$$$$$$$  ts[i]->token_id != TK_COMMA %s", ts[i]->text->str);
                // 不支持表达式
               //return FALSE;
            }
        }
    }

    return TRUE;
}

gboolean is_in_blacklist(GPtrArray* tokens) {
    guint len = tokens->len;
    guint i;
    sql_token* token;
    guint first_not_comment = 0;

    first_not_comment = skip_comment_token(tokens, 1);
    if (first_not_comment >= len) {
	 g_log_dbproxy(g_warning, "is_in_blacklist aaaa");
	return FALSE;
    }

    token = tokens->pdata[first_not_comment];
    if (token->token_id == TK_SQL_DELETE ||
        token->token_id == TK_SQL_UPDATE ||
          (config->select_where_limit == SEL_ON &&
                      token->token_id == TK_SQL_SELECT)) {
        for (i = first_not_comment; i < len; ++i) {
            token = tokens->pdata[i];
			g_log_dbproxy(g_warning, "token is %s", token->text->str);
            if (token->token_id == TK_SQL_WHERE) break;
        }
        if (i == len){
			g_log_dbproxy(g_warning, "i is %d, len is %d, is_in_blacklist bbb", i, len);
			return TRUE;
		}
    }

    for (i = first_not_comment; i < len; ++i) {
        token = tokens->pdata[i];
        if (token->token_id == TK_OBRACE) {
            token = tokens->pdata[i-1];
            if (strcasecmp(token->text->str, "SLEEP") == 0) {
	 g_log_dbproxy(g_warning, "is_in_blacklist cc");
		return TRUE;
		}
        }
    }

    token = tokens->pdata[first_not_comment];
    if (token->token_id == TK_SQL_KILL) {
        return TRUE;
    }

    return FALSE;
}

gboolean sql_is_write(GPtrArray *tokens) {
    sql_token **ts = (sql_token**)(tokens->pdata);
    guint len = tokens->len;

    if (len > 1) {
        guint i = 1;
        sql_token_id token_id;

        i = skip_comment_token(tokens, i);
        if (i >= len) return FALSE;

        token_id = ts[i]->token_id;

        return (token_id != TK_SQL_SELECT && token_id != TK_SQL_SET && token_id != TK_SQL_USE && token_id != TK_SQL_SHOW && token_id != TK_SQL_DESC && token_id != TK_SQL_EXPLAIN);
    } else {
        return TRUE;
    }
}

static void sql_rw_split(GPtrArray* tokens, network_mysqld_con* con, char type, gboolean is_write) {
    gboolean b_master = FALSE;
    network_mysqld_con_lua_t *st = con->plugin_con_state;
    network_backend_t *backend = NULL;
    gchar *backend_tag = NULL;
    gint backend_ndx = -1;

    if (con->client->conn_attr.autocommit_status == AUTOCOMMIT_FALSE
        || con->conn_status.is_set_autocommit
        || con->conn_status.lock_stmt_type != LOCK_TYPE_NONE) {
        b_master = TRUE;
        if (TRACE_SQL(con->srv->log->log_trace_modules)) {
            CON_MSG_HANDLE(g_message, con, "autocommit/lock stmt and in transaction "
                                                    "requires sending to master");
        }
    } else if (type == COM_QUERY) {
        if (is_write) {
            b_master = TRUE;
            if (TRACE_SQL(con->srv->log->log_trace_modules)) {
                CON_MSG_HANDLE(g_message, con, "write query requires sending to master");
            }
        } else {
            sql_token* first_token = tokens->pdata[1];
            if (first_token->token_id == TK_COMMENT && strcasecmp(first_token->text->str, "MASTER") == 0) {
                b_master = TRUE;
                if (TRACE_SQL(con->srv->log->log_trace_modules)) {
                    CON_MSG_HANDLE(g_message, con, "query starting with /*master*/ "
                                                        "requires sending to master");
                }
            } else if (first_token->token_id == TK_COMMENT &&
                            strncasecmp(first_token->text->str, "slave@",
                                            strlen("slave@") - 1) == 0) {
                b_master = FALSE;
                backend_tag = g_strdup(first_token->text->str + strlen("slave@"));
                if (TRACE_SQL(con->srv->log->log_trace_modules)) {
                    gchar *msg = g_strdup_printf("query starting with %s requires "
                                "sending to slave with tag:%s", first_token->text->str, backend_tag);
                    CON_MSG_HANDLE(g_message, con, msg);
                    g_free(msg);
                }
            } else {
                b_master = FALSE;
            }
        }
    } else if (type == COM_INIT_DB || type == COM_SET_OPTION || type == COM_FIELD_LIST) {
        b_master = FALSE;
    } else {
        if (TRACE_SQL(con->srv->log->log_trace_modules)) {
                    gchar *msg = g_strdup_printf("%s requires sending to master", GET_COM_NAME(type));
                    CON_MSG_HANDLE(g_message, con, msg);
                    g_free(msg);
                }
        b_master = TRUE;
    }

    // 如果当前需要发往主库，则检查当前的db连接是否为主库连接，如果不是则不能使用当前db连接
    if (b_master && con->server != NULL)
    {
        backend_ndx = -1;
        g_rw_lock_reader_lock(&con->srv->backends->backends_lock);
        backend = idle_rw(con, &backend_ndx);
        g_rw_lock_reader_unlock(&con->srv->backends->backends_lock);

        if (backend != st->backend)
        {
            network_backend_t *old_backend = st->backend;
            if (TRACE_SQL(con->srv->log->log_trace_modules)) {
                gchar *msg = g_strdup_printf("current backend(%d) isn't the master node(%d), "
                                            "DBProxy will close the connnection to this backend, then try to get a new master backend.",
                                             st->backend_ndx, backend_ndx);
                CON_MSG_HANDLE(g_message, con, msg);
                g_free(msg);
            }
            //network_connection_pool_lua_add_connection(con);
            network_socket_free(con->server);
            con->server = NULL;
            if (st->backend) {
                g_atomic_int_dec_and_test(&st->backend->connected_clients);
                st->backend = NULL;
                st->backend_ndx = -1;
            } else {
                g_log_dbproxy(g_critical, "unexpected case encountered");
            }
            if (old_backend != NULL && old_backend->type == BACKEND_TYPE_RW
                 && (con->conn_status.is_in_transaction || con->locks && g_hash_table_size(con->locks) > 0
                     || con->client && con->client->conn_attr.savepoint_flag)) {
                //if old backend is RW, the err-message is still 'I have no server backend', fix it later.
                if (backend_tag != NULL) { g_free(backend_tag); }
                g_log_dbproxy(g_warning, "candidate master-backend is not the original, close both connections");
                return;
            }
        }
    }

    if (!b_master && con->server == NULL)
    {
        backend_ndx = -1;
        g_rw_lock_reader_lock(&con->srv->backends->backends_lock);
        backend = wrr_ro(con, &backend_ndx, backend_tag);
        if (backend != NULL) {
            g_atomic_int_inc(&backend->connected_clients);
        }
        g_rw_lock_reader_unlock(&con->srv->backends->backends_lock);

        if (TRACE_SQL(con->srv->log->log_trace_modules)) {
            gchar *msg = g_strdup_printf("get read_only backend id:%d", backend_ndx);
            CON_MSG_HANDLE(g_message, con, msg);
            g_free(msg);
        }

        con->server = network_connection_pool_lua_swap(con, backend, backend_ndx,
                                                        con->srv->backends->pwd_table, 1);
        if (backend != NULL && con->server == NULL) {
            g_atomic_int_dec_and_test(&backend->connected_clients);
        }
    }

	/*
	zhangming 2018/1/14 22:21
	刚启动时, 是没有下面这个值的
	*/
    if (con->server == NULL) {
        backend_ndx = -1;
        g_rw_lock_reader_lock(&con->srv->backends->backends_lock);
        backend = idle_rw(con, &backend_ndx);
        if (backend != NULL) {
            g_atomic_int_inc(&backend->connected_clients);
        }
        g_rw_lock_reader_unlock(&con->srv->backends->backends_lock);

        if ( TRACE_SQL(con->srv->log->log_trace_modules)) {
            gchar *msg = g_strdup_printf("get read_write backend id:%d", backend_ndx);
            CON_MSG_HANDLE(g_message, con, msg);
            g_free(msg);
        }
		 g_log_dbproxy(g_critical, "ccccccccccccccc %d", backend_ndx);
		
		/*
		zhangming 2018/1/14 22:29
		是否是主库, 传到network_connection_pool_lua_swap函数中,根据类型, 取不同的账号和密码
		
		函数 
		NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth) {
		get_hash_passwd(bs->pwd_table, auth->username->str, &bs->user_mgr_lock, NULL, 0);

		最后一个参数 是 is_master 为0
		*/

		
		gint is_master = 1;
		if(b_master) {
			is_master = 2;
		}
		
		g_log_dbproxy(g_message, "sql_rw_split is_master is %d", is_master);

        con->server = network_connection_pool_lua_swap(con, backend, backend_ndx,
                                                        con->srv->backends->pwd_table, is_master);
        if (backend != NULL && con->server == NULL) {
            g_atomic_int_dec_and_test(&backend->connected_clients);
        }
    }

    if (backend_tag != NULL) { g_free(backend_tag); }

    return ;
}

/**
 * gets called after a query has been read
 *
 * - calls the lua script via network_mysqld_con_handle_proxy_stmt()
 *
 * @see network_mysqld_con_handle_proxy_stmt
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query) {
    GString *packet;
    network_socket *recv_sock, *send_sock;
    network_mysqld_con_lua_t *st = con->plugin_con_state;
    int proxy_query = 1;
    network_mysqld_lua_stmt_ret ret;

    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::enter");

    send_sock = NULL;
    recv_sock = con->client;
    st->injected.sent_resultset = 0;

    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::enter_lua");
    network_injection_queue_reset(st->injected.queries);

    GString* packets = g_string_new(NULL);
    int i;
    for (i = 0; NULL != (packet = g_queue_peek_nth(recv_sock->recv_queue->chunks, i)); i++) {
        g_string_append_len(packets, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);
    }

    char type = packets->str[0];
    if (type == COM_QUIT || type == COM_PING) {
        g_string_free(packets, TRUE);
        network_mysqld_con_send_ok_full(con->client, 0, 0, 0x0002, 0);
        ret = PROXY_SEND_RESULT;
        con->conn_status_var.cur_query_com_type = type;
        con->conn_status_var.cur_query_start_time = chassis_get_rel_microseconds();
        log_sql_client(config->sql_log_mgr, con);
    } else {
        const char *cur_query = NULL;
        if (packets->len > 1) {
            cur_query = packets->str + 1;
        }

        network_mysqld_stat_stmt_start(con, cur_query, type);
        log_sql_client(config->sql_log_mgr, con);

        GPtrArray *tokens = sql_tokens_new();
        sql_tokenizer(tokens, packets->str, packets->len);

        if (TRACE_SQL(con->srv->log->log_trace_modules)) {
            CON_MSG_HANDLE(g_message, con, "sql parse success");
        }
g_log_dbproxy(g_critical, "******** is %s %d %d", GET_COM_NAME(type), type, COM_STMT_PREPARE);
        if (type == COM_QUERY && tokens->len <= 1) {
            gchar *errmsg = g_strdup_printf("%s was empty", GET_COM_NAME(type));
            network_mysqld_con_send_error_full_nolog(con->client, C_S(errmsg),
                                               ER_EMPTY_QUERY, "42000");
            SEND_ERR_MSG_HANDLE(g_critical, errmsg, con->client);
            g_string_free(packets, TRUE);
            g_free(errmsg);
            ret = PROXY_SEND_RESULT;
        } else if (IS_UNSUPPORTED_COM_TYPE(type)
            || (type == COM_QUERY && is_in_blacklist(tokens))
            || !check_flags(tokens, con)) {
#if 0
            if (con->conn_status.is_found_rows) {
                    network_mysqld_con_send_1_int_resultset(con, INFO_FUNC_FOUND_ROWS);
                con->conn_status.is_found_rows = FALSE;
                reset_funcs_info(con->conn_status.info_funcs);
            } else if (con->conn_status.is_last_insert_id) {
                network_mysqld_con_send_1_int_resultset(con, INFO_FUNC_LAST_INSERT_ID);
                con->conn_status.is_last_insert_id = FALSE;
                reset_funcs_info(con->conn_status.info_funcs);
            } else if (con->conn_status.is_row_count) {
                network_mysqld_con_send_1_int_resultset(con, INFO_FUNC_ROW_COUNT);
                con->conn_status.is_row_count = FALSE;
                reset_funcs_info(con->conn_status.info_funcs);
            } else {
 #endif
	
			if(IS_UNSUPPORTED_COM_TYPE(type))	 {
				 g_log_dbproxy(g_critical, "!!!!!!!!!!!!!!!!!!!!!!!!!! is %s %d %d", GET_COM_NAME(type), type, COM_STMT_PREPARE);
			}else if(type == COM_QUERY && is_in_blacklist(tokens)){
				
			}else if(!check_flags(tokens, con)){
				g_log_dbproxy(g_critical, "########### !check_flags");
			}
			
            gchar *errmsg = g_strdup_printf("Proxy Warning - Syntax Forbidden %s:%s",
                                    GET_COM_NAME(type),
                                    packets->str+1);
            g_string_free(packets, TRUE);
            network_mysqld_con_send_error_full_nolog(con->client,
                                        C_S(errmsg),
                                        ER_UNKNOWN_ERROR, "07000");

            SEND_ERR_MSG_HANDLE(g_critical, errmsg, con->client);
            g_free(errmsg);
                reset_funcs_info(con->conn_status.info_funcs);
#if 0
            }
#endif
            ret = PROXY_SEND_RESULT;
        } else if (type == COM_QUERY && filter_pre(tokens, con, packets->str+1) == 1) {
            g_string_free(packets, TRUE);
            network_mysqld_con_send_error_full_nolog(con->client,
                                        C("Proxy Warning - Blacklist Forbidden"),
                                        ER_UNKNOWN_ERROR, "07000");
            SEND_ERR_MSG_HANDLE(g_critical, "Proxy Warning - Blacklist Forbidden", con->client);
            reset_funcs_info(con->conn_status.info_funcs);
            ret = PROXY_SEND_RESULT;
        } else {
            GPtrArray* sqls = NULL;

            reset_funcs_info(con->conn_status.info_funcs);

            if (type == COM_QUERY && g_hash_table_size(config->dt_table) > 0) {
                sqls = sql_parse(con, tokens);
            }

            gboolean is_write = sql_is_write(tokens);

            network_mysqld_stat_stmt_parser_end(con, type, is_write);

            ret = PROXY_SEND_INJECTION;
            injection* inj = NULL;
            if (sqls == NULL) {
                gint inj_type = is_write ? INJECTION_EXPLICIT_SINGLE_WRITE_QUERY : INJECTION_EXPLICIT_SINGLE_READ_QUERY;
                inj = injection_new(inj_type, packets);
                inj->resultset_is_needed = is_write;
                g_queue_push_tail(st->injected.queries, inj);
            } else {
                if (sqls->len == 1) {
                    gint inj_type = is_write ? INJECTION_EXPLICIT_SINGLE_WRITE_QUERY : INJECTION_EXPLICIT_SINGLE_READ_QUERY;
                    inj = injection_new(inj_type, sqls->pdata[0]);
                    inj->resultset_is_needed = is_write;
                    g_queue_push_tail(st->injected.queries, inj);
                } else {
                    merge_res_t* merge_res = con->merge_res;

                    merge_res->sub_sql_num = sqls->len;
                    merge_res->sub_sql_exed = 0;
                    merge_res->limit = G_MAXINT;
                    merge_res->affected_rows = 0;
                    merge_res->warnings = 0;

                    if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
                        gchar *msg = g_strdup_printf("current query has %d results to be merged", sqls->len);
                        CON_MSG_HANDLE(g_message, con, msg);
                        g_free(msg);
                    }

                    sql_token** ts = (sql_token**)(tokens->pdata);
                    for (i = tokens->len-2; i >= 0; --i) {
                        if (ts[i]->token_id == TK_SQL_LIMIT && ts[i+1]->token_id == TK_INTEGER) {
                            merge_res->limit = atoi(ts[i+1]->text->str);
                            break;
                        }
                    }

                    GPtrArray* rows = merge_res->rows;
                    for (i = 0; i < rows->len; ++i) {
                        GPtrArray* row = g_ptr_array_index(rows, i);
                        guint j;
                        for (j = 0; j < row->len; ++j) {
                            g_free(g_ptr_array_index(row, j));
                        }
                        g_ptr_array_free(row, TRUE);
                    }
                    g_ptr_array_set_size(rows, 0);

                    int id = is_write ? INJECTION_EXPLICIT_MULTI_WRITE_QUERY : INJECTION_EXPLICIT_MULTI_READ_QUERY;
                    for (i = 0; i < sqls->len; ++i) {
                        inj = injection_new(id, sqls->pdata[i]);
                        inj->resultset_is_needed = TRUE;
                        g_queue_push_tail(st->injected.queries, inj);
                    }
                }
                g_string_free(packets, TRUE);
                g_ptr_array_free(sqls, TRUE);
            }

            sql_rw_split(tokens, con, type, is_write);

            if (con->server == NULL)
            {
                gchar *msg = "I have no server backend, closing connection";
                sql_tokens_free(tokens);
                CON_MSG_HANDLE(g_critical, con, msg);
                SEND_INTERNAL_ERR(msg);
                return NETWORK_SOCKET_ERROR;
            }

           /* save start time */
            g_assert(st->injected.queries != NULL);
            GList *tmp = g_queue_peek_nth_link(st->injected.queries, 0);
            con->con_filter_var.ts_read_query = ((injection *)tmp->data)->ts_read_query;

            proxy_reinitialize_db_connection(con);
        }

        sql_tokens_free(tokens);
    }
    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::leave_lua");

    switch (ret) {
    case PROXY_NO_DECISION:
    case PROXY_SEND_QUERY:
        send_sock = con->server;

        /* no injection, pass on the chunks as is */
        while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) {
            network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, packet);
        }
        con->resultset_is_needed = FALSE; /* we don't want to buffer the result-set */

        break;
    case PROXY_SEND_RESULT: {
        gboolean is_first_packet = TRUE;
        proxy_query = 0;

        send_sock = con->client;

        /* flush the recv-queue and track the command-states */
        while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) {
            if (is_first_packet) {
                network_packet p;

                p.data = packet;
                p.offset = 0;

                network_mysqld_con_reset_command_response_state(con);

                network_mysqld_con_command_states_init(con, &p);

                is_first_packet = FALSE;
            }

            g_string_free(packet, TRUE);
        }

        break; }
    case PROXY_SEND_INJECTION: {
        injection *inj;

        inj = g_queue_peek_head(st->injected.queries);
        con->resultset_is_needed = inj->resultset_is_needed; /* let the lua-layer decide if we want to buffer the result or not */

        send_sock = con->server;

        network_mysqld_queue_reset(send_sock);
        network_mysqld_queue_append(send_sock, send_sock->send_queue, S(inj->query));

        network_mysqld_send_query_stat(con, inj->query->str[0], IS_EXPLICIT_WRITE_QUERY(inj));

        while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(packet, TRUE);

        break; }
    default:
        CON_MSG_HANDLE(g_error, con, "invalid lua stmt ret");
    }

    if (proxy_query) {
        con->state = CON_STATE_SEND_QUERY;
    } else {
        GList *cur;

        /* if we don't send the query to the backend, it won't be tracked. So track it here instead 
         * to get the packet tracking right (LOAD DATA LOCAL INFILE, ...) */

        for (cur = send_sock->send_queue->chunks->head; cur; cur = cur->next) {
            network_packet p;
            int r;

            p.data = cur->data;
            p.offset = 0;

            r = network_mysqld_proto_get_query_result(&p, con);
        }

        con->state = CON_STATE_SEND_QUERY_RESULT;
        con->resultset_is_finished = TRUE; /* we don't have more too send */
    }
    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::done");

    return NETWORK_SOCKET_SUCCESS;
}

/**
 * decide about the next state after the result-set has been written 
 * to the client
 * 
 * if we still have data in the queue, back to proxy_send_query()
 * otherwise back to proxy_read_query() to pick up a new client query
 *
 * @note we should only send one result back to the client
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_query_result) {

    network_socket *recv_sock, *send_sock;
    injection *inj;
    network_mysqld_con_lua_t *st = con->plugin_con_state;

    send_sock = con->server;
    recv_sock = con->client;

    if (st->connection_close) {
        con->state = CON_STATE_ERROR;

        return NETWORK_SOCKET_SUCCESS;
    }

    if (con->parse.command == COM_BINLOG_DUMP) {
        /**
         * the binlog dump is different as it doesn't have END packet
         *
         * @todo in 5.0.x a NON_BLOCKING option as added which sends a EOF
         */
        con->state = CON_STATE_READ_QUERY_RESULT;

        return NETWORK_SOCKET_SUCCESS;
    }

    /* if we don't have a backend, don't try to forward queries
     */
    if (!send_sock) {
        network_injection_queue_reset(st->injected.queries);
    }

    if (st->injected.queries->length == 0) {
        gint64 cur_time = chassis_get_rel_microseconds();
        gint64 respon_time = cur_time - con->conn_status_var.cur_query_start_time;
        if (respon_time > con->srv->long_query_time * 1000) {
            log_sql_slow(config->sql_log_mgr, con, respon_time);
        }
        /* we have nothing more to send, let's see what the next state is */
        network_mysqld_stat_stmt_end(con, cur_time);

        con->state = CON_STATE_READ_QUERY;
		g_log_dbproxy(g_message, "即将进入CON_STATE_READ_QUERY, 读取客户端 数据 "); 

		g_log_dbproxy(g_message, "这里写大表"); 
        return NETWORK_SOCKET_SUCCESS;
    }

    /* looks like we still have queries in the queue, 
     * push the next one 
     */
    inj = g_queue_peek_head(st->injected.queries);
    con->resultset_is_needed = inj->resultset_is_needed;

	 gchar *msg = g_strdup_printf("庹文颢 @@@@@@@@@ NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_query_result) %s:%s",
                                                                    GET_COM_STRING(inj->query));
                    CON_MSG_HANDLE(g_message, con, msg);


    if (!inj->resultset_is_needed && st->injected.sent_resultset > 0) {
        /* we already sent a resultset to the client and the next query wants to forward it's result-set too, that can't work */
        g_log_dbproxy(g_warning, "proxy.queries:append() in %s can only have one injected query without { resultset_is_needed = true } set. We close the client connection now", config->lua_script);

        return NETWORK_SOCKET_ERROR;
    }

    g_assert(inj);
    g_assert(send_sock);

    network_mysqld_queue_reset(send_sock);
    network_mysqld_queue_append(send_sock, send_sock->send_queue, S(inj->query));

    network_mysqld_send_query_stat(con, inj->query->str[0], IS_EXPLICIT_WRITE_QUERY(inj));


    network_mysqld_con_reset_command_response_state(con);

    con->state = CON_STATE_SEND_QUERY;

    return NETWORK_SOCKET_SUCCESS;
}

void merge_rows(network_mysqld_con* con, injection* inj) {
    if (!inj->resultset_is_needed || !con->server->recv_queue->chunks || inj->qstat.binary_encoded) return;

    proxy_resultset_t* res = proxy_resultset_new();

    res->result_queue = con->server->recv_queue->chunks;
    res->qstat = inj->qstat;
    res->rows  = inj->rows;
    res->bytes = inj->bytes;

    if (parse_resultset_fields(res) != 0) {
        if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
            CON_MSG_HANDLE(g_warning, con, "parse result fields failed during merge_rows");
        }
    }

    GList* res_row = res->rows_chunk_head;
    while (res_row) {
        network_packet packet;
        packet.data = res_row->data;
        packet.offset = 0;

        network_mysqld_proto_skip_network_header(&packet);
        network_mysqld_lenenc_type lenenc_type;
        network_mysqld_proto_peek_lenenc_type(&packet, &lenenc_type);

        switch (lenenc_type) {
            case NETWORK_MYSQLD_LENENC_TYPE_ERR:
            case NETWORK_MYSQLD_LENENC_TYPE_EOF:
                proxy_resultset_free(res);
                return;

            case NETWORK_MYSQLD_LENENC_TYPE_INT:
            case NETWORK_MYSQLD_LENENC_TYPE_NULL:
                break;
        }

        GPtrArray* row = g_ptr_array_new();

        guint len = res->fields->len;
        guint i;
        for (i = 0; i < len; i++) {
            guint64 field_len;

            network_mysqld_proto_peek_lenenc_type(&packet, &lenenc_type);

            switch (lenenc_type) {
                case NETWORK_MYSQLD_LENENC_TYPE_NULL:
                    g_ptr_array_add(row, NULL);
                    network_mysqld_proto_skip(&packet, 1);
                    break;

                case NETWORK_MYSQLD_LENENC_TYPE_INT:
                    network_mysqld_proto_get_lenenc_int(&packet, &field_len);
                    g_ptr_array_add(row, g_strndup(packet.data->str + packet.offset, field_len));
                    network_mysqld_proto_skip(&packet, field_len);
                    break;

                default:
                    break;
            }
        }

        g_ptr_array_add(con->merge_res->rows, row);
        if (con->merge_res->rows->len >= con->merge_res->limit) break;
        res_row = res_row->next;
    }

    proxy_resultset_free(res);
}

static void proxy_update_conn_attribute(network_mysqld_con *con, injection *inj)
{
    if (IS_EXPLICIT_INJ(inj)) {
        if (con->parse.command == COM_INIT_DB && inj->qstat.query_status == MYSQLD_PACKET_OK)
        {
            g_string_truncate(con->server->conn_attr.default_db, 0);
            g_string_append(con->server->conn_attr.default_db, inj->query->str + 1);
            g_string_truncate(con->client->conn_attr.default_db, 0);
            g_string_append(con->client->conn_attr.default_db, inj->query->str + 1);
        } else if (con->parse.command == COM_QUERY && inj->qstat.query_status == MYSQLD_PACKET_OK){
            if (con->conn_status.set_vars != NULL&& con->conn_status.set_vars->length > 0)
            {
                    set_var_queue_merge(con->server->conn_attr.set_vars, con->conn_status.set_vars);
                    set_var_queue_merge(con->client->conn_attr.set_vars, con->conn_status.set_vars);
            }

            if (con->conn_status.use_db->len > 0)
            {
                g_string_truncate(con->server->conn_attr.default_db, 0);
                g_string_append(con->server->conn_attr.default_db, con->conn_status.use_db->str);
                g_string_truncate(con->client->conn_attr.default_db, 0);
                g_string_append(con->client->conn_attr.default_db, con->conn_status.use_db->str);
            }

            if (con->conn_status.lock_stmt_type == LOCK_TYPE_GET)
            {
                if (!g_hash_table_lookup(con->locks, con->conn_status.lock_key->str)) g_hash_table_add(con->locks, g_strdup(con->conn_status.lock_key->str));
            } else if (con->conn_status.lock_stmt_type == LOCK_TYPE_RELEASE) {
                g_hash_table_remove(con->locks, con->conn_status.lock_key->str);
            }

            if (con->conn_status.set_charset_client->len > 0) {
                g_string_truncate(con->client->conn_attr.charset_client, 0);
                g_string_append(con->client->conn_attr.charset_client, con->conn_status.set_charset_client->str);
                g_string_truncate(con->server->conn_attr.charset_client, 0);
                g_string_append(con->server->conn_attr.charset_client, con->conn_status.set_charset_client->str);
            }

            if (con->conn_status.set_charset_results->len > 0) {
                g_string_truncate(con->client->conn_attr.charset_results, 0);
                g_string_append(con->client->conn_attr.charset_results, con->conn_status.set_charset_results->str);
                g_string_truncate(con->server->conn_attr.charset_results, 0);
                g_string_append(con->server->conn_attr.charset_results, con->conn_status.set_charset_results->str);
            }

            if (con->conn_status.set_charset_connection->len > 0) {
                g_string_truncate(con->client->conn_attr.charset_connection, 0);
                g_string_append(con->client->conn_attr.charset_connection, con->conn_status.set_charset_connection->str);
                g_string_truncate(con->server->conn_attr.charset_connection, 0);
                g_string_append(con->server->conn_attr.charset_connection, con->conn_status.set_charset_connection->str);
            }

            if (con->conn_status.is_set_autocommit || con->client->conn_attr.autocommit_status == AUTOCOMMIT_UNKNOWN) {
                if ((inj->qstat.server_status & SERVER_STATUS_AUTOCOMMIT) > 0) {
                    con->client->conn_attr.autocommit_status = con->server->conn_attr.autocommit_status = AUTOCOMMIT_TRUE;
                    con->client->conn_attr.savepoint_flag = FALSE;
                } else {
                    con->client->conn_attr.autocommit_status = con->server->conn_attr.autocommit_status = AUTOCOMMIT_FALSE;
                }
            }

            if (con->conn_status.is_savepoint) {
                if (con->client->conn_attr.autocommit_status != AUTOCOMMIT_TRUE)
                    con->client->conn_attr.savepoint_flag = TRUE;
                else
                    con->client->conn_attr.savepoint_flag = FALSE;
            }

            if (con->conn_status.is_rollback != INVALID_TYPE ||con->conn_status.is_commit != INVALID_TYPE) {
                con->client->conn_attr.savepoint_flag = FALSE;
            }

            if (inj->id == INJECTION_EXPLICIT_SINGLE_READ_QUERY) {
                con->conn_status.info_funcs[INFO_FUNC_ROW_COUNT].field_value = -1;
                con->conn_status.info_funcs[INFO_FUNC_FOUND_ROWS].field_value = inj->rows;
            } else if (inj->id == INJECTION_EXPLICIT_SINGLE_WRITE_QUERY) {
                con->conn_status.info_funcs[INFO_FUNC_ROW_COUNT].field_value = inj->qstat.affected_rows;
                if ((gint)inj->qstat.insert_id > 0) {
                    con->conn_status.info_funcs[INFO_FUNC_LAST_INSERT_ID].field_value = inj->qstat.insert_id;
                }
            }
        }

        if (con->parse.command == COM_QUERY) {
                if (inj->qstat.query_status == MYSQLD_PACKET_OK) {
                    if (inj->qstat.server_status & SERVER_STATUS_IN_TRANS)
                        con->client->conn_attr.savepoint_flag = FALSE;
                    con->conn_status.is_in_transaction = ((inj->qstat.server_status & SERVER_STATUS_IN_TRANS)
                                                            || con->client->conn_attr.savepoint_flag);
                }

            if (TRACE_SQL(con->srv->log->log_trace_modules)) {
                GString *p = g_string_new(NULL);
                g_string_append_printf(p, "[C:%s S:%s(%u)] con_autocommit = [%s], con_in_trx = [%s], server_in_trx = [%s]",
                                con->client->src->name->str, con->server->dst->name->str, con->server->challenge->thread_id,
                                (con->client->conn_attr.autocommit_status == AUTOCOMMIT_FALSE ? "FALSE":
                                        (con->client->conn_attr.autocommit_status == AUTOCOMMIT_TRUE ? "TRUE" : "UNKNOWN")),
                                con->conn_status.is_in_transaction ? "TRUE" : "FALSE",
                                inj->qstat.server_status & SERVER_STATUS_IN_TRANS ? "TRUE" : "FALSE");
                CON_MSG_HANDLE(g_message, con, p->str);
                g_string_free(p, TRUE);
            }
       }
    } else if (con->server) {
        if (inj->id == INJECTION_IMPLICIT_CHANGE_DB) {
            g_string_truncate(con->server->conn_attr.default_db, 0);
            g_string_append(con->server->conn_attr.default_db, con->client->conn_attr.default_db->str);
        } else if (inj->id == INJECTION_IMPLICIT_CHANGE_CHARSET_CLIENT) {
            g_string_truncate(con->server->conn_attr.charset_client, 0);
            g_string_append(con->server->conn_attr.charset_client, con->client->conn_attr.charset_client->str);
        } else if (inj->id == INJECTION_IMPLICIT_CHANGE_CHARSET_RESULTS) {
            g_string_truncate(con->server->conn_attr.charset_results, 0);
            g_string_append(con->server->conn_attr.charset_results, con->client->conn_attr.charset_results->str);
        } else if (inj->id == INJECTION_IMPLICIT_CHANGE_CHARSET_CONNECTION) {
            g_string_truncate(con->server->conn_attr.charset_connection, 0);
            g_string_append(con->server->conn_attr.charset_connection, con->client->conn_attr.charset_connection->str);
        } else if (inj->id == INJECTION_IMPLICIT_SET_AUTOCOMMIT) {
            con->server->conn_attr.autocommit_status = con->client->conn_attr.autocommit_status;
        } else if (inj->id == INJECTION_IMPLICIT_GET_FOUND_ROWS ||
                    inj->id == INJECTION_IMPLICIT_LAST_INSERT_ID) {
                    gint info_func_type =
                        (inj->id == INJECTION_IMPLICIT_GET_FOUND_ROWS) ?
                                INFO_FUNC_FOUND_ROWS : INFO_FUNC_LAST_INSERT_ID;

                    con->conn_status.is_in_select_calc_found_rows = FALSE;
                    con->conn_status.info_funcs[info_func_type].field_value =
                            network_mysqld_con_get_1_int_from_result_set(con, inj);
        } else if (inj->id == INJECTION_IMPLICIT_SET) {
            if (con->server != NULL) {
                set_var_unit *set_var = NULL;
                while ((set_var = g_queue_pop_head(con->server->conn_attr.set_vars))) {
                    set_var_free(set_var);
                }

                GList *set_vars = g_queue_peek_head_link(con->client->conn_attr.set_vars);
                while (set_vars != NULL) {
                    g_queue_push_tail(con->server->conn_attr.set_vars, set_var_copy(set_vars->data, NULL));
                    set_vars = g_list_next(set_vars);
                }
            }
        }
    }
}

/**
 * handle the query-result we received from the server
 *
 * - decode the result-set to track if we are finished already
 * - handles BUG#25371 if requested
 * - if the packet is finished, calls the network_mysqld_con_handle_proxy_resultset
 *   to handle the resultset in the lua-scripts
 *
 * @see network_mysqld_con_handle_proxy_resultset
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query_result) {
    int is_finished = 0;
    network_packet packet;
    network_socket *recv_sock, *send_sock;
    network_mysqld_con_lua_t *st = con->plugin_con_state;
    injection *inj = NULL;

    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter");

    recv_sock = con->server;
    send_sock = con->client;

    /* check if the last packet is valid */
    packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
    packet.offset = 0;

    if (0 != st->injected.queries->length) {
        inj = g_queue_peek_head(st->injected.queries);
    }

    if (inj && inj->ts_read_query_result_first == 0) {
        /**
         * log the time of the first received packet
         */
        inj->ts_read_query_result_first = chassis_get_rel_microseconds();
        /* g_get_current_time(&(inj->ts_read_query_result_first)); */
    }

    // FIX
    //if(inj) {
    //  g_string_assign_len(con->current_query, inj->query->str, inj->query->len);
    //}

    is_finished = network_mysqld_proto_get_query_result(&packet, con);
    if (is_finished == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

    con->resultset_is_finished = is_finished;

    /* copy the packet over to the send-queue if we don't need it */
    if (!con->resultset_is_needed) {
        network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, g_queue_pop_tail(recv_sock->recv_queue->chunks));
    }

    if (is_finished) {
        network_mysqld_lua_stmt_ret ret;

        /**
         * the resultset handler might decide to trash the send-queue
         * 
         * */
        if (inj) {
            if (con->parse.command == COM_QUERY || con->parse.command == COM_STMT_EXECUTE) {
                network_mysqld_com_query_result_t *com_query = con->parse.data;

                inj->bytes = com_query->bytes;
                inj->rows  = com_query->rows;
                inj->qstat.was_resultset = com_query->was_resultset;
                inj->qstat.binary_encoded = com_query->binary_encoded;

                /* INSERTs have a affected_rows */
                if (!com_query->was_resultset) {
                    inj->qstat.affected_rows = com_query->affected_rows;
                    inj->qstat.insert_id     = com_query->insert_id;
#if 0
                    if ((gint) inj->qstat.insert_id < 0 &&
                                inj->id != INJECTION_EXPLICIT_MULTI_WRITE_QUERY) {
                        modify_last_insert_id(con);
                    }
#endif
                }
                inj->qstat.server_status = com_query->server_status;
                inj->qstat.warning_count = com_query->warning_count;
                inj->qstat.query_status  = com_query->query_status;
            } else if (con->parse.command == COM_INIT_DB) {
                inj->qstat.query_status  = *(guint8 *)con->parse.data;
            }
            inj->ts_read_query_result_last = chassis_get_rel_microseconds();
            /* g_get_current_time(&(inj->ts_read_query_result_last)); */
        }

        network_mysqld_queue_reset(recv_sock); /* reset the packet-id checks as the server-side is finished */

        NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter_lua");
        GString* p;
        if (0 != st->injected.queries->length) {
            inj = g_queue_pop_head(st->injected.queries);
            if (IS_EXPLICIT_SINGLE_QUERY(inj)) {
                log_sql_backend(config->sql_log_mgr, con, (void *)inj);
                ret = PROXY_SEND_RESULT;
            } else if (inj->id == INJECTION_EXPLICIT_MULTI_READ_QUERY) {
                log_sql_backend(config->sql_log_mgr, con, (void *)inj);

                merge_res_t* merge_res = con->merge_res;
                if (inj->qstat.query_status == MYSQLD_PACKET_OK &&
                                    merge_res->rows->len < merge_res->limit) {
                merge_rows(con, inj);
                }

                if ((++merge_res->sub_sql_exed) < merge_res->sub_sql_num) {
                    if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
                        gchar *msg = g_strdup_printf("read query's %dth result will be merged",
                                                    merge_res->sub_sql_exed);
                        CON_MSG_HANDLE(g_message, con, msg);
                        g_free(msg);
                    }
                    ret = PROXY_IGNORE_RESULT;
                } else {
                    network_injection_queue_reset(st->injected.queries);
                    ret = PROXY_SEND_RESULT;

                    if (inj->qstat.query_status == MYSQLD_PACKET_OK) {
                        proxy_resultset_t* res = proxy_resultset_new();

                        if (inj->resultset_is_needed && !inj->qstat.binary_encoded) {
                            res->result_queue = con->server->recv_queue->chunks;
                        }
                        res->qstat = inj->qstat;
                        res->rows  = inj->rows;
                        res->bytes = inj->bytes;

                        if (parse_resultset_fields(res) != 0) {
                            if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
                                CON_MSG_HANDLE(g_message, con, "parse result fields failed before sending merge rows");
                            }
                        }

                        while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
                        network_mysqld_con_send_resultset(send_sock, res->fields, merge_res->rows);

                        proxy_resultset_free(res);

                        if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
                            gchar *msg = g_strdup_printf("read query's %d result has be merged",
                                                            merge_res->sub_sql_exed);
                            CON_MSG_HANDLE(g_message, con, msg);
                            g_free(msg);
                        }
                    }
                }
            } else if (inj->id == INJECTION_EXPLICIT_MULTI_WRITE_QUERY) {
                log_sql_backend(config->sql_log_mgr, con, (void *)inj);

                if (inj->qstat.query_status == MYSQLD_PACKET_OK) {
                    network_mysqld_ok_packet_t *ok_packet = network_mysqld_ok_packet_new();
                    packet.offset = NET_HEADER_SIZE;
                    if (network_mysqld_proto_get_ok_packet(&packet, ok_packet)) {
                        network_mysqld_ok_packet_free(ok_packet);

                        return NETWORK_SOCKET_ERROR;
                    }

                    merge_res_t *merge_res = con->merge_res;
                    merge_res->affected_rows += ok_packet->affected_rows;
                    merge_res->warnings += ok_packet->warnings;

                    if ((++merge_res->sub_sql_exed) < merge_res->sub_sql_num) {
                        ret = PROXY_IGNORE_RESULT;
                        if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
                            gchar *msg = g_strdup_printf("write query's %dth result is coming",
                                                    merge_res->sub_sql_exed);
                            CON_MSG_HANDLE(g_message, con, msg);
                            g_free(msg);
                        }
                    } else {
                        network_mysqld_con_send_ok_full(con->client, merge_res->affected_rows, 0, ok_packet->server_status, merge_res->warnings);
                        network_injection_queue_reset(st->injected.queries);
                        while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
                        ret = PROXY_SEND_RESULT;

                        if (TRACE_SHARD(con->srv->log->log_trace_modules)) {
                            gchar *msg = g_strdup_printf("write query's %dth result has be merged",
                                                        merge_res->sub_sql_exed);
                            CON_MSG_HANDLE(g_message, con, msg);
                            g_free(msg);
                        }
                    }

                    network_mysqld_ok_packet_free(ok_packet);
                } else {
                    ret = PROXY_SEND_RESULT;
                }
            } else {
                log_sql_backend(config->sql_log_mgr, con, (void *)inj);
                proxy_update_conn_attribute(con, inj);
                ret = PROXY_IGNORE_RESULT;
            }

            switch (ret) {
            case PROXY_SEND_RESULT:
                {
#if 0
                    gboolean b_reserve_conn = FALSE;
                    if (inj->qstat.warning_count > 0 ||
                            (inj->id == INJECTION_EXPLICIT_SINGLE_WRITE_QUERY && (gint) inj->qstat.insert_id < 0)) {
                            b_reserve_conn = TRUE;
                    }
#else
                    gboolean b_reserve_conn = (inj->qstat.insert_id > 0) || (inj->qstat.warning_count > 0) || (inj->qstat.affected_rows > 0);
#endif
                    proxy_update_conn_attribute(con, inj);

                    ++st->injected.sent_resultset;
                    if (st->injected.sent_resultset == 1) {
                        while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, p);
                    } else {
                        if (con->resultset_is_needed) {
                            while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
                        }
                    }

                    filter_post(con, inj);
                    if (!con->conn_status.is_in_transaction &&
                                !con->conn_status.is_in_select_calc_found_rows &&
                                    !b_reserve_conn && g_hash_table_size(con->locks) == 0) {
                            network_connection_pool_lua_add_connection(con);
                    } else if (TRACE_SQL(con->srv->log->log_trace_modules)) {
                        GString *msg = g_string_new("backend is reserved for ");
                        if (b_reserve_conn) {
#if 0
                            g_string_append_printf(msg, "warning_count = [%d], insert_id = [%d]",
                                            inj->qstat.warning_count, inj->qstat.insert_id);
#else
                            g_string_append_printf(msg, "[insert_id = %lu, warning_count = %d, affected_rows = %lu]",
                                            inj->qstat.insert_id, inj->qstat.warning_count, inj->qstat.affected_rows);
#endif
                        }
                        if (con->conn_status.is_in_transaction) {
                            g_string_append_printf(msg, "[in transaction]");
                        }
                        if (con->conn_status.is_in_select_calc_found_rows) {
                            g_string_append_printf(msg, "[query has SQL_CALC_FOUND_ROWS]");
                        }
                        if (g_hash_table_size(con->locks) > 0) {
                            g_string_append_printf(msg, "[have %d table locks]", g_hash_table_size(con->locks));
                        }

                        CON_MSG_HANDLE(g_message, con, msg->str);
                        g_string_free(msg, TRUE);
                    }
                }

                break;
            case PROXY_IGNORE_RESULT:
                if (con->resultset_is_needed) {
                    while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
                }
#if 0
                /* found_rows result & last_insert_id */
                if (!con->conn_status.is_in_transaction &&
                        (inj->id == INJECTION_IMPLICIT_GET_FOUND_ROWS ||
                         inj->id == INJECTION_IMPLICIT_LAST_INSERT_ID)) {
                    network_connection_pool_lua_add_connection(con);
                }
#endif
                break;
            default:
                break;
            }

            injection_free(inj);
        }

        NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::leave_lua");

        if (PROXY_IGNORE_RESULT != ret) {
            /* reset the packet-id checks, if we sent something to the client */
            network_mysqld_queue_reset(send_sock);
        }

        /**
         * if the send-queue is empty, we have nothing to send
         * and can read the next query */
        if (send_sock->send_queue->chunks) {
			g_log_dbproxy(g_message, "即将进入 CON_STATE_SEND_QUERY_RESULT, ！！！！给客户端发数据"); 
            con->state = CON_STATE_SEND_QUERY_RESULT;
        } else {
            /*
             * we already forwarded the resultset,
             * no way someone has flushed the resultset-queue
             */
            g_assert_cmpint(con->resultset_is_needed, ==, 1);

            gint64 cur_time = chassis_get_rel_microseconds();
            gint64 respon_time = cur_time - con->conn_status_var.cur_query_start_time;
            if (respon_time > con->srv->long_query_time * 1000) {
                log_sql_slow(config->sql_log_mgr, con, respon_time);
            }
            network_mysqld_stat_stmt_end(con, cur_time);
            con->state = CON_STATE_READ_QUERY;
        }
    }
    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::leave");
    
    return NETWORK_SOCKET_SUCCESS;
}

/**
 * connect to a backend
 *
 * @return
 *   NETWORK_SOCKET_SUCCESS        - connected successfully
 *   NETWORK_SOCKET_ERROR_RETRY    - connecting backend failed, call again to connect to another backend
 *   NETWORK_SOCKET_ERROR          - no backends available, adds a ERR packet to the client queue
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_connect_server) {
    guint i;

    if (TRACE_CON_STATUS(con->srv->log->log_trace_modules)) {
            CON_MSG_HANDLE(g_message, con, "proxy_connect_server begin");
    }

    network_mysqld_auth_challenge *challenge = network_mysqld_auth_challenge_new();

    challenge->protocol_version = MYSQL_PROTOCOL_VERSION;
    challenge->server_version_str =
            g_strdup((con->srv->my_version == MYSQL_55) ? MYSQL_PROTOCOL_SERVER_VERSION_55 : MYSQL_PROTOCOL_SERVER_VERSION_56);
    challenge->server_version =
            (con->srv->my_version == MYSQL_55) ? MYSQL_PROTOCOL_VERSION_ID_55 : MYSQL_PROTOCOL_VERSION_ID_56;
    static guint32 thread_id = 0;
    challenge->thread_id = ++thread_id;

    GString *str = con->challenge;
    for (i = 0; i < 20; ++i) g_string_append_c(str, rand()%127+1);
    g_string_assign(challenge->challenge, str->str);

    challenge->capabilities = MYSQL_PROTOCOL_CAPABILITIES;//41484;
    challenge->charset = 224;
    challenge->server_status = SERVER_STATUS_AUTOCOMMIT;

    GString *auth_packet = g_string_new(NULL);
    network_mysqld_proto_append_auth_challenge(auth_packet, challenge);
    network_mysqld_auth_challenge_free(challenge);
    network_mysqld_queue_append(con->client, con->client->send_queue, S(auth_packet));
    g_string_free(auth_packet, TRUE);

    con->state = CON_STATE_SEND_HANDSHAKE;

    return NETWORK_SOCKET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_init) {
    network_mysqld_con_lua_t *st = con->plugin_con_state;

    g_assert(con->plugin_con_state == NULL);

    if (TRACE_CON_STATUS(con->srv->log->log_trace_modules)) {
        CON_MSG_HANDLE(g_message, con, "proxy_init begin");
    }

    st = network_mysqld_con_lua_new();

    con->plugin_con_state = st;
    
    con->state = CON_STATE_CONNECT_SERVER;

    return NETWORK_SOCKET_SUCCESS;
}

/**
 * cleanup the proxy specific data on the current connection 
 *
 * move the server connection into the connection pool in case it is a 
 * good client-side close
 *
 * @return NETWORK_SOCKET_SUCCESS
 * @see plugin_call_cleanup
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_disconnect_client) {
    network_mysqld_con_lua_t *st = con->plugin_con_state;
    lua_scope  *sc = con->srv->sc;
//  gboolean use_pooled_connection = FALSE;

    if (st == NULL) return NETWORK_SOCKET_SUCCESS;
    
    /**
     * let the lua-level decide if we want to keep the connection in the pool
     */
/*
    switch (proxy_lua_disconnect_client(con)) {
    case PROXY_NO_DECISION:
        // just go on

        break;
    case PROXY_IGNORE_RESULT:
        break;
    default:
        g_log_dbproxy(g_error, "...");
        break;
    }
*/
    /**
     * check if one of the backends has to many open connections
     */

//  if (use_pooled_connection &&
//      con->state == CON_STATE_CLOSE_CLIENT) {
/*
    if (con->state == CON_STATE_CLOSE_CLIENT) {
        if (con->server && con->server->is_authed) {
            network_connection_pool_lua_add_connection(con);
        }
    } else if (st->backend) {
        st->backend->connected_clients--;
    }
*/
#ifdef HAVE_LUA_H
    /* remove this cached script from registry */
    if (st->L_ref > 0) {
        luaL_unref(sc->L, LUA_REGISTRYINDEX, st->L_ref);
    }
#endif

    network_mysqld_con_lua_free(st);

    con->plugin_con_state = NULL;

    /**
     * walk all pools and clean them up
     */

    return NETWORK_SOCKET_SUCCESS;
}

/**
 * read the load data infile data from the client
 *
 * - decode the result-set to track if we are finished already
 * - gets called once for each packet
 *
 * @FIXME stream the data to the backend
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_local_infile_data) {
    int query_result = 0;
    network_packet packet;
    network_socket *recv_sock, *send_sock;
    network_mysqld_com_query_result_t *com_query = con->parse.data;

    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter");
    
    recv_sock = con->client;
    send_sock = con->server;

    /* check if the last packet is valid */
    packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
    packet.offset = 0;

    /* if we get here from another state, src/network-mysqld.c is broken */
    g_assert_cmpint(con->parse.command, ==, COM_QUERY);
    g_assert_cmpint(com_query->state, ==, PARSE_COM_QUERY_LOCAL_INFILE_DATA);

    query_result = network_mysqld_proto_get_query_result(&packet, con);
    if (query_result == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

    if (con->server) {
        network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
                g_queue_pop_tail(recv_sock->recv_queue->chunks));
    } else {
        GString *s;
        /* we don't have a backend
         *
         * - free the received packets early
         * - send a OK later 
         */
        while ((s = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(s, TRUE);
    }

    if (query_result == 1) { /* we have everything, send it to the backend */
        if (con->server) {
            con->state = CON_STATE_SEND_LOCAL_INFILE_DATA;
        } else {
            network_mysqld_con_send_ok(con->client);
            con->state = CON_STATE_SEND_LOCAL_INFILE_RESULT;
        }
        g_assert_cmpint(com_query->state, ==, PARSE_COM_QUERY_LOCAL_INFILE_RESULT);
    }

    return NETWORK_SOCKET_SUCCESS;
}

/**
 * read the load data infile result from the server
 *
 * - decode the result-set to track if we are finished already
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_local_infile_result) {
    int query_result = 0;
    network_packet packet;
    network_socket *recv_sock, *send_sock;

    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_local_infile_result::enter");

    recv_sock = con->server;
    send_sock = con->client;

    /* check if the last packet is valid */
    packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
    packet.offset = 0;
    
    query_result = network_mysqld_proto_get_query_result(&packet, con);
    if (query_result == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

    network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
            g_queue_pop_tail(recv_sock->recv_queue->chunks));

    if (query_result == 1) {
        con->state = CON_STATE_SEND_LOCAL_INFILE_RESULT;
    }

    return NETWORK_SOCKET_SUCCESS;
}

/**
 * cleanup after we sent to result of the LOAD DATA INFILE LOCAL data to the client
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_local_infile_result) {
    network_socket *recv_sock, *send_sock;

    NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::send_local_infile_result::enter");

    recv_sock = con->server;
    send_sock = con->client;

    /* reset the packet-ids */
    if (send_sock) network_mysqld_queue_reset(send_sock);
    if (recv_sock) network_mysqld_queue_reset(recv_sock);

    network_mysqld_stat_stmt_end(con, chassis_get_rel_microseconds());
    con->state = CON_STATE_READ_QUERY;

    return NETWORK_SOCKET_SUCCESS;
}


int network_mysqld_proxy_connection_init(network_mysqld_con *con) {
    con->plugins.con_init                      = proxy_init;
    con->plugins.con_connect_server            = proxy_connect_server;
    con->plugins.con_read_handshake            = proxy_read_handshake;
    con->plugins.con_read_auth                 = proxy_read_auth;
    con->plugins.con_read_auth_result          = proxy_read_auth_result;
    con->plugins.con_read_query                = proxy_read_query;
    con->plugins.con_read_query_result         = proxy_read_query_result;
    con->plugins.con_send_query_result         = proxy_send_query_result;
    con->plugins.con_read_local_infile_data = proxy_read_local_infile_data;
    con->plugins.con_read_local_infile_result = proxy_read_local_infile_result;
    con->plugins.con_send_local_infile_result = proxy_send_local_infile_result;
    con->plugins.con_cleanup                   = proxy_disconnect_client;

    return 0;
}

/**
 * free the global scope which is shared between all connections
 *
 * make sure that is called after all connections are closed
 */
void network_mysqld_proxy_free(network_mysqld_con G_GNUC_UNUSED *con) {
}

void string_free(GString *s) {
    g_string_free(s, TRUE);
}

void
dt_table_free(db_table_t *dt)
{
    if (dt == NULL) return;

    if (dt->db_name) { g_free(dt->db_name); }
    if (dt->table_name) { g_free(dt->table_name); }
    if (dt->column_name) { g_free(dt->column_name); }

    g_free(dt);
}

chassis_plugin_config * network_mysqld_proxy_plugin_new(void) {
    config = g_new0(chassis_plugin_config, 1);

    config->fix_bug_25371   = 0; /** double ERR packet on AUTH failures */
    config->profiling       = 1;
    config->start_proxy     = 1;
    config->pool_change_user = 1; /* issue a COM_CHANGE_USER to cleanup the connection 
                     when we get back the connection from the pool */
    config->dt_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)dt_table_free);

    config->select_where_limit_str = NULL;
    config->select_where_limit = SEL_OFF;
    config->charset = NULL;

    config->opts = NULL;

    config->percentile_value = 64;

    config->check_state_conn_timeout = 3;
    config->check_state_interval = PROXY_CHECK_STATE_WAIT_TIMEOUT;
    config->check_state_retry_times = RETRY_TIMES;
    config->check_state_sleep_delay = SLEEP_DELAY;
    g_rw_lock_init(&config->config_lock);

    config->sql_log_mgr = sql_log_t_new();
    config->percentile_controller = pt_percentile_new(6.0, 29.0, 2);

    config->plugin_threads = g_hash_table_new_full(g_str_hash,
                                         g_str_equal,
                                         g_free,
                                         (GDestroyNotify)plugin_thread_t_free);
    config->table_prefix = NULL;
    config->table_suffix = NULL;
    config->tnw = tbl_name_wrap_new();

	/*
	zhangming 2018/1/16 23:40
	*/
	config->id_generate    = NULL;
	config->dbproxy_user = NULL;
	config->dbproxy_pwd = NULL;
	config->master_user  = NULL;
	config->master_pwd  = NULL;
	config->slave_user    = NULL;
	config->slave_pwd    = NULL;
}

void network_mysqld_proxy_plugin_free(chassis_plugin_config *oldconfig) {
    gsize i;

    if (config->listen_con) {
        event_del(&(config->listen_con->server->event));
        network_mysqld_con_free(config->listen_con);
    }

    g_strfreev(config->backend_addresses);
    g_strfreev(config->read_only_backend_addresses);

    if (config->address) {
        /* free the global scope */
        network_mysqld_proxy_free(NULL);

        g_free(config->address);
    }

    if (config->lua_script) g_free(config->lua_script);

    if (config->client_ips) {
        for (i = 0; config->client_ips[i]; i++) {
            g_free(config->client_ips[i]);
        }
        g_free(config->client_ips);
    }

    if (config->lvs_ips) {
        for (i = 0; config->lvs_ips[i]; i++) {
            g_free(config->lvs_ips[i]);
        }
        g_free(config->lvs_ips);
    }

    if (config->tables) {
        for (i = 0; config->tables[i]; i++) {
            g_free(config->tables[i]);
        }
        g_free(config->tables);
    }

    g_hash_table_remove_all(config->dt_table);
    g_hash_table_destroy(config->dt_table);

    if (config->select_where_limit_str) g_free(config->select_where_limit_str);

    if (config->user_ips_str) {
        for (i = 0; config->user_ips_str[i]; i++) {
            g_free(config->user_ips_str[i]);
        }
        g_free(config->user_ips_str);
    }

	/*
	zhangming 2018/1/26 0:19
	不再使用
    if (config->pwds) {
        for (i = 0; config->pwds[i]; i++) {
            g_free(config->pwds[i]);
        }
        g_free(config->pwds);
    }
	*/

    if (config->user_backends_str) {
        for (i = 0; config->user_backends_str[i]; i++) {
            g_free(config->user_backends_str[i]);
        }
        g_free(config->user_backends_str);
    }

    if (config->charset) g_free(config->charset);
    g_rw_lock_clear(&config->config_lock);
    if (config->opts) chassis_options_free(config->opts);

    g_hash_table_remove_all(config->plugin_threads);
    g_hash_table_destroy(config->plugin_threads);

    if (config->sql_log_mgr) sql_log_t_free(config->sql_log_mgr);

    if (config->percentile_switch) g_free(config->percentile_switch);
    pt_percentile_free(config->percentile_controller);

    if (config->table_prefix) g_free(config->table_prefix);
    if (config->table_suffix) g_free(config->table_suffix);
    if (config->tnw) tbl_name_wrap_free(config->tnw);
	
	/*
	zhangming 2018/1/25 23:53
	*/
	if (config->id_generate) g_free(config->id_generate);
	if (config->dbproxy_user) g_free(config->dbproxy_user);
	if (config->dbproxy_pwd) g_free(config->dbproxy_pwd);
	if (config->master_user) g_free(config->master_user);
	if (config->master_pwd) g_free(config->master_pwd);
	if (config->slave_user) g_free(config->slave_user);
	if (config->slave_pwd) g_free(config->slave_pwd);

    g_free(config);
}

/**
 * plugin options 
 */
static chassis_options_t * network_mysqld_proxy_plugin_get_options(chassis_plugin_config *oldconfig) {
    if (config->opts == NULL) {
        chassis_options_t *opts = chassis_options_new();

        chassis_options_add(opts, "proxy-address",            'P', 0, G_OPTION_ARG_STRING, &(config->address), "listening address:port of the proxy-server (default: :4040)", "<host:port>",
                            NULL, show_proxy_address, SHOW_OPTS_PROPERTY);
        chassis_options_add(opts, "proxy-read-only-backend-addresses", 'r', 0, G_OPTION_ARG_STRING_ARRAY, &(config->read_only_backend_addresses), "address:port of the remote slave-server (default: not set)", "<host:port>",
                            NULL, NULL, 0);
        chassis_options_add(opts, "proxy-backend-addresses",  'b', 0, G_OPTION_ARG_STRING_ARRAY, &(config->backend_addresses), "address:port of the remote backend-servers (default: 127.0.0.1:3306)", "<host:port>",
                            NULL, NULL, 0);
        chassis_options_add(opts, "proxy-skip-profiling",     0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &(config->profiling), "disables profiling of queries (default: enabled)", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "proxy-fix-bug-25371",      0, 0, G_OPTION_ARG_NONE, &(config->fix_bug_25371), "fix bug #25371 (mysqld > 5.1.12) for older libmysql versions", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "proxy-lua-script",         's', 0, G_OPTION_ARG_FILENAME, &(config->lua_script), "filename of the lua script (default: not set)", "<file>",
                            NULL, NULL, 0);
        chassis_options_add(opts, "no-proxy",                 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &(config->start_proxy), "don't start the proxy-module (default: enabled)", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "proxy-pool-no-change-user", 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &(config->pool_change_user), "don't use CHANGE_USER to reset the connection coming from the pool (default: enabled)", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "client-ips", 0, 0, G_OPTION_ARG_STRING_ARRAY, &(config->client_ips), "all permitted client ips", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "lvs-ips", 0, 0, G_OPTION_ARG_STRING_ARRAY, &(config->lvs_ips), "all lvs ips", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "tables", 0, 0, G_OPTION_ARG_STRING_ARRAY, &(config->tables), "sub-table settings", NULL,
                            assign_shard_tables, shard_tables_show_save, SAVE_OPTS_PROPERTY);

		/*
		zhangming 2018/1/26 0:19 不再使用了
        chassis_options_add(opts, "pwds", 0, 0, G_OPTION_ARG_STRING_ARRAY, &(config->pwds), "password settings", NULL, NULL, NULL, 0);
		*/
        chassis_options_add(opts, "charset", 0, 0, G_OPTION_ARG_STRING, &(config->charset), "original charset(default: LATIN1)", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "select-where-limit", 0, 0, G_OPTION_ARG_STRING, &(config->select_where_limit_str), "forbidden on where sql(default: OFF)", NULL,
                            assign_select_where_limit, show_select_where_limit, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "user-hosts", 0, 0, G_OPTION_ARG_STRING_ARRAY, &(config->user_ips_str), "permitted hosts of users(default: NULL, all host are permitted)", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "user-backends", 0, 0, G_OPTION_ARG_STRING_ARRAY, &(config->user_backends_str), "set user's backends(default: NULL)", NULL,
                            NULL, NULL, 0);
        chassis_options_add(opts, "check-state-conn-timeout", 0, 0, G_OPTION_ARG_INT, &(config->check_state_conn_timeout), "set check_state connect time out(default: 3s)", NULL,
                            assign_check_state_conn_timeout, show_check_state_conn_timeout, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "check-state-interval", 0, 0, G_OPTION_ARG_INT, &(config->check_state_interval), "set check_state wakeup interval(default: 4s)", NULL,
                            assign_check_state_interval, show_check_state_interval, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "check-state-retry-times", 0, 0, G_OPTION_ARG_INT, &(config->check_state_retry_times), "set check_state connect/query retry times (default: 3)", NULL,
                            assign_check_state_retry_times, show_check_state_retry_times, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "check-state-sleep-delay", 0, 0, G_OPTION_ARG_INT, &(config->check_state_sleep_delay), "set check_state connect/query delay timeout (default: 1s)", NULL,
                            assign_check_state_sleep_delay, show_check_state_sleep_delay, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "percentile-switch", 0, 0, G_OPTION_ARG_STRING, &(config->percentile_switch), "this parameter determines the percentile is on or off", NULL, assign_percentile_switch, show_percentile_switch, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "percentile-value", 0, 0, G_OPTION_ARG_INT, &(config->percentile_value), "this parameter determines the percentile th", NULL, assign_percentile_value, show_percentile_value, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "percentile", 0, 0, G_OPTION_ARG_DOUBLE, &(config->percentile), "this parameter determines the percentile", NULL, NULL, show_percentile, SHOW_OPTS_PROPERTY);
        chassis_options_add(opts, "sql-log", 0, 0, G_OPTION_ARG_STRING, &(config->sql_log_type), "sql log type(ON: open, REALTIME: open_sync, OFF: close default: OFF)", NULL, assign_sql_log, show_sql_log, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "sql-log-mode", 0, 0, G_OPTION_ARG_STRING, &(config->sql_log_mode), "sql log mode(CLIENT: client sql, BACKEND: backend sql, ALL: client + backend, default: ALL)", NULL,
                                                        assign_sql_log_mode, show_sql_log_mode, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "sql-log-slow-ms", 0, 0, G_OPTION_ARG_INT, &(config->sql_log_mgr->sql_log_slow_ms), "only log sql which takes longer than this milliseconds (default: 0)", NULL,
                                                        assign_sql_log_slow_ms, show_sql_log_slow_ms, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "sql-log-file-size", 0, 0, G_OPTION_ARG_INT, &(config->sql_log_mgr->sql_log_max_size), "this parameter determines the maximum size of an individual log file (default: 1G), depending on sql-log not OFF.", NULL,
                                                        assign_sql_log_file_size, show_sql_log_file_size, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "sql-log-file-num", 0, 0, G_OPTION_ARG_INT, &(config->sql_log_mgr->sql_log_file_num), "this parameter determines the maximum number of log files (default: -1, unlimited), depending on sql-log not OFF.", NULL,
                                                        assign_sql_log_file_num, show_sql_log_file_num, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "sql-log-buffer-size", 0, 0, G_OPTION_ARG_INT, &(config->sql_log_mgr->sql_log_buffer_size), "this parameter determines the maximum number of logs in log buffer(default: 50000)", NULL,
                                                        assign_sql_log_buffer_size, show_sql_log_buffer_size, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "table-prefix", 0, 0, G_OPTION_ARG_STRING, &(config->table_prefix), "support table name mapping prefix (default: NULL)", NULL,
                                                        assign_table_prefix, show_table_prefix, ALL_OPTS_PROPERTY);
        chassis_options_add(opts, "table-suffix", 0, 0, G_OPTION_ARG_STRING, &(config->table_suffix), "support table name mapping suffix (default: NULL)", NULL,
                                                        assign_table_suffix, show_table_suffix, ALL_OPTS_PROPERTY);
		
		/*
			zhangming 2018/1/16 15:03
		*/
		chassis_options_add(opts, "id-generate", 0, 0, G_OPTION_ARG_STRING, &(config->id_generate), "id-generate", NULL, NULL, NULL, 0);
		
		chassis_options_add(opts, "dbproxy-user", 0, 0, G_OPTION_ARG_STRING, &(config->dbproxy_user), "dbproxy-user", NULL, NULL, NULL, 0);

		chassis_options_add(opts, "dbproxy-pwd", 0, 0, G_OPTION_ARG_STRING, &(config->dbproxy_pwd), "dbproxy-pwd", NULL, NULL, NULL, 0);

		chassis_options_add(opts, "master-user", 0, 0, G_OPTION_ARG_STRING, &(config->master_user), "master-user", NULL, NULL, NULL, 0);
	
		chassis_options_add(opts, "master-pwd", 0, 0, G_OPTION_ARG_STRING, &(config->master_pwd), "master-pwd", NULL, NULL, NULL, 0);

		chassis_options_add(opts, "slave-user", 0, 0, G_OPTION_ARG_STRING, &(config->slave_user), "slave-user", NULL, NULL, NULL, 0);

		chassis_options_add(opts, "slave-pwd", 0, 0, G_OPTION_ARG_STRING, &(config->slave_pwd), "slave-pwd", NULL, NULL, NULL, 0);

        config->opts = opts;
    }
        
    return config->opts;
}

void handler(int sig) {
    switch (sig) {
    case SIGUSR1:
        online = TRUE;
        break;
    case SIGUSR2:
        online = FALSE;
        break;
    }
}

static void check_backend_thread_running(network_backend_t* backend, MYSQL *mysql) {
    MYSQL_RES *result = NULL;

    if (mysql_query(mysql, "show status like 'Threads_running'")) {
        g_log_dbproxy(g_warning, "get backend (%s) threads_running failed:%s", backend->addr->name->str, mysql_error(mysql));
        return;
    }

    result = mysql_store_result(mysql);
    if (result != NULL) {
        if (mysql_num_fields(result) > 1 && mysql_num_rows(result) > 0) {
            MYSQL_ROW row = mysql_fetch_row(result);
            backend->thread_running = atoi(row[1]);
        } else {
            g_log_dbproxy(g_warning, "get backend (%s) threads_running failed, num_fields:%d, num_rows:%llu", backend->addr->name->str, mysql_num_fields(result), mysql_num_rows(result));
        }
        mysql_free_result(result);
    } else {
        g_log_dbproxy(g_warning, "get backend (%s) threads_running failed:%s", backend->addr->name->str, mysql_error(mysql));
    }
}

/*
 * plugin thread for checking the backends status
 */
static void*
check_state(void *user_data)
{
    plugin_thread_param *plugin_params = (plugin_thread_param *) user_data;
    chassis             *chas = (chassis *)plugin_params->magic_value;
    GCond               *g_cond = plugin_params->plugin_thread_cond;
    GMutex              *g_mutex = plugin_params->plugin_thread_mutex;
    network_backends_t  *bs = chas->backends;
    gchar               *monitor_user = NULL, *monitor_pwd = NULL;
    gint                i = 0, j = 0, k = 0, m = 0, tm = 1;
    gint64              end_time = 0;

    sleep(1);

    g_log_dbproxy(g_message, "%s thread start", PROXY_CHECK_STATE_THREAD);

    while (!chassis_is_shutdown()) {
        backend_info *bkinfo = NULL;
        GPtrArray* backends = NULL;
        guint len = 0;

        g_rw_lock_reader_lock(&bs->user_mgr_lock);
        if (bs->monitor_user != NULL) {
            monitor_user = g_strdup(bs->monitor_user);
            monitor_pwd = g_strdup(bs->monitor_pwd);
        }
        g_rw_lock_reader_unlock(&bs->user_mgr_lock);

        g_rw_lock_reader_lock(&bs->backends_lock);
        backends = bs->backends;
        len = backends->len;
        bkinfo = g_malloc0(sizeof(backend_info) * len);
        if (bkinfo == NULL) {
            g_rw_lock_reader_unlock(&bs->backends_lock);
            goto sleep_phase;
        }
        for (i = 0; i < len; i++) {
            network_backend_t* backend = g_ptr_array_index(backends, i);
            bkinfo[i].backend = backend;
            if (backend == NULL) continue;
            bkinfo[i].port = ntohs(backend->addr->addr.ipv4.sin_port);
            bkinfo[i].ip = inet_ntoa(backend->addr->addr.ipv4.sin_addr);
            bkinfo[i].ip = g_strdup(bkinfo[i].ip);
            bkinfo[i].state = g_atomic_int_get(&backend->state);
            bkinfo[i].bkid = backend->backend_id; 
            bkinfo[i].name = g_strdup(backend->addr->name->str);
            bkinfo[i].type = backend->type; 
        }
        g_rw_lock_reader_unlock(&bs->backends_lock);

        for (i = 0; i < len; ++i) {
            backend_info    *bk_info = bkinfo + i;
            gchar           *ip = bk_info->ip;
            guint           port = bk_info->port;
            backend_state_t bt = BACKEND_STATE_UNKNOWN;
            guint           err_no = 0;

            if (bk_info->backend == NULL || IS_BACKEND_OFFLINE(bk_info))
                continue;

            /* what about mointor_user/pwd is NULL ? */
            m = j = k = 0;
            while (m < config->check_state_retry_times) {
                MYSQL  mysql;
                tm = config->check_state_conn_timeout;
                mysql_init(&mysql);
                /* connect_timeout read_timeout write_timeout */
                mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, &tm);
                mysql_options(&mysql, MYSQL_OPT_READ_TIMEOUT, &tm);
                mysql_options(&mysql, MYSQL_OPT_WRITE_TIMEOUT, &tm);
                mysql_real_connect(&mysql, ip, monitor_user, monitor_pwd, NULL, port, NULL, 0);
                err_no = mysql_errno(&mysql);
                if (err_no == 0) {
                    mysql_close(&mysql);
                    break;
                } else if (err_no == ER_ACCESS_DENIED_ERROR) {
                    if (monitor_user != NULL)
                        g_log_dbproxy(g_warning, "accessing backend(%s) was denied: %s. user name: %s",
                                                     bk_info->name, mysql_error(&mysql), monitor_user);
                    mysql_close(&mysql);
                    break;
                } else if (err_no == ER_CON_COUNT_ERROR || err_no == ER_TOO_MANY_USER_CONNECTIONS) {
                    g_log_dbproxy(g_critical, "connecting backend(%s) failed: %s. user name: %s",
                                                     bk_info->name, mysql_error(&mysql), (monitor_user ? monitor_user : "is null"));
                    mysql_close(&mysql);
                    break;
                } else {
                    m++;
                    g_log_dbproxy(g_critical, "due to %s, retry %dth times to connect backend %s. user name: %s",
                                          mysql_error(&mysql), m, bk_info->name, (monitor_user ? monitor_user : "is null"));
                    mysql_close(&mysql);
                    usleep(config->check_state_sleep_delay * 1000);
                }
            }

            if (err_no == ER_ACCESS_DENIED_ERROR || err_no == 0 || err_no == ER_CON_COUNT_ERROR
                                                          || err_no == ER_TOO_MANY_USER_CONNECTIONS) {
                bt = BACKEND_STATE_UP;
            } else if (err_no != 0) {
                bt = BACKEND_STATE_DOWN;
            }

            if (bk_info->state != bt && bk_info->type == BACKEND_TYPE_RO) {
                int idx = 0;
                gboolean change = FALSE;
                network_backend_t* tmpbk = NULL;
                g_rw_lock_writer_lock(&bs->backends_lock);
                while (idx < bs->backends->len) {
                    tmpbk = g_ptr_array_index(bs->backends, idx);
                    if (tmpbk == bk_info->backend && bk_info->bkid == tmpbk->backend_id && bk_info->state == tmpbk->state) {
                        SET_BACKEND_STATE(tmpbk, bt);
                        change = TRUE;
                        break;
                    }
                    idx++;
                }
                g_rw_lock_writer_unlock(&bs->backends_lock);
                if (change)
                    g_log_dbproxy(g_warning, "set backend (%s) state to %s", bk_info->name,
                        bt == BACKEND_STATE_UP ? "UP" : (bt == BACKEND_STATE_DOWN ? "DOWN" : "PENDING"));
            }
        }

        for (i = 0; i < len; i++) {
            backend_info* bk_info = bkinfo + i;
            if (bk_info->ip)
                g_free(bk_info->ip);
            if (bk_info->name)
                g_free(bk_info->name);
            bk_info->name = NULL;
            bk_info->ip = NULL;
        }
        g_free(bkinfo);

sleep_phase:
        if (monitor_user != NULL) {
            g_free(monitor_user);
            monitor_user = NULL;
        }
        if (monitor_pwd != NULL) {
            g_free(monitor_pwd);
            monitor_pwd = NULL;
        }

        g_mutex_lock(g_mutex);
        end_time = g_get_monotonic_time() + config->check_state_interval * G_TIME_SPAN_SECOND;
        if (!g_cond_wait_until(g_cond, g_mutex, end_time)) {
            g_log_dbproxy(g_debug, "check state waiting meet timeout");
        } else {
            g_log_dbproxy(g_message, "check_state thread get exit signal");
        }
        g_mutex_unlock(g_mutex);
    }

    mysql_library_end();
    g_log_dbproxy(g_message, "check_state thread will exit");
    g_thread_exit(0);
    return NULL;
}

/* Comment out this function, because this function cause many bugs */
/*
static void*
check_state(void *user_data)
{
    plugin_thread_param *plugin_params = (plugin_thread_param *) user_data;
    chassis             *chas = (chassis *)plugin_params->magic_value;
    GCond               *g_cond = plugin_params->plugin_thread_cond;
    GMutex              *g_mutex = plugin_params->plugin_thread_mutex;
    network_backends_t  *bs = chas->backends;
    MYSQL mysql;
    gchar               *monitor_user = NULL, *monitor_pwd = NULL;
    gint                i = 0, j = 0, k = 0, m = 0, tm = 1;
    gint64              end_time = 0;

    sleep(1);

    g_log_dbproxy(g_message, "%s thread start", PROXY_CHECK_STATE_THREAD);

    mysql_init(&mysql);

    while (!chassis_is_shutdown()) {
        GPtrArray* backends = bs->backends;
        guint len = backends->len;

        g_rw_lock_reader_lock(&bs->user_mgr_lock);
        if (bs->monitor_user != NULL) {
            monitor_user = g_strdup(bs->monitor_user);
            monitor_pwd = g_strdup(bs->monitor_pwd);
        }
        g_rw_lock_reader_unlock(&bs->user_mgr_lock);

        for (i = 0; i < len; ++i) {
            network_backend_t* backend = g_ptr_array_index(backends, i);

            if (backend == NULL) continue ;

            if (IS_BACKEND_OFFLINING(backend) &&
                        g_atomic_int_get(&backend->connected_clients) == 0) {
                if (g_rw_lock_writer_trylock(&bs->backends_lock)) {
                    if (g_atomic_int_get(&backend->connected_clients) == 0) {
                        SET_BACKEND_STATE(backend, BACKEND_STATE_OFFLINE);
                        backend->thread_running = 0;
                        g_log_dbproxy(g_message, "offline backend %s success", backend->addr->name->str);
                    }
                    g_rw_lock_writer_unlock(&bs->backends_lock);
                }
            } else if (IS_BACKEND_REMOVING(backend) &&
                            g_atomic_int_get(&backend->connected_clients) == 0) {
                GString *name = g_string_new(backend->addr->name->str);
                if (network_backends_remove(bs, backend)) {
                    g_log_dbproxy(g_message, "remove backend %s success", name->str);
                    backend = NULL;
                }
                g_string_free(name, TRUE);
            }

            if (backend == NULL ||
                    IS_BACKEND_OFFLINE(backend) ||
                    IS_BACKEND_WAITING_EXIT(backend))
                continue;

            // connect and get thread_running 
            gchar* ip = inet_ntoa(backend->addr->addr.ipv4.sin_addr);
            guint port = ntohs(backend->addr->addr.ipv4.sin_port);
            backend_state_t bt = BACKEND_STATE_UNKNOWN;
            MYSQL_RES       *result = NULL;

            tm = config->check_state_conn_timeout;
            //connect_timeout read_timeout write_timeout
            mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, &tm);
            mysql_options(&mysql, MYSQL_OPT_READ_TIMEOUT, &tm);     //to consider and test
            mysql_options(&mysql, MYSQL_OPT_WRITE_TIMEOUT, &tm);    //to consider and test

            // what about mointor_user/pwd is NULL ?
            m = j = k = 0;
            while (m < config->check_state_retry_times) {
            mysql_real_connect(&mysql, ip, monitor_user, monitor_pwd, NULL, port, NULL, 0);
                if (mysql_errno(&mysql) == 0) {
                    break;
                } else if (mysql_errno(&mysql) == CR_SERVER_LOST) {
                    m++;
                    g_log_dbproxy(g_warning, "due to %s, retry %dth times to connect backend %s",
                                          mysql_error(&mysql),
                                          m, backend->addr->name->str);
                    sleep(config->check_state_sleep_delay);
                } else {
                    break;
                }
            }

            if ((monitor_user == NULL && mysql_errno(&mysql) == ER_ACCESS_DENIED_ERROR) ||
                                (chas->max_backend_tr == 0 && mysql_errno(&mysql) == 0)) {
                bt = BACKEND_STATE_UP;
                goto set_state;
            } else if (mysql_errno(&mysql) != 0) {
                bt = BACKEND_STATE_DOWN;
                g_log_dbproxy(g_critical, "set backend(%s) state to DOWN for: %d(%s)",
                              backend->addr->name->str,
                              mysql_errno(&mysql), mysql_error(&mysql));
                goto set_state;
            }
query :
            m = 0;
            while (m < config->check_state_retry_times) {
                mysql_query(&mysql, "SHOW STATUS LIKE 'Threads_running';");

                if ((mysql_errno(&mysql) == 0) ||
                        (mysql_errno(&mysql) == CR_SERVER_GONE_ERROR)) {
                   break;
                } else {
                    m++;
                    g_log_dbproxy(g_warning, "due to %s, retry %dth times to get thread_running from %s",
                                          mysql_error(&mysql),
                                          m, backend->addr->name->str);
                    sleep(config->check_state_sleep_delay);
                }
            }

            if (mysql_errno(&mysql) != 0) {
                bt = BACKEND_STATE_DOWN;
                g_log_dbproxy(g_critical, "set backend(%s) state to DOWN for: %d(%s)",
                              backend->addr->name->str,
                              mysql_errno(&mysql), mysql_error(&mysql));
                goto set_state;
            }

            result = mysql_store_result(&mysql);
            if (result == NULL) {
                if (j++ < config->check_state_retry_times) {
                    g_log_dbproxy(g_warning, "due to invalid result, retry %dth times to get thread_running from %s",
                                    j,
                                    backend->addr->name->str);
                    sleep(config->check_state_sleep_delay);
                    goto query;
                } else {
                    bt = BACKEND_STATE_DOWN;
                    g_log_dbproxy(g_critical, "set backend(%s) state to DOWN for retry %d times to get thread_running",
                                        backend->addr->name->str, config->check_state_retry_times);
                    goto set_state;
            }
            } else {
                MYSQL_ROW row;

                g_assert(mysql_num_fields(result) > 1 && mysql_num_rows(result) > 0);

                // get result
                row = mysql_fetch_row(result);
                set_raw_int_value(row[1], &(backend->thread_running), 1, 1024);
                mysql_free_result(result);

                if (backend->thread_running < chas->max_backend_tr) {
                    bt = BACKEND_STATE_UP;
                } else {
                    if (k++ < config->check_state_retry_times) {
                        g_log_dbproxy(g_warning, "due to %d over %d retry %d times to get thread_running from %s",
                                        backend->thread_running,
                                        chas->max_backend_tr, k,
                                        backend->addr->name->str);
                        sleep(config->check_state_sleep_delay);
                        goto query;
                    } else {
                        bt = BACKEND_STATE_PENDING;
                        g_log_dbproxy(g_critical, "set backend(%s) to PENDING due to thread running is %d",
                                        backend->addr->name->str, backend->thread_running);
                    }
                }
            }
set_state:
            mysql_close(&mysql);

            if (backend->state != bt) {
                SET_BACKEND_STATE(backend, bt);
                g_log_dbproxy(g_warning, "set backend (%s) state to %s",//重复
                        backend->addr->name->str,
                        bt == BACKEND_STATE_UP ? "UP" : (bt == BACKEND_STATE_DOWN ? "DOWN" : "PENDING"));
            }
        }

        if (monitor_user != NULL) { g_free(monitor_user); }
        if (monitor_pwd != NULL) { g_free(monitor_pwd); }

        g_mutex_lock(g_mutex);
        end_time = g_get_monotonic_time() + config->check_state_interval * G_TIME_SPAN_SECOND;
        if (!g_cond_wait_until(g_cond, g_mutex, end_time)) {
            g_log_dbproxy(g_debug, "check state waiting meet timeout");
        } else {
            g_log_dbproxy(g_message, "check_state thread get exit signal");
        }
        g_mutex_unlock(g_mutex);
    }
exit:
    g_log_dbproxy(g_message, "check_state thread will exit");
    g_thread_exit(0);
}
*/

/**
 * init the plugin with the parsed config
 */
int network_mysqld_proxy_plugin_apply_config(chassis *chas, chassis_plugin_config *oldconfig) {
    network_mysqld_con *con;
    network_socket *listen_sock;
    guint i;
    GError *gerr = NULL;
    network_backends_t *bs = chas->backends;

    if (!config->start_proxy) {
        return 0;
    }

    if (!config->address) {
        g_log_dbproxy(g_critical, "Failed to get bind address, please set by --proxy-address=<host:port>");
        return -1;
    }

    if (!config->backend_addresses) {
        config->backend_addresses = g_new0(char *, 2);
        config->backend_addresses[0] = g_strdup("127.0.0.1:3306");
    }

    /** 
     * create a connection handle for the listen socket 
     */
    con = network_mysqld_con_new();
    network_mysqld_add_connection(chas, con);

    config->listen_con = con;
    
    listen_sock = network_socket_new(SOCKET_LISTEN);
    network_socket_set_chassis(listen_sock, chas);
    con->server = listen_sock;

    /* set the plugin hooks as we want to apply them to the new connections too later */
    network_mysqld_proxy_connection_init(con);

    if (0 != network_address_set_address(listen_sock->dst, config->address)) {
        return -1;
    }

    if (0 != network_socket_bind(listen_sock)) {
        return -1;
    }
    g_log_dbproxy(g_message, "proxy listening on port %s", config->address);

    for (i = 0; config->backend_addresses && config->backend_addresses[i]; i++) {
        if (-1 == network_backends_add(bs, config->backend_addresses[i], BACKEND_TYPE_RW)) {
            return -1;
        }
    }

    for (i = 0; config->read_only_backend_addresses && config->read_only_backend_addresses[i]; i++) {
        if (-1 == network_backends_add(bs, config->read_only_backend_addresses[i], BACKEND_TYPE_RO)) {
            return -1;
        }
    }

    signal(SIGUSR1, handler);
    signal(SIGUSR2, handler);

    if (config->select_where_limit_str) {
        if (strcasecmp(config->select_where_limit_str, "ON") == 0) {
            config->select_where_limit = SEL_ON;
        }
    }
    if (add_shard_tables(config, config->tables) != 0) {
            return -1;
    };

    /* sql log init */
    if (sql_log_t_load_options(chas)) {
        g_log_dbproxy(g_critical, "init proxy sql log failed");
        return -1;
    }

    /* percentile init */
    if (config->percentile_controller == NULL) {
        g_log_dbproxy(g_critical, "get percentile controller failed");
        return -1;
    }
    if (config->percentile_switch && 0 == strcasecmp(config->percentile_switch, "on")) {
        config->percentile_controller->percentile_switch = pt_on;
    } else if (config->percentile_switch && 0 == strcasecmp(config->percentile_switch, "off")){
        config->percentile_controller->percentile_switch = pt_off;
    } else if (config->percentile_switch == NULL) {
        config->percentile_controller->percentile_switch = pt_off;
    } else {
        g_log_dbproxy(g_critical, "--percentile_switch has to be on or off, is %s", config->percentile_switch);
        return -1;
    }

        if (config->percentile_value > 0 && config->percentile_value <= 100) {
            config->percentile_controller->percentile_value = config->percentile_value;
        } else {
            g_log_dbproxy(g_critical, "--percentile-value has to be (1,100], is %d", config->percentile_value);
            return -1;
        }
	
	/*
	格式 做了变化 ip:用户名:密码:用户名(db):密码:(pwd)
	pwds=10.99.1.151:root:7O7YJJEK:root:7O7YJJEK
	
	zhangming 2018/1/25 23:58 
	又发生变化 
	dbproxy_user = xxx;
	dbproxy_pwd = xxx;
	master_user  = xxx;
	master_pwd  = xxx;
	slave_user    = xxx;
	slave_pwd    = xxx;

	zhangmng 2018/7/4 00:12 为保持统一, 使用原来的方法， 否则只能设置一组账号和密码了
	*/
    //for (i = 0; config->pwds && config->pwds[i]; i++) 
	{
        gchar *user = NULL, *pwd = NULL, *user_master = NULL, *pwd_master = NULL, *user_slave = NULL, *pwd_slave = NULL;
//        gchar *cur_pwd = g_strdup(config->pwds[i]);
//        gchar *tmp_for_free = cur_pwd;
        gboolean is_complete = FALSE;

		/*
        if ((user = strsep(&cur_pwd, ":")) != NULL) {
            if ((pwd = strsep(&cur_pwd, ":")) != NULL) {
                is_complete = TRUE;
            }
        }

		
		if ((user = strsep(&cur_pwd, ":")) != NULL) {
			if ((pwd = strsep(&cur_pwd, ":")) != NULL) {
				if ((user_master = strsep(&cur_pwd, ":")) != NULL) {
					if ((pwd_master = strsep(&cur_pwd, ":")) != NULL) {
						if ((user_slave = strsep(&cur_pwd, ":")) != NULL) {
							if ((pwd_slave = strsep(&cur_pwd, ":")) != NULL) {
								is_complete = TRUE;
							}
						}
					}
				}
			}
		}
		*/

		
		if(config->dbproxy_user != NULL && 
			config->dbproxy_pwd != NULL && 
			config->master_user != NULL &&
			config->master_pwd != NULL &&
			config->slave_user != NULL &&
			config->slave_pwd != NULL
		){
			is_complete = TRUE;
		}
		

        if (is_complete) {
		
			user = config->dbproxy_user;
			pwd = config->dbproxy_pwd;
			user_master = config->master_user;
			pwd_master = config->master_pwd;
			user_slave = config->slave_user;
			pwd_slave = config->slave_pwd;
			
			

			g_log_dbproxy(g_message, "user_proxy is %s, pwd_proxy is %s, user_master is %s, pwd_master is %s, user_slave is %s, pwd_slave is %s", user, pwd, user_master, pwd_master, user_slave, pwd_slave);

            char* raw_pwd = decrypt(pwd);
			char* raw_pwd_master = decrypt(pwd_master);
			char* raw_pwd_slave = decrypt(pwd_slave);

            if (raw_pwd && raw_pwd_master && raw_pwd_slave) {
				/*
				设置dbproxy本身的账号和密码
				*/

                GString* hashed_password = g_string_new(NULL);
                network_mysqld_proto_password_hash(hashed_password, raw_pwd, strlen(raw_pwd));
				
				/*
				主库 设置密码
				*/
				GString* hashed_password_master = g_string_new(NULL);
				network_mysqld_proto_password_hash(hashed_password_master, raw_pwd_master, strlen(raw_pwd_master));
				
				/*
				从库 设置密码
				*/
				GString* hashed_password_slave = g_string_new(NULL);
				network_mysqld_proto_password_hash(hashed_password_slave, raw_pwd_slave, strlen(raw_pwd_slave));
					

				/*
				hash 
				key: username (dbproxy本身的账号)
				value: 加密过的dbproxy本身的密码, 加密过的主mysql密码,加密过的从mysql密码,
				         主mysql 账号, 从mysql 账号
				*/
                user_info_hval *hval = user_info_hval_new(hashed_password, hashed_password_master, user_master, hashed_password_slave, user_slave);

//				 g_log_dbproxy(g_message, "hashed_password_slave is %s ,len is %d", hval->hashed_password_slave->str, hval->hashed_password_slave->len);

				/*
				保存密码明文, 这里是个数组，感觉作用不到,因为只有一组账号密码在起作用
				*/
                raw_user_info *rwi = raw_user_info_new(user, pwd, NULL, NULL, user_master, pwd_master, user_slave, pwd_slave);
 
                g_rw_lock_writer_lock(&bs->user_mgr_lock);
                if (g_hash_table_lookup(bs->pwd_table, user) == NULL) {
					g_hash_table_insert(bs->pwd_table, g_strdup(user), hval);
					g_ptr_array_add(bs->raw_pwds, rwi);
                }
                g_rw_lock_writer_unlock(&bs->user_mgr_lock);

                //g_free(tmp_for_free);
                g_free(raw_pwd);
            } else {
                g_log_dbproxy(g_critical, "user %s' password decrypt failed", user);
                //g_free(tmp_for_free);
                return -1;
            }
        } else {
			g_log_dbproxy(g_critical, "ccccccccccccc");
            g_log_dbproxy(g_critical, "incorrect password settings, need three groupd user/pwd");
            //g_free(tmp_for_free);
            return -1;
        }
    }


	/*
	zhangming 2018/1/17 0:34
	从配置文件中取出字段 id_generate 的值,因为每台机器都不一样
	g_log_dbproxy(g_message, "^^^^^^^^^^^^^^^^^^^ %s", config->id_generate);
	
	*/
	int region_id = 0;
	int worker_id = 0;
	gboolean is_complete = FALSE;
	gchar *id_generate = g_strdup(config->id_generate);


	if ( (region_id = strtoll(strsep(&id_generate, ":"), NULL, 10)) != NULL) {
		 g_log_dbproxy(g_message, "##### is %s", id_generate);
		if ( (worker_id = strtoll(strsep(&id_generate, ":"), NULL, 10)) != NULL) {
			is_complete = TRUE;
		}
	}
	if (is_complete) {
		 snowflake_init(region_id, worker_id);
		 g_log_dbproxy(g_message, "id_generate is %s, region_id is %d, worker_id is %d", config->id_generate, region_id, worker_id);
	} else {
		g_log_dbproxy(g_critical, "id_generate is %s, region_id is %d, worker_id is %d", config->id_generate, region_id, worker_id);
	}

    user_info_hval *whitelist = user_info_hval_new(NULL, NULL, NULL, NULL,NULL);
    raw_user_info *rwi_whitelist = raw_user_info_new(WHITELIST_USER, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    g_rw_lock_writer_lock(&bs->user_mgr_lock);
    g_hash_table_insert(bs->pwd_table, g_strdup(WHITELIST_USER), whitelist);
    g_ptr_array_add(bs->raw_pwds, rwi_whitelist);
    g_rw_lock_writer_unlock(&bs->user_mgr_lock);

    for (i = 0; config->user_ips_str && config->user_ips_str[i]; i++) {
        gchar *user = NULL, *ips = NULL;
        gboolean is_complete = FALSE;
        gchar *cur_user_info = g_strdup(config->user_ips_str[i]);
        gchar *tmp_for_free = cur_user_info;

        if ((user = strsep(&cur_user_info, USER_IDENT)) != NULL) {
            if ((ips = strsep(&cur_user_info, USER_IDENT)) != NULL) {
                is_complete = TRUE;
            }
        }

        if (is_complete) {
            if (user_hosts_handle(bs, user, ips, ADD_USER_HOST) != 0) {
                g_log_dbproxy(g_warning, "add user hosts failed: user %s doesn't exist", user);
            }
        }

        g_free(tmp_for_free);
    }

    for (i = 0; config->user_backends_str && config->user_backends_str[i]; i++) {
            gchar *user = NULL, *backends = NULL;
            gboolean is_complete = FALSE;
            gchar *cur_user_info = g_strdup(config->user_backends_str[i]);
            gchar *tmp_for_free = cur_user_info;

            if ((user = strsep(&cur_user_info, USER_IDENT)) != NULL) {
                if ((backends = strsep(&cur_user_info, USER_IDENT)) != NULL) {
                    is_complete = TRUE;
                }
            }

            if (is_complete) {
                if (user_backends_handle(bs, user, backends, ADD_BACKENDS) != 0) {
                    g_log_dbproxy(g_warning, "add user backends failed: user %s doesn't exist", user);
            }
        }

        g_free(tmp_for_free);
    }

    if (config->table_prefix && strlen(config->table_prefix) > 0) {
        config->tnw->prefix = g_strdup(config->table_prefix);
    }
    if (config->table_suffix && strlen(config->table_suffix) > 0) {
        config->tnw->suffix = g_strdup(config->table_suffix);
    }

    /* load the script and setup the global tables */
    network_mysqld_lua_setup_global(chas->sc->L, chas);

    /**
     * call network_mysqld_con_accept() with this connection when we are done
     */

    event_set(&(listen_sock->event), listen_sock->fd, EV_READ|EV_PERSIST, network_mysqld_con_accept, con);
    event_base_set(chas->event_base, &(listen_sock->event));
    event_add(&(listen_sock->event), NULL);

    /* create plugin thread */
    init_pti(pti, chas);
    for (i = 0; pti[i].plugin_thread_names != NULL; i++) {
        plugin_thread_t *plugin_thread = plugin_thread_t_new(NULL);

        plugin_thread->thread_param->magic_value = pti[i].thread_args;
        plugin_thread->thread_param->plugin_thread_cond = &(plugin_thread->thr_cond);
        plugin_thread->thread_param->plugin_thread_mutex = &(plugin_thread->thr_mutex);

        plugin_thread->thr = g_thread_try_new(pti[i].plugin_thread_names,
                                                (GThreadFunc)pti[i].thread_fn,
                                                (gpointer)plugin_thread->thread_param, &gerr);
    if (gerr) {
            g_log_dbproxy(g_message, "create %s thread failed. %s", pti[i].plugin_thread_names, gerr->message);
            g_error_free(gerr);
            gerr = NULL;
            plugin_thread_t_free(plugin_thread);
            continue;
    }

        g_hash_table_insert(config->plugin_threads,
                                g_strdup(pti[i].plugin_thread_names),
                                plugin_thread);
    }

    return 0;
}

G_MODULE_EXPORT int plugin_init(chassis_plugin *p) {
    p->magic        = CHASSIS_PLUGIN_MAGIC;
    p->name         = g_strdup("proxy");
    p->version  = g_strdup(PACKAGE_VERSION);

    p->init         = network_mysqld_proxy_plugin_new;
    p->get_options  = network_mysqld_proxy_plugin_get_options;
    p->apply_config = network_mysqld_proxy_plugin_apply_config;
    p->destroy      = network_mysqld_proxy_plugin_free;

    return 0;
}

static int
filter_pre(GPtrArray *tokens, network_mysqld_con* con, gchar *sql_raw)
{
    GString             *sql_rewrite = NULL;
    chassis             *chas = NULL;
    sql_filter          *cur_filter = NULL;
    sql_reserved_query  *cur_reserved_query = NULL;
    gchar               *sql_rewrite_md5 = NULL;
    guint               htl_size = 0;
    sql_filter_hval     *hval = NULL;
    int query_status = RQ_NO_STATUS;
    int ret = 0;

    g_assert(tokens != NULL && con != NULL && sql_raw != NULL);

    chas = con->srv;
    cur_filter = con->srv->proxy_filter;
    cur_reserved_query = con->srv->proxy_reserved;

    g_rw_lock_reader_lock(&cur_filter->sql_filter_lock);
    htl_size = g_hash_table_size(cur_filter->blacklist);
    g_rw_lock_reader_unlock(&cur_filter->sql_filter_lock);

    if (htl_size == 0 && g_atomic_int_get(&cur_reserved_query->lastest_query_num) == 0) return ret;

    sql_rewrite = sql_filter_sql_rewrite(tokens);
    if (sql_rewrite == NULL)
    {
        g_log_dbproxy(g_warning, "event_thread(%d) C:%s filter rewrite %s:%s failed",
                   chassis_event_get_threadid(),
                   NETWORK_SOCKET_SRC_NAME(con->client),
                   GET_COM_NAME(COM_QUERY), sql_raw);

        if (con->con_filter_var.cur_sql_rewrite)
            g_string_free(con->con_filter_var.cur_sql_rewrite, TRUE);
        if (con->con_filter_var.cur_sql_rewrite_md5)
            g_string_free(con->con_filter_var.cur_sql_rewrite_md5, TRUE);
        return ret;
    }

    sql_rewrite_md5 = g_compute_checksum_for_string(G_CHECKSUM_MD5,
                                      sql_rewrite->str, sql_rewrite->len);
    /* find in filter */
    if (htl_size != 0)
    {
        g_rw_lock_reader_lock(&cur_filter->sql_filter_lock);
        hval = sql_filter_lookup(cur_filter, sql_rewrite_md5);
        if (hval != NULL)
        {
            if (hval->flag == 0)
                query_status = RQ_HIT_BY_FILTER;
            else
                query_status = RQ_FOBIDDEN_BY_FILTER;

            g_atomic_int_inc(&hval->hit_times);
        }
        g_rw_lock_reader_unlock(&cur_filter->sql_filter_lock);
    }

    if (query_status & RQ_FOBIDDEN_BY_FILTER)
    {
        g_log_dbproxy(g_warning, "event_thread(%d) C:%s %s:%s fobidden by filter:%s",
               chassis_event_get_threadid(),
               NETWORK_SOCKET_SRC_NAME(con->client),
               GET_COM_NAME(COM_QUERY), sql_raw, sql_rewrite->str);
        ret = 1;
    }
    else
    {
        if (query_status & RQ_HIT_BY_FILTER)
            g_log_dbproxy(g_debug, "event_thread(%d) C:%s %s:%s hitted by filter:%s",
                    chassis_event_get_threadid(),
                    NETWORK_SOCKET_SRC_NAME(con->client),
                    GET_COM_NAME(COM_QUERY), sql_raw, sql_rewrite->str);

        /* save the input sql to con */
        if (con->con_filter_var.cur_sql_rewrite)
            g_string_assign(con->con_filter_var.cur_sql_rewrite, sql_rewrite->str);
        else
            con->con_filter_var.cur_sql_rewrite = g_string_new(sql_rewrite->str);

        if (con->con_filter_var.cur_sql_rewrite_md5)
            g_string_assign(con->con_filter_var.cur_sql_rewrite_md5, sql_rewrite_md5);
        else
            con->con_filter_var.cur_sql_rewrite_md5 = g_string_new(sql_rewrite_md5);
    }

    if (sql_rewrite_md5) g_free(sql_rewrite_md5);
    g_string_free(sql_rewrite, TRUE);
    return ret;
}

static void
filter_post(network_mysqld_con *con, injection *inj)
{
    chassis             *chas = NULL;
    sql_filter          *cur_filter = NULL;
    sql_reserved_query  *cur_rq = NULL;
    reserved_query_item *cur_rq_item = NULL;
    gchar               *sql_rewrite = NULL;
    gchar               *sql_rewrite_md5 = NULL;
    gboolean            b_new_rq = FALSE;
    gint                cur_query_time = 0;
    gint                interval_to_gap = 0;
    gint                rqi_status = RQ_NO_STATUS;
    gint                cur_time = time(NULL);

    if (con == NULL) return ;
    if (con->con_filter_var.cur_sql_rewrite == NULL || con->con_filter_var.cur_sql_rewrite_md5 == NULL) return ;
    if (inj == NULL || *(inj->query->str) != COM_QUERY || !IS_EXPLICIT_INJ(inj)) return ;

    chas = con->srv;
    cur_filter = chas->proxy_filter;
    cur_rq = chas->proxy_reserved;

    if (g_atomic_int_get(&cur_rq->lastest_query_num) < 1)
    {
#ifdef FILTER_DEBUG
        g_log_dbproxy(g_debug, "[reserved query] [skip by lastest_query_num = %d]",
                                g_atomic_int_get(&cur_rq->lastest_query_num));
#endif
        goto exit;
    }

    /* check query elapse time */
    if (g_atomic_int_get(&cur_rq->query_filter_time_threshold) < 0)
    {
#ifdef FILTER_DEBUG
        g_log_dbproxy(g_debug, "[reserved query] [skip check for query_filter_time_threshold = %d",
                                g_atomic_int_get(&cur_rq->query_filter_time_threshold));
#endif
    }
    else
    {
        cur_query_time = cur_time - con->con_filter_var.ts_read_query/(MICROSEC);
        if (cur_query_time > g_atomic_int_get(&cur_rq->query_filter_time_threshold))
            { rqi_status |= RQ_OVER_TIME; }
        else
            { rqi_status &= ~RQ_OVER_TIME; }
    }

    /* check the query frequency */
    sql_rewrite_md5  = con->con_filter_var.cur_sql_rewrite_md5->str;
    sql_rewrite = con->con_filter_var.cur_sql_rewrite->str;

    g_rw_lock_writer_lock(&cur_rq->rq_lock);
    cur_rq_item = sql_reserved_query_lookup(cur_rq, sql_rewrite_md5);
    if (cur_rq_item == NULL)
    {
        b_new_rq = TRUE;
    }
    else
    {
        /* move to tail */
        sql_reserved_query_move_to_tail(cur_rq, cur_rq_item);

        /* check query sum */
        cur_rq_item->item_access_num++;
        cur_rq_item->item_last_access_time = cur_time;

        if (g_atomic_int_get(&cur_rq->freq_time_window) == 0)
        {
#ifdef FILTER_DEBUG
            g_log_dbproxy(g_debug, "[reserved query] [skip check for freq_time_window = %d]",
                                g_atomic_int_get(&cur_rq->freq_time_window));
#endif
        }
        else
        {
            gdouble cur_freq = 0.0;

            interval_to_gap = cur_time - cur_rq_item->item_gap_start_time;
            if (interval_to_gap < g_atomic_int_get(&cur_rq->freq_time_window))
                cur_rq_item->item_gap_access_num++;
            else
            {
                cur_rq_item->item_gap_access_num = 0;
                cur_rq_item->item_gap_start_time = cur_time;
            }

            cur_freq = (double)cur_rq_item->item_gap_access_num/g_atomic_int_get(&cur_rq->freq_time_window);
            /*
             * cur_rq->query_filter_frequent_threshold is
             * protected by cur_rq->rq_lock
             */
            if (cur_freq > cur_rq->query_filter_frequent_threshold)
                { rqi_status |= RQ_OVER_FREQ;  }
            else
                { rqi_status &= ~RQ_OVER_FREQ; }
        }

        cur_rq_item->item_status |= rqi_status;
    }
    g_rw_lock_writer_unlock (&cur_rq->rq_lock);

    /* add to filter*/
    if (rqi_status & RQ_PRIORITY_2)
    {
        g_rw_lock_writer_lock(&cur_filter->sql_filter_lock);
        sql_filter_hval *hval = sql_filter_lookup(cur_filter, sql_rewrite_md5);
        if (hval == NULL)
        {
            sql_filter_insert(cur_filter, sql_rewrite, sql_rewrite_md5,
                                cur_filter->auto_filter_flag, AUTO_ADD_FILTER);
            g_log_dbproxy(g_message, "[filter][auto added][success][flag = %d] [filter: %s] [hashcode: %s]",
                                                cur_filter->auto_filter_flag,
                                                sql_rewrite, sql_rewrite_md5);
        }
        g_rw_lock_writer_unlock(&cur_filter->sql_filter_lock);
    }

    if (b_new_rq)
    {
        g_rw_lock_writer_lock(&cur_rq->rq_lock);
        cur_rq_item = sql_reserved_query_lookup(cur_rq, sql_rewrite_md5);
        if (cur_rq_item == NULL)
        {
            cur_rq_item = reserved_query_item_new(sql_rewrite, sql_rewrite_md5);
            cur_rq_item->item_status |= rqi_status;

            g_hash_table_insert(cur_rq->ht_reserved_query, g_strdup(sql_rewrite_md5), cur_rq_item);
            sql_reserved_query_insert(cur_rq, cur_rq_item);
#ifdef FILTER_DEBUG
            g_log_dbproxy(g_debug, "[filter][reserved query][added] %s", sql_rewrite);
#endif
        }
        g_rw_lock_writer_unlock(&cur_rq->rq_lock);

        sql_reserved_query_rebuild(cur_rq, g_atomic_int_get(&cur_rq->lastest_query_num));
    }

exit:

    if (con->con_filter_var.cur_sql_rewrite_md5)
    {
        g_string_free(con->con_filter_var.cur_sql_rewrite_md5, TRUE);
        con->con_filter_var.cur_sql_rewrite_md5 = NULL;
    }

    if (con->con_filter_var.cur_sql_rewrite)
    {
        g_string_free(con->con_filter_var.cur_sql_rewrite, TRUE);
        con->con_filter_var.cur_sql_rewrite = NULL;
    }

    return ;
}

static gchar *
show_proxy_address(void *ex_param)
{
    return g_strdup(config->address);
}

static gchar *
show_charset(void *ex_param)
{
    return g_strdup(config->charset);
}

static gint
assign_select_where_limit(const char *newval, void *ex_param)
{
    gboolean ret = 0;

    g_assert(newval != NULL);

    if (strcasecmp(newval, "ON") == 0) {
        config->select_where_limit = SEL_ON;
    } else if (strcasecmp(newval, "OFF") == 0) {
        config->select_where_limit = SEL_OFF;
    } else {
        ret = 1;
    }

    return ret;
}

static gchar *
show_select_where_limit(void *ex_param)
{
    if (config->select_where_limit == SEL_ON) {
        return g_strdup("ON");
    } else {
        return g_strdup("OFF");
    }
}

static gint
add_shard_tables(chassis_plugin_config *config, gchar **shard_tables)
{
    gint i = 0;
    for (i = 0; shard_tables && shard_tables[i]; i++) {
        db_table_t  *dt = g_new0(db_table_t, 1);
        gchar       *db = NULL, *token = NULL;
        gboolean    is_complete = FALSE;
        gchar       *cur_tbl_str = g_strdup(shard_tables[i]);
        gchar       *tmp_for_free = cur_tbl_str;

        if ((db = strsep(&cur_tbl_str, ".")) != NULL) {
            dt->db_name = g_strdup(db);
            if ((token = strsep(&cur_tbl_str, ".")) != NULL) {
                dt->table_name = g_strdup(token);
                if ((token = strsep(&cur_tbl_str, ".")) != NULL) {
                    dt->column_name = g_strdup(token);
                    if ((token = strsep(&cur_tbl_str, ".")) != NULL) {
                        dt->table_num = atoi(token);
						/*
						zhangming 2018/1/3 14:52
						*/
						if ((token = strsep(&cur_tbl_str, ".")) != NULL) {
							dt->split_table_method = atoi(token);
						}else{
							dt->split_table_method =1;
						}
                        if (dt->table_num > 0) {
                        is_complete = TRUE;
                    }
                }
            }
        }
        }

        g_free(tmp_for_free);

        if (is_complete) {
            gchar* key = g_strdup_printf("%s.%s", dt->db_name, dt->table_name);
            g_rw_lock_writer_lock(&config->config_lock);
            g_hash_table_insert(config->dt_table, key, dt);
            g_rw_lock_writer_unlock(&config->config_lock);
        } else {
            g_log_dbproxy(g_critical, "incorrect sub-table settings");
            dt_table_free(dt);
            return 1;
        }
    }

    return 0;
}

static gint
remove_shard_tables(chassis_plugin_config *config, gchar **shard_tables)
{
    gint i = 0;
    gint ret = 0;
    g_rw_lock_writer_lock(&config->config_lock);
    for (i = 0; shard_tables && shard_tables[i]; i++) {
        /* check ? */
        if (!g_hash_table_remove(config->dt_table, shard_tables[i])) {
            ret = 1;
            break;
        }
    }
    g_rw_lock_writer_unlock(&config->config_lock);

    return ret;
}


static gint
assign_shard_tables(const char *newval, void *ex_param)
{
    gchar **shard_tables = NULL;
    gint ret = 1;
    external_param *t_param = (external_param *)ex_param;

    g_assert(newval != NULL);

    shard_tables = g_strsplit(newval, ",", -1);

    if (shard_tables != NULL) {
        if (t_param->opt_type == ADD_SHARD_TABLE) {
            ret = add_shard_tables(config, shard_tables);
        } else if (t_param->opt_type == RM_SHARD_TABLE) {
            ret = remove_shard_tables(config, shard_tables);
        }

        if (shard_tables != NULL) {
            g_strfreev(shard_tables);
        }
    }

    return ret;
}

/*
zhangming 2018/1/3 15:00
该函数用于在终端输入 show tables 显示
*/
static GString *
get_shard_tables(void *ex_param)
{
	 g_log_dbproxy(g_critical, "get_shard_tables");
    GHashTableIter  iter;
    db_table_t      *dt_value = NULL;
    gchar           *key = NULL;
    GString         *shard_tables = NULL;
    gint            i = 0;
    gint            shard_table_len = 0;

    g_rw_lock_reader_lock(&config->config_lock);

    shard_table_len = g_hash_table_size (config->dt_table);
    if (shard_table_len > 0) {
        shard_tables = g_string_new(NULL);
    }

    g_hash_table_iter_init(&iter, config->dt_table);

    while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&dt_value)) {
		/*
		zhangming 2018/1/3 14:56
        g_string_append_printf(shard_tables, "%s.%s.%s.%d%s",
                                        dt_value->db_name, dt_value->table_name,
                                        dt_value->column_name, dt_value->table_num,
                                        (i == shard_table_len - 1) ? "" : ",");

		*/
		g_string_append_printf(shard_tables, "%s.%s.%s.%d.%d%s",
                                        dt_value->db_name, dt_value->table_name,
                                        dt_value->column_name, dt_value->table_num,
                                        dt_value->split_table_method,
										(i == shard_table_len - 1) ? "" : ",");

        i++;
		
    }
    g_rw_lock_reader_unlock(&config->config_lock);

    return shard_tables;
}

static gchar *
shard_tables_show_save(void *ex_param)
{
    external_param *st_param = (external_param *) ex_param;
    const gchar *opt_tables = st_param->tables;

    GString *shard_tables = get_shard_tables(NULL);

    if (st_param->opt_type == SAVE_SHARD_TABLE) {
        gchar *res = NULL;
        if (shard_tables != 0 && shard_tables->len > 0) {
            res = g_strdup(shard_tables->str);
            g_string_free(shard_tables, TRUE);
        }

        return res;
    }
int num=0;
    if (st_param->opt_type == SHOW_SHARD_TABLE) {
        lua_State *L = (lua_State *)(st_param->L);
        lua_newtable(L);
			 num = lua_gettop(L);
 g_log_dbproxy(g_critical, "stack num is %d", num);
        if (shard_tables != NULL) {
            gint i = 0, j = 0;
            gchar   **tables = g_strsplit(shard_tables->str, ",", -1);
            gchar   **opt_table_array = g_strsplit(opt_tables, ",", -1);

            for (i = 0; tables && tables[i]; i++) {
                gint match = 0;

                if (*opt_table_array == NULL) {
                    match = 1;
                } else {
                    for (j = 0; opt_table_array != NULL && opt_table_array[j]; j++) {
                        if (opt_match(tables[i], opt_table_array[j])) {
                            match = 1;
                            break;
                        }
                    }
                }
                if (match == 0) continue;
			//	lua_pushstring(L,"table");


                lua_pushstring(L, tables[i]);
				
//				lua_newtable(L);
//                lua_pushstring(L, "test");

                lua_newtable(L);
                lua_pushstring(L, "db");

                gchar *db_name_end = g_strstr_len(tables[i], strlen(tables[i]), ".");
                gchar *db_name = g_strndup(tables[i], db_name_end - tables[i]);
                lua_pushlstring(L, C_S(db_name));



                lua_settable(L, -3);
				
			
				if(lua_istable(L,-1)) {
					 g_log_dbproxy(g_critical, "is table");
				}
			//	lua_remove(L, -1);
	 num = lua_gettop(L);
g_log_dbproxy(g_critical, "stack num is %d", num);
                lua_settable(L, -3);

//				 lua_settable(L, -3);

                g_free(db_name);
            }

            if (tables != NULL) {
                g_strfreev(tables);
            }
            if (opt_table_array != NULL) {
                g_strfreev(opt_table_array);
            }
        }

        if (shard_tables) {
            g_string_free(shard_tables, TRUE);
        }
    }
    return NULL;
}

static int
assign_check_state_conn_timeout(const char *newval, void *ex_param)
{
    g_assert(newval != NULL);
    return set_raw_int_value(newval, &config->check_state_conn_timeout,
                                                        0, G_MAXINT32);
}

static gchar *
show_check_state_conn_timeout(void *ex_param)
{
     return g_strdup_printf("%d", config->check_state_conn_timeout);
}

static int
assign_check_state_interval(const char *newval, void *ex_param)
{
    return set_raw_int_value(newval, &config->check_state_interval,
                                      0, G_MAXINT32);
}

static gchar *
show_check_state_interval(void *ex_param)
{
    return g_strdup_printf("%d", config->check_state_interval);
}

static plugin_thread_t *
plugin_thread_t_new(GThread *thr)
{
    plugin_thread_t *plugin_thread = g_new0(plugin_thread_t, 1);

    plugin_thread->thr = thr;
    g_cond_init(&plugin_thread->thr_cond);
    g_mutex_init(&plugin_thread->thr_mutex);

    plugin_thread->thread_param = g_new0(plugin_thread_param, 1);

    return plugin_thread;
}

static void
plugin_thread_t_free(plugin_thread_t *plugin_thread)
{
    if (plugin_thread == NULL) return ;

    g_mutex_lock(&plugin_thread->thr_mutex);
    g_cond_signal(&plugin_thread->thr_cond);
    g_mutex_unlock(&plugin_thread->thr_mutex);

    g_assert (GPOINTER_TO_INT(g_thread_join(plugin_thread->thr)) == 0);

    g_cond_clear(&plugin_thread->thr_cond);
    g_mutex_clear(&plugin_thread->thr_mutex);

    g_free(plugin_thread->thread_param);
    g_free(plugin_thread);

    return ;
}

static int
assign_check_state_retry_times(const char *newval, void *ex_param) {
    g_assert(newval != NULL);
    return set_raw_int_value(newval, &config->check_state_retry_times,
                                                        0, G_MAXINT32);
}

static gchar *show_check_state_retry_times(void *ex_param) {
    return g_strdup_printf("%d", config->check_state_retry_times);
}

static int
assign_check_state_sleep_delay(const char *newval, void *ex_param) {
    g_assert(newval != NULL);
    return set_raw_int_value(newval, &config->check_state_sleep_delay,
                                                        0, G_MAXINT32);
}

static gchar *
show_check_state_sleep_delay(void *ex_param) {
     return g_strdup_printf("%d", config->check_state_sleep_delay);
}

static tbl_name_wrap *
tbl_name_wrap_new()
{
    tbl_name_wrap *tnw = g_new0(tbl_name_wrap,1);

    tnw->prefix = NULL;
    tnw->suffix = NULL;
    g_rw_lock_init(&tnw->name_wrap_lock);
    return tnw;
}

static void
tbl_name_wrap_free(tbl_name_wrap *tnw)
{
    if (tnw == NULL) {
        return ;
    }

    if (tnw->prefix) g_free(tnw->prefix);
    if (tnw->suffix) g_free(tnw->suffix);

    g_rw_lock_clear(&tnw->name_wrap_lock);

    g_free(tnw);
}

static int
assign_table_prefix(const char *newval, void *ex_param) {
    if (config->tnw != NULL) {
        g_rw_lock_writer_lock(&config->tnw->name_wrap_lock);
        if (config->tnw->prefix != NULL) {
            g_free(config->tnw->prefix);
        }
        config->tnw->prefix = g_strdup(newval);
        g_rw_lock_writer_unlock(&config->tnw->name_wrap_lock);
    }
    return 0;
}

static gchar *
show_table_prefix(void *ex_param) {
    gchar *res = NULL;
    if (config->tnw != NULL) {
        g_rw_lock_reader_lock(&config->tnw->name_wrap_lock);
        if (config->tnw->prefix != NULL) {
            res = g_strdup(config->tnw->prefix);
        }
        g_rw_lock_reader_unlock(&config->tnw->name_wrap_lock);
    }

    return res ? res : g_strdup("");
}

static int
assign_table_suffix(const char *newval, void *ex_param) {
    if (config->tnw != NULL) {
        g_rw_lock_writer_lock(&config->tnw->name_wrap_lock);
        if (config->tnw->suffix != NULL) {
            g_free(config->tnw->suffix);
        }
        config->tnw->suffix = g_strdup(newval);
        g_rw_lock_writer_unlock(&config->tnw->name_wrap_lock);
    }

    return 0;
}

static gchar *
show_table_suffix(void *ex_param) {
    gchar *res = NULL;
    if (config->tnw != NULL) {
        g_rw_lock_reader_lock(&config->tnw->name_wrap_lock);
        if (config->tnw->suffix != NULL) {
            res = g_strdup(config->tnw->suffix);
        }
        g_rw_lock_reader_unlock(&config->tnw->name_wrap_lock);
    }

    return res ? res : g_strdup("");
}




