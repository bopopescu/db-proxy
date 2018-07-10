#include <stdio.h>

/*
 gcc $(pkg-config --cflags --libs glib-2.0 gmodule-2.0) -o test2 test2.c
 */
#include <stdlib.h>
#include <glib.h>
#include <gmodule.h>


/* the function signature for 'say_hello' */


typedef int (*snowflake_init_func) (int region_id, int worker_id);
typedef long int (*snowflake_id_func) ();

gboolean get_id (const char *filename, GError **error) {
  snowflake_init_func snowflake_init;
  snowflake_id_func  snowflake_id; 
  GModule      *module;

  char* mo = g_module_build_path("./", filename);
  printf("module addr is %s\n", mo);

  module = g_module_open (mo, G_MODULE_BIND_LAZY);
  if (!module){
      g_warning ("%s: %s", filename, g_module_error ());
      return FALSE;
    }

  if (!g_module_symbol (module, "snowflake_init", (gpointer *)&snowflake_init)){
    if (!g_module_close (module))
      g_warning ("%s: %s", filename, g_module_error ());
      return FALSE;
    }

  /* call our function in the module */
  snowflake_init (1,2);

  if (!g_module_symbol (module, "snowflake_id", (gpointer *)&snowflake_id)){

	}

  long int id = snowflake_id();
  printf("id is %ld\n", id);
  if (!g_module_close (module))
    g_warning ("%s: %s", filename, g_module_error ());

  return TRUE;
}

int main(){
  gboolean res = FALSE;
  GError* err;
  res = get_id("snow", &err);
  //printf("true %d\n", TRUE);
  //printf("false %d\n", FALSE);
  //printf("%d\n", res);
  return 0;
}
