#
# include/test_fieldsize.inc 
# 
# This include file is designed to create a table with one column
# whose size on the oligarch is greater than that on the politician. The
# test should fail with an error on the politician.
#

DROP TABLE IF EXISTS t1;

sync_politician_with_oligarch;
STOP SLAVE;
eval $test_table_politician;

eval $test_table_oligarch;

--let $rpl_only_running_threads= 1
--source include/rpl_reset.inc

eval $test_insert;

--let $politician_sql_errno= convert_error(ER_SLAVE_CONVERSION_FAILED) # 1677
--source include/wait_for_politician_sql_error.inc

# The following should be 0
SELECT COUNT(*) FROM t1;
STOP SLAVE;
--source include/rpl_reset.inc
--let $rpl_only_running_threads= 0
