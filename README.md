# db-proxy

修改美团dbproxy源码

修复了若干小问题<br/>
1. 分表字段为int, select in 多个时, 会少查询一些数据<br/>
分表字段 uid<br/>
分表个数 2<br/>
select * from 表名 where uid in (2,8)<br/>

mt[2%2] = 2<br/>
mt[8%2] = 8<br/>

后面会覆盖前面<br/>

