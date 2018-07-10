#!/bin/sh

function input()
{
	read -p "$1" param
	if [ "$param" == "" ]; then
		echo $2
	else
		echo $param
	fi
}

create="yes"

while [ $create == "yes" ]
do
	#1. ��server��
	server=`input "please input server: " $server`

	#2. ��DB��
	db=`input "please input DB: " $db`

	#3. ���û���
	username=`input "please input username: " $username`

	#4. ������
	password=`input "please input password: " $password`

	#5. ������
	table=`input "please input table name: " ""`

	#6. ���ӱ�����
	num=`input "please input num of sub-tables: " ""`

	#7. ���������
	sql=`input "please input SQL of create table(no return): " ""`

	#8. ����һ���ӱ�table_0
	echo -e $sql
	sh -c "mysql -h$server -u$username -p$password $db -e'$sql'"

	#9. �������ӱ�
	for (( i=1; i<$num; i=i+1 ))
	do
	    sql="CREATE TABLE ${table}_${i} LIKE ${table}_0"
	    echo -e $sql
	    sh -c "mysql -h$server -u$username -p$password $db -e'$sql'"
	done

	#10. �Ƿ������
	read -p "continue to create table?(type yes or no)" create
done
