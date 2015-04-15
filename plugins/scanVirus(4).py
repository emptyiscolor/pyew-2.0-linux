#!usr/bin/env python
#-*-coding:utf-8 -*-
''' 
1.将表中信息拿出来，如果表为空返回失败，如果有信息则返回信息
2.将所取信息和Demo对比，如果找到就上报病毒，没有则上报文件无病毒
'''
import os
import sqlite3
import string
import binascii

DB_NAME = "files.sqlite"
DATABASE_PATH = os.path.abspath(os.path.join(os.path.dirname("__file__"),os.path.pardir)) + os.sep + "files.sqlite"


#binascii.b2a_hex(row[field]) 
#binascii.a2b_hex("e4bda0e5a5bde5958a").decode("utf8")

def extractSig(db):
	try:
		con = sqlite3.connect(DATABASE_PATH)
		cur = con.cursor()
		list1 = []
		cur.execute("select Sig from db")
		list1 = cur.fetchall()
		close()
	except:
		print 'table info is null...'

	return list1


def scanVirus(pyew,db):
        
	l = extractSig(DB_NAME)	
	buf = pyew.getBuffer()

	if len(buf) == 0:
		print 'scan virus error file is none...  '
	return

	try:
		if l in x.findall(buf, re.IGNORECASE | re.MULTILINE):
			print 'this file is infected by the virus...'
	except:
		print 'this file is safe...'

	return


functions = {"scanvirus": scanVirus}
