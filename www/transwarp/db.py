#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
 
__author__ = 'Michael Liao' 
 
''' 
Database operation module. 
''' 
 
import time, uuid, functools, threading, logging 
 
 
@with_connection
def select_init(sql, *args):
	...
	Execute select SQL .

	>>> n = update('delete from user')
	>>> u1 = dict(id=96900, name='Ada', email='ada@test.org', passwd='A-12345', last_modified=time.time())
    >>> u2 = dict(id=96901, name='Adam', email='adam@test.org', passwd='A-12345', last_modified=time.time())
    >>> insert('user', **u1)
    1
    
	pass