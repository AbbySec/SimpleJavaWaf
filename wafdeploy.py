#!/usr/bin/python
# coding=utf-8
'''
Created on Nov 17, 2019

@author: bobo_rb
'''
import os

base_dir = '/Users/dabaicai/Documents/tmp/html'


def scandir(startdir):
    os.chdir(startdir)
    for obj in os.listdir(os.curdir):
        path = os.getcwd() + os.sep + obj
        if os.path.isfile(path) and '.php' in obj:
            modifyip(path, '<?php', '<?php\nrequire_once(\'' + base_dir + '/waf.php\');')  # 强行加一句代码
        if os.path.isdir(obj):
            scandir(obj)
            os.chdir(os.pardir)


def modifyip(tfile, sstr, rstr):
    try:
        lines = open(tfile, 'r').readlines()
        flen = len(lines) - 1
        for i in range(flen):
            if sstr in lines[i]:
                lines[i] = lines[i].replace(sstr, rstr)
        open(tfile, 'w').writelines(lines)

    except Exception as e:
        print e


scandir(base_dir)
