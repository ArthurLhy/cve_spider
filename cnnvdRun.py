'''
Date: 2020-10-16 14:32:11
LastEditors: Hangyu
LastEditTime: 2021-09-22 12:46:37
FilePath: /cve_spider/cnnvdRun.py
'''
import subprocess
from os import (system, chdir)
from datetime import datetime
import schedule
from time import sleep

def job():
    chdir('cve_cpe/')
    
    message = "update" + datetime.now().strftime("%m/%d/%Y-%H:%M:%S")
    
schedule.every().day.at("10:30").do(job)
while True:
    schedule.run_pending()
    sleep(1)


    
