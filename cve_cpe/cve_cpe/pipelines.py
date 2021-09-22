'''
Author: your name
Date: 2020-09-27 10:21:11
LastEditTime: 2020-10-26 17:20:54
LastEditors: Hangyu
Description: In User Settings Edit
FilePath: /gitlab/cve_spider/cve_cpe/cve_cpe/pipelines.py
'''
# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html

# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
from scrapy.exceptions import DropItem
from time import strptime
import json
import logging
from os import path

class UpdatePipeline:
    def __init__(self):
        pass
        
    def open_spider(self, spider):
        logging.info("<<< 正在更新漏洞数据 >>>")
        pass
    
    def process_item(self, item, spider):
        
        pub_year = strptime(item['publish_date'], '%Y-%m-%d').tm_year
        target_file = path.abspath('./cvestatic/cve/nvdcve-%s.json'%pub_year)
        
        self.reader = open(target_file, 'r+')
        self.file = self.reader.read()
        data = json.loads(self.file)
        
        for i in range(0, len(data)):
            if (data[i]["ID"] == item["ID"]) and (data[i]["versionID"] != item["versionID"]):
                data[i] = dict(item)
                logging.info("modified cve found: %s"%item["ID"])
                self.reader.seek(0)
                self.reader.truncate()
                self.reader.write(json.dumps(data))
                return
            elif (data[i]["ID"] == item["ID"]) and (data[i]["versionID"] == item["versionID"]):
                logging.info("duplicated cve found: %s"%item)
                raise DropItem("duplicated cve found: %s"%item)
        
        data.append(dict(item))
        logging.info("new cve found: %s"%item["ID"])
        temp = json.dumps(data)
        
        self.reader.seek(0)
        self.reader.truncate()
        self.reader.write(temp)
        self.reader.close()
        
        pass
    
    def close_spider(self, spider):
        logging.info('更新已结束')
        pass
    
class cnnvdPipeline:
    
    def __init__(self):
        pass
        
    def open_spider(self, spider):
        print("<<< 中文数据初始化开始 >>>")
        pass
    
    def process_item(self, item, spider):
        
        pub_year = strptime(item['publish_date'], '%Y-%m-%d').tm_year
        target_file = './cvestatic/cnnvd/cnnvdcve-%s.json'%pub_year
        print(path.exists(target_file))
        if path.exists(target_file):
            read = True
            self.reader = open(target_file, 'r+')
        else:
            read = False
            data = []
            self.reader = open(target_file, 'a+')
            
        self.file = self.reader.read()
        if read == True:
            data = json.loads(self.file)
        
        if data is not []:
            for i in range(0, len(data)):
                if (data[i]["ID"] == item["ID"]) and (data[i]["versionID"] != item["versionID"]):
                    data[i] = dict(item)
                    logging.info("modified cnnvd cve found: %s"%item["ID"])
                    self.reader.seek(0)
                    self.reader.truncate()
                    self.reader.write(json.dumps(data, ensure_ascii=False))
                    return
                elif (data[i]["ID"] == item["ID"]) and (data[i]["versionID"] == item["versionID"]):
                    logging.info("duplicated cnnvd cve found: %s"%item)
                    raise DropItem("duplicated cnnvd cve found: %s"%item)
        
        data.append(dict(item))
        logging.info("new cnnvd cve found: %s"%item["ID"])
        temp = json.dumps(data, ensure_ascii=False)
        
        self.reader.seek(0)
        self.reader.truncate()
        self.reader.write(temp)
        self.reader.close()
        
        pass
    
    def close_spider(self, spider):
        print('update finished!')
        pass