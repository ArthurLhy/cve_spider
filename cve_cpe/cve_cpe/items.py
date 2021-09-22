'''
Author: your name
Date: 2020-09-27 10:21:11
LastEditTime: 2020-10-26 16:48:28
LastEditors: Hangyu
Description: In User Settings Edit
FilePath: /gitlab/cve_spider/cve_cpe/cve_cpe/items.py
'''
# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CveCpeItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    ID = scrapy.Field()
    data_format = scrapy.Field()
    publish_date = scrapy.Field()
    last_modified_date = scrapy.Field()
    description = scrapy.Field()
    cvss3_info = scrapy.Field()
    cvss2_info = scrapy.Field()
    cwe_info = scrapy.Field()
    cpe_match = scrapy.Field()
    references = scrapy.Field()
    versionID = scrapy.Field()
    pass

class CnnvdItem(scrapy.Item):
    
    ID = scrapy.Field()
    name = scrapy.Field()
    cnnvdID = scrapy.Field()
    source = scrapy.Field()
    publish_date = scrapy.Field()
    last_modified_date = scrapy.Field()
    description = scrapy.Field()
    announcement = scrapy.Field()
    level = scrapy.Field()
    vul_type = scrapy.Field()
    threat_type = scrapy.Field()
    vendor = scrapy.Field()
    references = scrapy.Field()
    patch = scrapy.Field()
    versionID =scrapy.Field()
    
    
    