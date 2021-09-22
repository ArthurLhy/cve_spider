'''
Author: your name
Date: 2020-09-27 10:30:02
LastEditTime: 2020-11-02 17:45:06
LastEditors: Hangyu
Description: In User Settings Edit
FilePath: /gitlab/cve_spider/cve_cpe/cve_cpe/spiders/spider_cve.py
'''

from datetime import date, timedelta
from hashlib import md5
from lxml import etree
from json import loads
from time import (strftime, strptime)
from datetime import datetime
import scrapy
from cve_cpe.items import (CveCpeItem, CnnvdItem)


class SpiderCveSpider(scrapy.Spider):
    name = 'spider_cve'
    allow_domains = ['https://nvd.nist.gov/']
    current_index = 0
    orginal_url = ''
    
    def mode_select(self, mode, startdate = '01%2F01%2F1990', enddate = '12%2F31%2F2009'):
        
        url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&'
         
        if mode == 'init':
            url = url + 'pub_start_date=%s'%startdate + "&pub_end_date=%s"%enddate
        elif mode == 'update':
            yesterday = date.today() + timedelta(-2)
            yesterday = yesterday.__format__('%m%2f%d%2f%Y')    
            url = url + 'mod_start_date=' + yesterday
        elif mode == 'allupdate':
            url = url
        return url
    
    def start_requests(self):
        # search for updates in NVD for last three days
        self.orginal_url = self.mode_select('update')
        yield scrapy.Request(self.orginal_url, callback = self.parse)
        
        
    def parse(self, response):
        # go detail into the cve page to request the detail information
        index = response.xpath("//div[@class='col-sm-12 col-lg-3']/strong/text()").extract_first().replace(",", "")
        list_selector = response.xpath("//table[@data-testid='vuln-results-table']/tbody/tr/th/strong/a")

        for items in list_selector:
            url = 'https://nvd.nist.gov' + items.xpath("@href").extract_first()
            yield scrapy.Request(url, callback = self.detail_parse)
            
        self.current_index += 20
        
        if self.current_index < int(index):
            next_url = self.orginal_url + "&startIndex=%d"%(self.current_index)
            yield scrapy.Request(next_url, callback = self.parse)
            
    def detail_parse(self, response):
        
        item = CveCpeItem()
        item['references'] = []
        item['cpe_match'] = []
        item['cwe_info'] = []
       
        items = response.xpath("//table[@id='vulnDetailTableView']/tr/td/div")
        
        data_format = items.xpath('div[2]/div/span[3]/text()').extract_first()
        ID = items.xpath('div[2]/div/a/text()').extract_first() 
        publish_date = items.xpath('div[2]/div/span[1]/text()').extract_first()
        publish_date = strftime("%Y-%m-%d", strptime(publish_date, "%m/%d/%Y"))
        last_modified_date = items.xpath('div[2]/div/span[2]/text()').extract_first()
        last_modified_date = strftime("%Y-%m-%d", strptime(last_modified_date, "%m/%d/%Y"))
        description = items.xpath("div[1]/p[1]/text()").extract()
        
        versionID = md5((ID + last_modified_date).encode("utf-8")).hexdigest()

        item['ID'] = ID
        item['data_format'] = data_format
        item['publish_date'] = publish_date
        item['last_modified_date'] = last_modified_date
        item['versionID'] = versionID
        item['description'] = description
        
        #deal with cvss detail
        item['cvss3_info'] = self.deal_with_cvss(items, 'cvss3')
        item['cvss2_info'] = self.deal_with_cvss(items, 'cvss2')
        
        #deal with reference info                    
        reference_list = items.xpath("//table[@data-testid='vuln-hyperlinks-table']/tbody/tr")
        
        for i in range(len(reference_list)):
            path = "//table[@data-testid='vuln-hyperlinks-table']/tbody/tr[%d]/td[1]/a/text()"%(i+1)
            item['references'].append(reference_list.xpath(path).extract_first())
        
        #deal with cwe info
        cwe_list = items.xpath("//table[@data-testid='vuln-CWEs-table']/tbody/tr")
        
        for i in range(len(cwe_list)):
            id_path = "//table[@data-testid='vuln-CWEs-table']/tbody/tr[%d]/td[1]/a/text()"%(i+1)
            name_path = "//table[@data-testid='vuln-CWEs-table']/tbody/tr[%d]/td[2]/text()"%(i+1)
            item['cwe_info'].append({'cwe_id': cwe_list.xpath(id_path).extract_first(),
                                     'cwe_name': cwe_list.xpath(name_path).extract_first()})
            
        url = "https://nvd.nist.gov/vuln/detail/" + ID + "/cpes?expandCpeRanges=true"
        yield scrapy.Request(url, meta = {"item": item}, callback = self.cpe_parse, dont_filter = True)
    
    def cpe_parse(self, response):
        item = response.meta["item"]
        
        cpe_list = response.xpath("//input[@id='cveTreeJsonDataHidden']/@value").extract()
        for config in cpe_list:
            config = config.replace("&quotquot;", "\"").replace("&quoquot;", "\"")
            config = loads(config)
            for configlist in config:
                containers = configlist['containers']
                for level_1 in containers:
                    for info in level_1['cpes']:
                        item['cpe_match'].append({'cpe23Uri': info['cpe23Uri'].replace("\\", ""),
                                                'cpe22Uri': info['cpe22Uri']})
                        for matchcpe in info['matchCpes']:
                            item['cpe_match'].append({'cpe23Uri': matchcpe['cpe23Uri'].replace("\\", ""),
                                                    'cpe22Uri': matchcpe['cpe22Uri']})
                        for rangecpe in info['rangeCpes']:
                            item['cpe_match'].append({'cpe23Uri': rangecpe['cpe23Uri'].replace("\\", ""),
                                                    'cpe22Uri': rangecpe['cpe22Uri']})
                    sub_containers = level_1['containers']
                    for level_2 in sub_containers:
                        for subinfo in level_2['cpes']:
                            item['cpe_match'].append({'cpe23Uri': subinfo['cpe23Uri'].replace("\\", ""),
                                                    'cpe22Uri': subinfo['cpe22Uri']})
                            for matchcpe in subinfo['matchCpes']:
                                item['cpe_match'].append({'cpe23Uri': matchcpe['cpe23Uri'].replace("\\", ""),
                                                        'cpe22Uri': matchcpe['cpe22Uri']})
                            for rangecpe in subinfo['rangeCpes']:
                                item['cpe_match'].append({'cpe23Uri': rangecpe['cpe23Uri'].replace("\\", ""),
                                                        'cpe22Uri': rangecpe['cpe22Uri']})
                        
                    
        yield item
                  
    def deal_with_cvss(self, items, cvss):
        
        cvss_return = []
            
        if cvss == 'cvss3':
            cvss_list = cvss_vector = items.xpath("//div[@id='Vuln3CvssPanel']/div[@class='row no-gutters']")
        elif cvss == 'cvss2':
            cvss_list = cvss_vector = items.xpath("//div[@id='Vuln2CvssPanel']/div[@class='row no-gutters']")
        
        for i in range(len(cvss_list)):
            
            if cvss == 'cvss3':
                path = "//div[@id='Vuln3CvssPanel']/div[%d]/"%(i+1)
            elif cvss == 'cvss2':
                path = "//div[@id='Vuln2CvssPanel']/div[%d]/"%(i+1)
                
            provider_path = path + "div[1]/div/div[2]/span/text()"
            cvss_info_path = path + "div[2]/span/span/a/text()"
            cvss_vector_path = path + "div[3]/span/span/text()"
            cvss_detail_path = path + "div[3]/input/@value"
                
            provider = items.xpath(provider_path).extract_first()
            cvss_info = items.xpath(cvss_info_path).extract_first().split()
            cvss_detail = items.xpath(cvss_detail_path).extract_first()
            cvss_vector = items.xpath(cvss_vector_path).extract_first().rstrip(")").lstrip("(")
            
            
            if len(cvss_info) == 2:
                cvss3_score = cvss_info[0]
                cvss3_severity = cvss_info[1] 
                detail_element = etree.HTML(cvss_detail)
                
                impact_score = detail_element.xpath("//p[1]/span[4]/text()")[0]
                explo_score = detail_element.xpath("//p[1]/span[5]/text()")[0]
                av = detail_element.xpath("//p[2]/span[1]/text()")[0]
                ac = detail_element.xpath("//p[2]/span[2]/text()")[0]
                
                if cvss == 'cvss3':
                    pr = detail_element.xpath("//p[2]/span[3]/text()")[0]
                    ui = detail_element.xpath("//p[2]/span[4]/text()")[0]
                    scope = detail_element.xpath("//p[2]/span[5]/text()")[0]
                    confident = detail_element.xpath("//p[2]/span[6]/text()")[0]
                    integrity = detail_element.xpath("//p[2]/span[7]/text()")[0]
                    availability = detail_element.xpath("//p[2]/span[8]/text()")[0]
                    
                    cvss_detail = {'impact_score': impact_score.strip(),
                                'exploitability_score': explo_score.strip(),
                                'Attack Vector': av.strip(),
                                'Attack Complexity': ac.strip(),
                                'Privileges Required': pr.strip(),
                                'User Interaction': ui.strip(),
                                'Scope': scope.strip(),
                                'Confidentiality': confident.strip(),
                                'Integrity': integrity.strip(),
                                'Availability': availability.strip()}
                
                elif cvss == 'cvss2':
                    au = detail_element.xpath("//p[2]/span[3]/text()")[0]
                    confident = detail_element.xpath("//p[2]/span[4]/text()")[0]
                    integrity = detail_element.xpath("//p[2]/span[5]/text()")[0]
                    availability = detail_element.xpath("//p[2]/span[6]/text()")[0]
                    addtional = detail_element.xpath("//p[2]/span[7]/text()")
                    
                    cvss_detail = {'impact_score': impact_score,
                                'exploitability_score': explo_score,
                                'Attack Vector': av,
                                'Attack Complexity': ac,
                                'Authentication': au,
                                'Confidentiality': confident,
                                'Integrity': integrity,
                                'Availability': availability,
                                'Additional Information': addtional}
            else:
                cvss3_score = cvss3_severity = cvss_vector = ""
            
            if cvss == 'cvss3':
                cvss_return.append({'cvss3_provider': provider,
                                    'cvss3_score': cvss3_score,
                                    'cvss3_severity': cvss3_severity,
                                    'cvss3_vector': cvss_vector,
                                    'cvss3_detail': cvss_detail})  
            elif cvss == 'cvss2':
                cvss_return.append({'cvss2_provider': provider,
                                    'cvss2_score': cvss3_score,
                                    'cvss2_severity': cvss3_severity,
                                    'cvss2_vector': cvss_vector,
                                    'cvss2_detail': cvss_detail})
        return cvss_return
         
class CnnvdSpider(scrapy.Spider):
    name = "cnnvd"
    start_urls = ['http://cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=10']
      
    def parse(self, response):
        vul_list = response.css("div.list_list ul li")
        for vul_item in vul_list:
            vul_attr = vul_item.css("a::attr(href)").get()
            yield response.follow(vul_attr, callback=self.parse_vul_detail)

        link_list = response.css(".page")[0].css("a")
        for link in link_list:
            link_text = link.css('a::text').get()
            # print(link_text)
            if "上一页" in link_text:
                next_page = link.css('a')[0].attrib["onclick"].split("'")[1]
                # print(next_page)
                if next_page is not None:
                    yield response.follow(next_page, callback=self.parse)
    
    
    def parse_vul_detail(self, response):
        
        item = CnnvdItem()
        detail_xq_div = response.css(".detail_xq")
        
        # title
        vul_title = detail_xq_div.css("h2::text").get().strip()
        item['name'] = vul_title
        
        
        # 2. ul li
        vul_info_list = detail_xq_div.css("ul li")
        
        cnnvdID = vul_info_list[0].css("span::text").get().replace("CNNVD编号：", "")
        item['cnnvdID'] = cnnvdID
        item['level'] = self.tell_and_strip(vul_info_list[1].css("a::text").get())
        item["ID"] = self.tell_and_strip(vul_info_list[2].css("a::text").get())
        item["vul_type"] = self.tell_and_strip(vul_info_list[3].css("a::text").get())
        item["publish_date"] = self.tell_and_strip(vul_info_list[4].css("a::text").get())
        item["threat_type"] = self.tell_and_strip(vul_info_list[5].css("a::text").get())
        last_modified_date = self.tell_and_strip(vul_info_list[6].css("a::text").get())
        item["last_modified_date"] = last_modified_date
        item["vendor"] = self.tell_and_strip(vul_info_list[7].css("a::text").get())
        item["source"] = self.tell_and_strip(vul_info_list[8].css("a::text").get())
        
        versionID = md5((cnnvdID + last_modified_date).encode("utf-8")).hexdigest()
        item["versionID"] = versionID 
        
        item["description"] = []
        item["announcement"] = []
        item["references"] = []
                    
        # 3. d_ldjj
        vul_info_list2 = response.css(".d_ldjj")
        
        for vul_info in vul_info_list2:
            title = vul_info.css(".title_bt").css("h2::text").get().strip()
            
            if "漏洞简介" in title:
                for des in vul_info.css("p::text").getall():
                    des = self.deal_with_strip(des) 
                    item["description"].append(des)            
            if "漏洞公告" in title:
                for des in vul_info.css("p::text").getall():
                    des = self.deal_with_strip(des)
                    item["announcement"].append(des) 
            if "参考网址" in title:
                for a in vul_info.css("p::text").getall():
                    if "链接:" in a:
                        des = self.deal_with_strip(a[3:])
                        item["references"].append(des) 
            if "补丁" in title:
                patch_name = vul_info.css("a::text").get()
                if patch_name is not None:
                    patch_url = "http://cnnvd.org.cn/" + vul_info.css("a")[0].attrib["href"].strip().replace("javascript:void(0)", "")
                    item["patch"] = {"patch_name": patch_name,
                                     "patch_url": patch_url}
            
        yield item
        
    def deal_with_strip(self, thing):
        if thing is not None:
            thing = thing.strip().replace("/n", "").replace("/t", "")
        return thing
    
    def tell_and_strip(self, string):
        if string is not None:
            string = string.strip()
        return string