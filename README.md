# cve_cpe 数据爬虫（来自NVD和CNNVD数据库）

**依赖Scrapy 2.3.0的爬虫**

## 项目结构

```markdown
>.
├── Pipfile 
├── Pipfile.lock
├── README.md
├── cnnvdRun.py **cnnvd定时爬取脚本**
├── run.py **NVD cve定时爬取脚本**
├── >cve_cpe **主目录**
│   ├── cve_cpe **scrapy项目目录**
│   │   ├── __init__.py
│   │   ├── items.py **爬虫数据item配置**
│   │   ├── middlewares.py **数据流中间层配置**
│   │   ├── pipelines.py **数据管道（清理，去重，更新）配置**
│   │   ├── settings.py **scrapy基本配置（项目组件启用和配置）**
│   │   └── spiders **爬虫目录**
│   │       ├── __init__.py
│   │       └── spider_cve.py **爬虫**
│   └── scrapy.cfg **scrapy配置文件**
└──
```



## 本地测试

#### nvd数据爬取的本地测试

1. 进入spiders目录

```sh
scrapy crawl spider_cve -o test.json
# 导出为json文件
```

#### cnnvd数据爬取的本地测试

1. 进入cve目录

```sh
mkdir cvestatic/cnnvd
scrapy crawl cnnvd 						#注意这里要启用pipeline（详细参考关于部署章节）
```



## 关于部署

1. ***setting***文件的配置

   ```python
   RETRY_ENABLED = True                  # 开启失败重试，我们的爬虫默认开启
   RETRY_TIMES = 6                       # 失败后重试次数，默认两次，这里经过对nvd的测试发现6次重试稳定可以拿到全部数据（网络正常）
   RETRY_HTTP_CODES = [500, 502, 503, 504, 522, 524, 408, 403, 429, 404]    # 碰到这些返回值，才开启重试操作
   
   ITEM_PIPELINES = {
       'cve_cpe.pipelines.UpdatePipeline': 300,				# 启用nvd数据爬取的pipeline，默认管道容量 300 items
   }															# 注意在 **本地测试** 中需要将pipeline注释掉来关闭管道
   ITEM_PIPELINES = {
      'cve_cpe.pipelines.cnnvdPipeline': 300,					# 启用cnnvd数据爬取的pipeline，默认管道容量300 items
}														  	# 注意在 **本地测试** 中要启用pipeline
   ```
   

2. 启动爬虫并定时更新

   ```sh
   nohup pipenv run python run.py &   				#启用NVD数据爬虫并放在后台定时执行更新git仓库（关于定时的时间设定参考wiki）
   nohup pipenv run python cnnvdRun.py & 			#启用CNNVD数据爬虫并放在后台定期执行更新git仓库
   ```

   