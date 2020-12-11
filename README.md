# SimpleJavaWaf
> 大白菜

## 1. Introduction
It is a very simple java waf, including a waf for jsp project and a waf for normal web project.

## 2. Install
- JSP WAF

Copy the waf.jsp to the base path of your web application, then run the py script to deploy:
```
python wafJspDeploy.py
```

- Web WAF(Thanks @bluefin)

You have to modify the src package path, then compile the WafFilter.java to a .class file, deploy .class to correct path in the web application, finally, modify the web.xml file like this:
```
<filter>
    <filter-name>WAF</filter-name>
    <filter-class>org.bluefin.filter.WafFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>WAF</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```
