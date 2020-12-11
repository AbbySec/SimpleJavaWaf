package org.bluefin.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

public class WafFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    /**** 自定义函数 *****/
//    String waf_log = "/Users/dabaicai/Documents/tmp/waf_jsp_log.txt";

    /*** 初始化header ***/
    private Map<String, String> getHeadersMap(HttpServletRequest request) {
        Map<String, String> headersMap = new HashMap();
        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            headersMap.put(key, value);
        }
        return headersMap;
    }

    /*** 初始化POST ***/
    private Map<String, String> getParametersMap(HttpServletRequest request) throws Exception {
        Map<String, String> parameterMap = new HashMap();
        Enumeration enu = request.getParameterNames();
        while (enu.hasMoreElements()) {
            String key = (String) enu.nextElement();
            //String value = URLDecoder.decode(request.getParameter(key), "UTF-8");
            // 保持原始的并不做urldecode
            String value = request.getParameter(key);
            parameterMap.put(key, value);
        }
        return parameterMap;
    }

    /***** waf校验 *****/
    private boolean waf(HashMap<String, String> baseInfoMap, Map<String, String> headersMap,
                Map<String, String> parametersMap, String waf_input) throws Exception {
        boolean isPass = true;
        String waf_regex = "exec|class|runtime\\b|file\\b|write|run\\b|runable|read\\b|cmd\\b|console\\b";
        waf_regex += "|getruntime|getparameter|processbuilder|start\\b|command|scanner|forname|getmethod";
        waf_regex += "|method|invoke|process|shell|classloader|getsystemclassloader|loadclass|getclass|eval";
        waf_regex += "|request|pythoninterpreter|processcmd";
        // 危险的SQL指令
        waf_regex += "|select\\b|and\\b|or\\b|insert\\b|update\\b|union|load_file|outfile|dumpfile";
        // 此处单引号可能引发高误判，如果影响check机需去掉
        waf_regex += "|sub\\b|/\\*\\b|\\*/\\b|'\\b|substring|substr|strcmp";
        // 危险的linux指令
        waf_regex += "|\\.\\./|\\./|nc\\b|cat\\b|echo|flag|curl|system|wget";
        Pattern p = Pattern.compile(waf_regex);
        // 判断header
        if (!headersMap.isEmpty()) {
            Iterator<String> headerValuesIt = headersMap.values().iterator();
            while (headerValuesIt.hasNext()) {
                String headerValue = headerValuesIt.next();
                Matcher m = p.matcher(headerValue);
                if (m.find()) {
                    //System.out.println("find:" + headerValue);
                    isPass = false;
                }
            }
        }
        // 判断get/post参数的value
        if (!parametersMap.isEmpty()) {
            Iterator<String> paramValuesIt = parametersMap.values().iterator();
            while (paramValuesIt.hasNext()) {
                //String paramValue = URLDecoder.decode(paramValuesIt.next(), "UTF-8");
                String paramValue = paramValuesIt.next();
                Matcher m = p.matcher(paramValue);
                if (m.find()) {
                    System.out.println("find:" + paramValue);
                    isPass = false;
                } else {
                    //System.out.println("not find:" + paramValue);
                }
            }
        }
        // 判断input部分
        if (waf_input != null && !"".equals(waf_input)) {
            String checkInput = URLDecoder.decode(waf_input, "UTF-8");
            Matcher m = p.matcher(checkInput);
            if (m.find()) {
                //System.out.println("find:" + checkInput);
                isPass = false;
            }
        }
        return isPass;
    }

    /*** 写waf_log ***/
    private void waf_log(String type, HashMap<String, String> baseInfoMap, Map<String, String> headersMap,
                 Map<String, String> parametersMap, String waf_input) throws Exception {
        Calendar calendar = Calendar.getInstance();
        // 获得当前小时数
        int curHoure24 = calendar.get(Calendar.HOUR_OF_DAY);
        // 获得当前时间
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String nowTime = sdf.format(calendar.getTime());
        String property = "java.io.tmpdir";
        String tempDir = System.getProperty(property);
        // log文件路径
        String filepath = tempDir + File.separator +  "waflog_" + curHoure24 + ".txt";
        System.out.println("logfile path:" + filepath);
        /*** 开始拼装请求 ***/
        StringBuffer fileContext = new StringBuffer();
        fileContext.append("------------------------" + type + "------------------------\n");
        fileContext.append("-----[" + nowTime + "] [SRC_IP: " + baseInfoMap.get("waf_remote_addr") + "] -----\n");
        fileContext.append(baseInfoMap.get("waf_method") + " " + baseInfoMap.get("waf_request_uri")
                + " " + baseInfoMap.get("waf_protocol") + "\n");
        // 写header
        for (Map.Entry entry : headersMap.entrySet()) {
            fileContext.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
        }
        // 处理POST请求
        if ("POST".equalsIgnoreCase(baseInfoMap.get("waf_method")) && !parametersMap.isEmpty()) {
            fileContext.append("\n");
            Iterator postParamIt = parametersMap.keySet().iterator();
            while (postParamIt.hasNext()) {
                String postParamKey = (String) postParamIt.next();
                String postParamValue = parametersMap.get(postParamKey);
                if (postParamIt.hasNext()) {
                    fileContext.append(postParamKey).append("=").append(postParamValue).append("&");
                } else {
                    fileContext.append(postParamKey).append("=").append(postParamValue);
                }
            }
        }
        // 写input流部分
        if (waf_input != null && !"".equals(waf_input)) {
            fileContext.append("\n");
            fileContext.append(URLDecoder.decode(waf_input, "UTF-8"));
        }
        // 写文件
        fileContext.append("\n");
        writeFile(filepath, fileContext.toString());
    }

    /***** 追加写文件 *****/
    void writeFile(String filepath, String context) throws Exception {
        File file = new File(filepath);
        FileOutputStream fos = null;
        if (!file.exists()) {
            file.createNewFile();
            fos = new FileOutputStream(file);
        } else {
            // 此处设定true为追加
            fos = new FileOutputStream(file, true);
        }
        OutputStreamWriter osw = new OutputStreamWriter(fos, "UTF-8");
        osw.write(context);
        osw.write("\r\n");
        osw.close();
        fos.close();
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        /*****
         * waf_log处理
         * 1. 无论get还是post，均可以通过getParametersMap来获取参数
         * 2. 如果是get，直接在url后面拼接参数，post则写在下方
         * 3. form-data | text/plain需要通过字节流读取
         *****/
        /***** 基本信息部分 *****/
        try {
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            HashMap<String, String> baseInfoMap = new HashMap();
            // method
            String waf_method = request.getMethod();
            baseInfoMap.put("waf_method", waf_method);
            String waf_remote_addr = request.getRemoteAddr();
            baseInfoMap.put("waf_remote_addr", waf_remote_addr);
            String waf_request_port = String.valueOf(request.getLocalPort());
            baseInfoMap.put("waf_request_port", waf_request_port);
            // 仅包含后半部分，不包含ip、端口
            String waf_request_uri = request.getRequestURI();
            // 增加queryString参数
            String waf_queryString = request.getQueryString();
            // 如果是get，把参数添加到url
            if ("GET".equalsIgnoreCase(waf_method) && waf_queryString != null && !"".equals(waf_queryString)) {
                waf_request_uri += "?" + waf_queryString;
            }
            baseInfoMap.put("waf_request_uri", waf_request_uri);
            // 协议
            String waf_protocol = request.getProtocol();
            baseInfoMap.put("waf_protocol", waf_protocol);
            // 完整请求url
            StringBuffer waf_request_url = request.getRequestURL();
            baseInfoMap.put("waf_request_url", waf_request_url.toString());
            /***** header *****/
            Map<String, String> headersMap = getHeadersMap(request);
            /***** POST - 需要先处理post数据 *****/
            Map<String, String> parametersMap = getParametersMap(request);
            /***** 处理form-data(适用于content-type = multipart/form-data | text/plain) *****/
            //if (headersMap.get("content-type").toString().indexOf("form-data") >= 0) {}
            // 如果是form-data，需要通过reader读取
            BufferedReader reader = request.getReader();
            String line = null;
            StringBuffer waf_input = new StringBuffer();
            while ((line = reader.readLine()) != null) {
                waf_input.append(line);
            }
            // 写日志
            boolean isPass = waf(baseInfoMap, headersMap, parametersMap, waf_input.toString());
            if (isPass) {
                waf_log("[pass]", baseInfoMap, headersMap, parametersMap, waf_input.toString());
            } else {
                waf_log("[filter]", baseInfoMap, headersMap, parametersMap, waf_input.toString());
                // 写入虚假的flag
                servletResponse.getWriter().write("flag{efe85e2b213fb5908c3e321da9f49ff9}");
                return;
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}
