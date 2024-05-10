package fast_grok

import (
	"fmt"
	"testing"
)

var (
	input1  = `10.4.37.96 - - [16/Apr/2024:14:07:11 +0800] "GET /digitalstore/api/broadcast/getDataSubtitles HTTP1.1" 200 196 2.948 "http://10.99.1.106:8766/dashboards/2?datasource=95&ident=dev-backup-01" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" "-" "10.99.1.107:17001"`
	format1 = `%{IPORHOST:remote_addr} - %{DATA:remote_user} \[%{HTTPDATE:time_local}\] "%{WORD:method} %{URIPATH:request} %{DATA:protocol}" %{NUMBER:status} %{NUMBER:body_bytes_sent} %{NUMBER:request_time} "%{DATA:http_referer}" "%{DATA:http_user_agent}" "%{DATA:http_x_forwarded_for}" "%{DATA:upstream_addr}"`
	format2 = `%{IPORHOST:remote_addr333} - %{DATA:d123} \[%{HTTPDATE:d123time_local}\] "%{WORD:method} %{URIPATH:request} %{DATA:protocol}" %{NUMBER:status} %{NUMBER:body_bytes_sent} %{NUMBER:request_time} "%{DATA:http_referer}" "%{DATA:http_user_agent}" "%{DATA:http_x_forwarded_for}" "%{DATA:upstream_addr}"`
)

func TestFastGrok(t *testing.T) {
	g, err := NewBase(format1)
	if err != nil {
		fmt.Println(err)
	}
	resMap, err := g.Parse(input1)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%#v", resMap)

}
