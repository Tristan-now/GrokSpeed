package fast_grok

import (
	"errors"
	"fmt"
	"github.com/fstab/grok_exporter/exporter"
	"github.com/fstab/grok_exporter/oniguruma"
	"regexp"
	"strings"
)

type Patterns map[string]string

type Grok struct {
	parser   *oniguruma.Regex
	Patterns *Patterns
	labels   []string
	Format   string `json:"format"`
}

func New(format string) (*Grok, error) {
	pattern := Patterns(make(map[string]string))
	return &Grok{Patterns: &pattern}, nil
}

func (g *Grok) AddPattern(pattern string) error {
	r := regexp.MustCompile(`([A-z0-9]+)\s+(.+)`)
	match := r.FindStringSubmatch(pattern)
	if match == nil {
		return fmt.Errorf("'%v' is not a valid pattern definition.", pattern)
	}
	(*g.Patterns)[match[1]] = match[2]
	return nil
}

func NewBase(format string) (*Grok, error) {
	patterns, err := BasePatters()
	if err != nil {
		return nil, err
	}
	regex, err := exporter.Compile(format, patterns)
	if err != nil {
		return nil, err
	}
	labels := GetLabels(format)
	return &Grok{
		parser: regex,
		labels: labels,
		Format: format,
	}, nil
}

func (p *Grok) Parse(origin string) (map[string]interface{}, error) {
	if p.parser == nil || len(origin) == 0 {
		return nil,
			errors.New("invalid input format")
	}
	resMap := make(map[string]interface{})

	searchResult, err := p.parser.Search(origin)
	if err != nil {
		return nil, err
	}

	if !searchResult.IsMatch() {
		return nil, errors.New("searchResult match failed")
	}

	for _, field := range p.labels {
		value, err := searchResult.GetCaptureGroupByName(field)
		if err != nil {
			return nil, err
		}
		resMap[field] = value
	}
	return resMap, nil
}

// AddPattern,Compile,

func GetLabels(logLine string) []string {
	pattern := `%\{[^:]+:(\w+)}`
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(logLine, -1)

	var variables []string
	for _, match := range matches {
		if len(match) > 1 { // 确保至少有一个子匹配
			variables = append(variables, match[1])
		}
	}

	return variables
}

func BasePatters() (*exporter.Patterns, error) {
	p := exporter.InitPatterns()
	if len(*p) != 0 {
		return nil, errors.New("patterns nil")
	}
	for _, pattern := range strings.Split(initPattern, "\n") {
		p.AddPattern(pattern)
	}
	return p, nil
}

var (
	initPattern = `
USERNAME [a-zA-Z0-9_-]+
USER %{USERNAME}
INT (?:[+-]?(?:[0-9]+))
BASE10NUM (?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))
NUMBER (?:%{BASE10NUM})
BASE16NUM (?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))
BASE16FLOAT \b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b
POSINT \b(?:[1-9][0-9]*)\b
NONNEGINT \b(?:[0-9]+)\b
WORD \b\w+\b
NOTSPACE \S+
SPACE \s*
DATA .*?
GREEDYDATA .*
UUID [A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}
MAC (?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})
CISCOMAC (?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})
WINDOWSMAC (?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})
COMMONMAC (?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})
IP (?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])
HOSTNAME \b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)
HOST %{HOSTNAME}
IPORHOST (?:%{HOSTNAME}|%{IP})
HOSTPORT (?:%{IPORHOST=~/\./}:%{POSINT})
PATH (?:%{UNIXPATH}|%{WINPATH})
UNIXPATH (?>/(?>[\w_%!$@:.,-]+|\\.)*)+
#UNIXPATH (?<![\w\/])(?:/[^\/\s?*]*)+
LINUXTTY (?>/dev/pts/%{NONNEGINT})
BSDTTY (?>/dev/tty[pq][a-z0-9])
TTY (?:%{BSDTTY}|%{LINUXTTY})
WINPATH (?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+
URIPROTO [A-Za-z]+(\+[A-Za-z+]+)?
URIHOST %{IPORHOST}(?::%{POSINT:port})?
URIPATH (?:/[A-Za-z0-9$.+!*'(){},~:;=#%_\-]*)+
URIPARAM \?[A-Za-z0-9$.+!*'|(){},~#%&/=:;_?\-\[\]]*
URIPATHPARAM %{URIPATH}(?:%{URIPARAM})?
URI %{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?
MONTH \b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b
MONTHNUM (?:0?[1-9]|1[0-2])
MONTHDAY (?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])
DAY (?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)
YEAR (?>\d\d){1,2}
HOUR (?:2[0123]|[01][0-9])
MINUTE (?:[0-5][0-9])
SECOND (?:(?:[0-5][0-9]|60)(?:[.,][0-9]+)?)
TIME (?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])
DATE_US %{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}
DATE_EU %{YEAR}[./-]%{MONTHNUM}[./-]%{MONTHDAY}
ISO8601_TIMEZONE (?:Z|[+-]%{HOUR}(?::?%{MINUTE}))
ISO8601_SECOND (?:%{SECOND}|60)
TIMESTAMP_ISO8601 %{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?
DATE %{DATE_US}|%{DATE_EU}
DATESTAMP %{DATE}[- ]%{TIME}
TZ (?:[PMCE][SD]T)
DATESTAMP_RFC822 %{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}
DATESTAMP_OTHER %{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}
SYSLOGTIMESTAMP %{MONTH} +%{MONTHDAY} %{TIME}
PROG (?:[\w._/%-]+)
SYSLOGPROG %{PROG:program}(?:\[%{POSINT:pid}\])?
SYSLOGHOST %{IPORHOST}
SYSLOGFACILITY <%{NONNEGINT:facility}.%{NONNEGINT:priority}>
HTTPDATE %{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}
QS %{QUOTEDSTRING}
SYSLOGBASE %{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:
COMBINEDAPACHELOG %{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|-)" %{NUMBER:response} (?:%{NUMBER:bytes}|-) %{QS:referrer} %{QS:agent}
LOGLEVEL ([T|t]race|TRACE|[D|d]ebug|DEBUG|[N|n]otice|NOTICE|[I|i]nfo|INFO|[W|w]arn?(?:ing)?|WARN?(?:ING)?|[E|e]rr?(?:or)?|ERR?(?:OR)?|[C|c]rit?(?:ical)?|CRIT?(?:ICAL)?|[F|f]atal|FATAL|[S|s]evere|SEVERE)
`
)
