package core

import (
	"crypto/sha1"
	"fmt"
	"github.com/fatih/color"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"net/url"
	"os"
	"path"
	"strings"
)

// PassiveAnalyze do passive analyzer based on default passive signature
func PassiveAnalyze(options libs.Options, record libs.Record) {
	if !utils.FolderExists(options.PassiveFolder) {
		return
	}
	passives := GetPassives(options)
	if len(passives) <= 0 {
		return
	}
	for _, passive := range passives {
		// filter by level
		if passive.Level > options.Level {
			continue
		}

		for _, rule := range passive.Rules {
			if len(rule.Detections) <= 0 {
				continue
			}
			// select passive
			if options.SelectedPassive != "*" {
				passiveName := strings.ToLower(fmt.Sprintf("%v-%v", passive.Name, rule.ID))
				if !strings.Contains(passiveName, options.SelectedPassive) {
					continue
				}
			}
			runPassive(options, record, rule)
		}
	}
}

func runPassive(options libs.Options, record libs.Record, rule libs.Rule) {
	for _, detectionString := range rule.Detections {
		utils.DebugF("[Passive] %v", rule.Reason)
		extra, result := RunDetector(record, detectionString)
		if extra != "" {
			record.ExtraOutput = extra
		}
		if result == true {
			var outputName string
			if options.NoOutput == false {
				outputName = StorePassiveOutput(record, rule, detectionString, options)
				record.RawOutput = outputName
			}
			color.Yellow("[Passive] %v %v", record.Request.URL, outputName)
		}
	}
}

// GetPassives get all passives rule
func GetPassives(options libs.Options) []libs.Passive {
	var passives []libs.Passive
	passives = append(passives, defaultPassive())
	passiveFiles := utils.GetFileNames(utils.NormalizePath(options.PassiveFolder), "yaml")
	for _, passiveFile := range passiveFiles {
		passive, err := ParsePassive(passiveFile)
		if err == nil {
			passives = append(passives, passive)
		}
	}
	return passives
}

// StorePassiveOutput store passive output found
func StorePassiveOutput(record libs.Record, rule libs.Rule, detectionString string, options libs.Options) string {
	head := fmt.Sprintf("[%v|%v] - %v\n\n", rule.ID, strings.Replace(rule.Reason, " ", "_", -1), record.Request.URL)
	content := fmt.Sprintf("[%v] - %v\n\n", rule.ID, record.Request.URL)
	content += fmt.Sprintf("[%v] - %v\n\n", rule.Reason, detectionString)
	// print out matches string
	if record.ExtraOutput != "" {
		content += fmt.Sprintf("%v\n", strings.Repeat("-", 50))
		content += fmt.Sprintf("[Matches String]\n")
		content += strings.TrimSpace(record.ExtraOutput)
		content += fmt.Sprintf("\n%v\n", strings.Repeat("-", 50))
	}

	if record.Request.MiddlewareOutput != "" {
		content += strings.Join(record.Request.Middlewares, "\n")
		content += record.Request.MiddlewareOutput
		content += fmt.Sprintf("\n%v\n", strings.Repeat("-", 50))
	}
	content += record.Request.Beautify
	content += fmt.Sprintf("\n%v\n", strings.Repeat("-", 50))
	content += record.Response.Beautify

	// hash the content
	h := sha1.New()
	h.Write([]byte(content))
	checksum := h.Sum(nil)
	parts := []string{options.PassiveOutput}
	if record.Request.URL == "" {
		parts = append(parts, record.Request.Target["Domain"])
	} else {
		u, _ := url.Parse(record.Request.URL)
		parts = append(parts, u.Hostname())
	}
	parts = append(parts, fmt.Sprintf("%v-%x", utils.StripName(rule.ID), checksum))
	p := path.Join(parts...)
	if _, err := os.Stat(path.Dir(p)); os.IsNotExist(err) {
		err = os.MkdirAll(path.Dir(p), 0750)
		if err != nil {
			utils.ErrorF("Error Write content to: %v", p)
		}
	}
	utils.WriteToFile(p, content)
	sum := fmt.Sprintf("%v - %v", strings.TrimSpace(head), p)
	utils.AppendToContent(options.PassiveSummary, sum)
	return p
}

// default rule
func defaultPassive() libs.Passive {
	rules := []libs.Rule{
		libs.Rule{
			ID:     "default-error-01",
			Reason: "SQL Error",
			Detections: []string{
				`RegexSearch("resbody", "(Exception (condition )?\\d+\\. Transaction rollback|com\\.frontbase\\.jdbc|org\\.h2\\.jdbc|Unexpected end of command in statement \\[\"|Unexpected token.*?in statement \\[|org\\.hsqldb\\.jdbc|CLI Driver.*?DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE|com\\.ibm\\.db2\\.jcc|Zend_Db_(Adapter|Statement)_Db2_Exception|Pdo[./_\\\\]Ibm|DB2Exception|Warning.*?\\Wifx_|Exception.*?Informix|Informix ODBC Driver|ODBC Informix driver|com\\.informix\\.jdbc|weblogic\\.jdbc\\.informix|Pdo[./_\\\\]Informix|IfxException|Warning.*?\\Wingres_|Ingres SQLSTATE|Ingres\\W.*?Driver|com\\.ingres\\.gcf\\.jdbc|Dynamic SQL Error|Warning.*?\\Wibase_|org\\.firebirdsql\\.jdbc|Pdo[./_\\\\]Firebird|Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access|Syntax error \\(missing operator\\) in query expression|Driver.*? SQL[\\-\\_\\ ]*Server|OLE DB.*? SQL Server|\\bSQL Server[^&lt;&quot;]+Driver|Warning.*?\\W(mssql|sqlsrv)_|\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}|System\\.Data\\.SqlClient\\.SqlException|(?s)Exception.*?\\bRoadhouse\\.Cms\\.|Microsoft SQL Native Client error '[0-9a-fA-F]{8}|\\[SQL Server\\]|ODBC SQL Server Driver|ODBC Driver \\d+ for SQL Server|SQLServer JDBC Driver|com\\.jnetdirect\\.jsql|macromedia\\.jdbc\\.sqlserver|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|com\\.microsoft\\.sqlserver\\.jdbc|Pdo[./_\\\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception|SQL syntax.*?MySQL|Warning.*?\\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|Unknown column '[^ ]+' in 'field list'|MySqlClient\\.|com\\.mysql\\.jdbc|Zend_Db_(Adapter|Statement)_Mysqli_Exception|Pdo[./_\\\\]Mysql|MySqlException|\\bORA-\\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\\W(oci|ora)_|quoted string not properly terminated|SQL command not properly ended|macromedia\\.jdbc\\.oracle|oracle\\.jdbc|Zend_Db_(Adapter|Statement)_Oracle_Exception|Pdo[./_\\\\](Oracle|OCI)|OracleException|PostgreSQL.*?ERROR|Warning.*?\\Wpg_|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near|ERROR: parser: parse error at or near|PostgreSQL query failed|org\\.postgresql\\.jdbc|Pdo[./_\\\\]Pgsql|PSQLException|SQL error.*?POS([0-9]+)|Warning.*?\\Wmaxdb_|DriverSapDB|com\\.sap\\.dbtech\\.jdbc|SQLite/JDBCDriver|SQLite\\.Exception|(Microsoft|System)\\.Data\\.SQLite\\.SQLiteException|Warning.*?\\W(sqlite_|SQLite3::)|\\[SQLITE_ERROR\\]|SQLite error \\d+:|sqlite3.OperationalError:|SQLite3::SQLException|org\\.sqlite\\.JDBC|Pdo[./_\\\\]Sqlite|SQLiteException|Warning.*?\\Wsybase_|Sybase message|Sybase.*?Server message|SybSQLException|Sybase\\.Data\\.AseClient|com\\.sybase\\.jdbc)")`,
			}},
		libs.Rule{
			ID:     "default-error-02",
			Reason: "General Error",
			Detections: []string{
				`RegexSearch("resbody", "injectx|stack smashing detected|Backtrace|Memory map|500 Internal Server Error|Set-Cookie:\\scrlf=injection|java\\.io\\.FileNotFoundException|java\\.lang\\.Exception|java\\.lang\\.IllegalArgumentException|java\\.net\\.MalformedURLException|Warning: include\\(|Warning: unlink\\(|for inclusion \\(include_path=|fread\\(|Failed opening required|Warning: file_get_contents\\(|Fatal error: require_once\\(|Warning: file_exists\\(|root:|(uid|gid|groups)=\\d+|bytes from \\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b|Configuration File \\(php\\.ini\\) Path |vulnerable 10|Trying \\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b|\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b\\s+localhost|BROADCAST,MULTICAST|drwxr-xr|Active Internet connections|Syntax error|sh:|Average Speed   Time|dir: cannot access|<script>alert\\(1\\)</script>|drwxrwxr|GNU/Linux|(Exception (condition )?\\d+\\. Transaction rollback|com\\.frontbase\\.jdbc|org\\.h2\\.jdbc|Unexpected end of command in statement \\[\"|Unexpected token.*?in statement \\[|org\\.hsqldb\\.jdbc|CLI Driver.*?DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE|com\\.ibm\\.db2\\.jcc|Zend_Db_(Adapter|Statement)_Db2_Exception|Pdo[./_\\\\]Ibm|DB2Exception|Warning.*?\\Wifx_|Exception.*?Informix|Informix ODBC Driver|ODBC Informix driver|com\\.informix\\.jdbc|weblogic\\.jdbc\\.informix|Pdo[./_\\\\]Informix|IfxException|Warning.*?\\Wingres_|Ingres SQLSTATE|Ingres\\W.*?Driver|com\\.ingres\\.gcf\\.jdbc|Dynamic SQL Error|Warning.*?\\Wibase_|org\\.firebirdsql\\.jdbc|Pdo[./_\\\\]Firebird|Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access|Syntax error \\(missing operator\\) in query expression|Driver.*? SQL[\\-\\_\\ ]*Server|OLE DB.*? SQL Server|\\bSQL Server[^&lt;&quot;]+Driver|Warning.*?\\W(mssql|sqlsrv)_|\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}|System\\.Data\\.SqlClient\\.SqlException|(?s)Exception.*?\\bRoadhouse\\.Cms\\.|Microsoft SQL Native Client error '[0-9a-fA-F]{8}|\\[SQL Server\\]|ODBC SQL Server Driver|ODBC Driver \\d+ for SQL Server|SQLServer JDBC Driver|com\\.jnetdirect\\.jsql|macromedia\\.jdbc\\.sqlserver|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|com\\.microsoft\\.sqlserver\\.jdbc|Pdo[./_\\\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception|SQL syntax.*?MySQL|Warning.*?\\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|Unknown column '[^ ]+' in 'field list'|MySqlClient\\.|com\\.mysql\\.jdbc|Zend_Db_(Adapter|Statement)_Mysqli_Exception|Pdo[./_\\\\]Mysql|MySqlException|\\bORA-\\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\\W(oci|ora)_|quoted string not properly terminated|SQL command not properly ended|macromedia\\.jdbc\\.oracle|oracle\\.jdbc|Zend_Db_(Adapter|Statement)_Oracle_Exception|Pdo[./_\\\\](Oracle|OCI)|OracleException|PostgreSQL.*?ERROR|Warning.*?\\Wpg_|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near|ERROR: parser: parse error at or near|PostgreSQL query failed|org\\.postgresql\\.jdbc|Pdo[./_\\\\]Pgsql|PSQLException|SQL error.*?POS([0-9]+)|Warning.*?\\Wmaxdb_|DriverSapDB|com\\.sap\\.dbtech\\.jdbc|SQLite/JDBCDriver|SQLite\\.Exception|(Microsoft|System)\\.Data\\.SQLite\\.SQLiteException|Warning.*?\\W(sqlite_|SQLite3::)|\\[SQLITE_ERROR\\]|SQLite error \\d+:|sqlite3.OperationalError:|SQLite3::SQLException|org\\.sqlite\\.JDBC|Pdo[./_\\\\]Sqlite|SQLiteException|Warning.*?\\Wsybase_|Sybase message|Sybase.*?Server message|SybSQLException|Sybase\\.Data\\.AseClient|com\\.sybase\\.jdbc)|System\\.Xml\\.XPath\\.XPathException|MS\\.Internal\\.Xml|Unknown error in XPath|org\\.apache\\.xpath\\.XPath|A closing bracket expected in|An operand in Union Expression does not produce a node-set|Cannot convert expression to a number|Document Axis does not allow any context Location Steps|Empty Path Expression|DOMXPath|Empty Relative Location Path|Empty Union Expression|Expected \\'\\)\\' in|Expected node test or name specification after axis operator|Incompatible XPath key|Incorrect Variable Binding|libxml2 library function failed|libxml2|Invalid predicate|Invalid expression|xmlsec library function|xmlsec|error \\'80004005\\'|A document must contain exactly one root element|<font face=\"Arial\" size=2>Expression must evaluate to a node-set|Expected token ']'|<p>msxml4\\.dll<\\/font>|<p>msxml3\\.dll<\\/font>|4005 Notes error: Query is not understandable|SimpleXMLElement::xpath|xmlXPathEval:|simplexml_load_string|parser error :|An error occured!|xmlParseEntityDecl|simplexml_load_string|xmlParseInternalSubset|DOCTYPE improperly terminated|Start tag expected|No declaration for attribute|No declaration for element|failed to load external entity|Start tag expected|Invalid URI: file:\\/\\/\\/|Malformed declaration expecting version|Unicode strings with encoding|must be well-formed|Content is not allowed in prolog|org.xml.sax|SAXParseException|com.sun.org.apache.xerces|ParseError|nokogiri|REXML|XML syntax error on line|Error unmarshaling XML|conflicts with field|illegal character code|XML Parsing Error|SyntaxError|no root element|not well-formed\n")`},
		},
		//////
		libs.Rule{
			ID:     "default-error-03",
			Reason: "PHP Error",
			Detections: []string{
				`RegexSearch("resbody", "Warning: include\(|Warning: unlink\(|for inclusion \(include_path=|fread\(|Failed opening required|Warning: file_get_contents\(|Fatal error: require_once\(|Warning: file_exists\(")`},
		},

		libs.Rule{
			ID:     "default-error-04",
			Reason: "Java Error",
			Detections: []string{
				`RegexSearch("resbody", "java\.io\.FileNotFoundException|java\.lang\.Exception|java\.lang\.IllegalArgumentException|java\.net\.MalformedURLException"`},
		},

		libs.Rule{
			ID:     "default-error-05",
			Reason: "XML Error",
			Detections: []string{
				`RegexSearch("resbody", "simplexml_load_string|parser error :|An error occured!|xmlParseEntityDecl|simplexml_load_string|xmlParseInternalSubset|DOCTYPE improperly terminated|Start tag expected|No declaration for attribute|No declaration for element|failed to load external entity|Start tag expected|Invalid URI: file:\/\/\/|Malformed declaration expecting version|Unicode strings with encoding|must be well-formed|Content is not allowed in prolog|org.xml.sax|SAXParseException|com.sun.org.apache.xerces|ParseError|nokogiri|REXML|XML syntax error on line|Error unmarshaling XML|conflicts with field|illegal character code|XML Parsing Error|SyntaxError|no root element|not well-formed"`},
		},

		libs.Rule{
			ID:     "default-error-06",
			Reason: "RCE Error",
			Detections: []string{
				`RegexSearch("resbody", "root:|(uid|gid|groups)=\d+|bytes from \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|Configuration File \(php\.ini\) Path |vulnerable 10|Trying \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b\s+localhost|BROADCAST,MULTICAST|drwxr-xr|Active Internet connections|Syntax error|sh:|Average Speed   Time|dir: cannot access|<script>alert\(1\)</script>|drwxrwxr|GNU/Linux"`},
		},

		//libs.Rule{
		//	ID:     "default-error-02",
		//	Reason: "General Error",
		//	Detections: []string{
		//		`RegexSearch("response", "regexhere"`},
		//},

	}
	return libs.Passive{
		Name:  "Default",
		Desc:  "Default Rule for catching common Error",
		Rules: rules,
	}
}
