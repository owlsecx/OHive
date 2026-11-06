// ============================================================
//
//	OHive — Windows Registry Hive Parser
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only) — OWL suite
//
// ============================================================
package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const APPNAME = "OHive"
const SUITE = "Owl Forensics Suite"
const TAGLINE = "Windows Registry Hive Parser"
const SUBLINE = "regf cells · nk/vk/lf/lh/li/ri · key tree · value decode · ATT&CK persistence"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const BANNER = `
 ██████╗ ██╗  ██╗██╗██╗   ██╗███████╗
██╔═══██╗██║  ██║██║██║   ██║██╔════╝
██║   ██║███████║██║██║   ██║█████╗
██║   ██║██╔══██║██║╚██╗ ██╔╝██╔══╝
╚██████╔╝██║  ██║██║ ╚████╔╝ ███████╗
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and CRITICAL/HIGH.
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	DR  = CY // legacy alias (was dark-red frame) → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
func menu(title string, items [][2]string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
			col(pad(it[0], 20), W) + col("─ "+it[1], DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 20), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 20), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ---- Common finding / report types ----
type Finding struct {
	ID          string            `json:"id"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence"`
	Mitre       []string          `json:"mitre_attack"`
	Category    string            `json:"category"`
	Score       float64           `json:"score"`
	Tags        []string          `json:"tags"`
	Location    string            `json:"location"`
	Timestamp   string            `json:"timestamp"`
	Extra       map[string]string `json:"extra,omitempty"`
}

type Report struct {
	Tool        string            `json:"tool"`
	Version     string            `json:"version"`
	GeneratedAt string            `json:"generated_at"`
	Subject     string            `json:"subject"`
	Grade       string            `json:"grade"`
	Score       float64           `json:"score"`
	Summary     string            `json:"summary"`
	Findings    []Finding         `json:"findings"`
	Stats       map[string]int    `json:"stats"`
	Meta        map[string]string `json:"meta"`
}

const VERSION = "1.0"

func newReport(subject string) *Report {
	return &Report{
		Tool: APPNAME, Version: VERSION,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Subject:     subject, Grade: "N/A", Score: 0,
		Findings: []Finding{}, Stats: map[string]int{}, Meta: map[string]string{},
	}
}

func (r *Report) add(f Finding) {
	if f.ID == "" {
		f.ID = fmt.Sprintf("F-%04d", len(r.Findings)+1)
	}
	if f.Timestamp == "" {
		f.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if f.Extra == nil {
		f.Extra = map[string]string{}
	}
	r.Findings = append(r.Findings, f)
	r.Stats[f.Severity]++
	r.Stats["total"]++
}

func gradeFromScore(score float64) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 67:
		return "D+"
	case score >= 63:
		return "D"
	case score >= 60:
		return "D-"
	default:
		return "F"
	}
}

func severityWeight(s string) float64 {
	switch strings.ToLower(s) {
	case "critical":
		return 25
	case "high":
		return 15
	case "medium":
		return 8
	case "low":
		return 3
	case "info":
		return 0.5
	default:
		return 1
	}
}

func (r *Report) finalize() {
	penalty := 0.0
	for _, f := range r.Findings {
		penalty += severityWeight(f.Severity)
	}
	score := 100.0 - penalty
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	r.Score = score
	r.Grade = gradeFromScore(score)
	r.Summary = fmt.Sprintf("%d findings · grade %s (%.1f/100)", len(r.Findings), r.Grade, r.Score)
}

func exportTXT(r *Report) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== %s v%s Report ===\n", r.Tool, r.Version))
	b.WriteString(fmt.Sprintf("Generated : %s\n", r.GeneratedAt))
	b.WriteString(fmt.Sprintf("Subject   : %s\n", r.Subject))
	b.WriteString(fmt.Sprintf("Grade     : %s (%.1f)\n", r.Grade, r.Score))
	b.WriteString(fmt.Sprintf("Summary   : %s\n", r.Summary))
	b.WriteString(strings.Repeat("=", 64) + "\n\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%s] %s — %s\n", f.Severity, f.ID, f.Title))
		b.WriteString(fmt.Sprintf("  Category : %s\n", f.Category))
		b.WriteString(fmt.Sprintf("  Location : %s\n", f.Location))
		b.WriteString(fmt.Sprintf("  Evidence : %s\n", f.Evidence))
		b.WriteString(fmt.Sprintf("  Detail   : %s\n", f.Description))
		if len(f.Mitre) > 0 {
			b.WriteString(fmt.Sprintf("  MITRE    : %s\n", strings.Join(f.Mitre, ", ")))
		}
		if len(f.Tags) > 0 {
			b.WriteString(fmt.Sprintf("  Tags     : %s\n", strings.Join(f.Tags, ", ")))
		}
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf("\nStats: %v\n", r.Stats))
	return b.String()
}

func exportMD(r *Report) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s Report\n\n", r.Tool))
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| Version | %s |\n", r.Version))
	b.WriteString(fmt.Sprintf("| Generated | %s |\n", r.GeneratedAt))
	b.WriteString(fmt.Sprintf("| Subject | `%s` |\n", r.Subject))
	b.WriteString(fmt.Sprintf("| Grade | **%s** (%.1f) |\n", r.Grade, r.Score))
	b.WriteString(fmt.Sprintf("| Summary | %s |\n\n", r.Summary))
	b.WriteString("## Findings\n\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("### %s — %s (%s)\n\n", f.ID, f.Title, f.Severity))
		b.WriteString(fmt.Sprintf("- **Category:** %s\n", f.Category))
		b.WriteString(fmt.Sprintf("- **Location:** `%s`\n", f.Location))
		b.WriteString(fmt.Sprintf("- **Evidence:** %s\n", f.Evidence))
		b.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
		if len(f.Mitre) > 0 {
			b.WriteString(fmt.Sprintf("- **MITRE ATT&CK:** %s\n", strings.Join(f.Mitre, ", ")))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportJSON(r *Report) string {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(data)
}

func exportCSV(r *Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"id", "severity", "title", "category", "location", "evidence", "mitre", "score", "tags"})
	for _, f := range r.Findings {
		_ = w.Write([]string{f.ID, f.Severity, f.Title, f.Category, f.Location, f.Evidence,
			strings.Join(f.Mitre, ";"), fmt.Sprintf("%.2f", f.Score), strings.Join(f.Tags, ";")})
	}
	w.Flush()
	return buf.String()
}

func exportSARIF(r *Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type artLoc struct {
		URI string `json:"uri"`
	}
	type physLoc struct {
		ArtifactLocation artLoc `json:"artifactLocation"`
	}
	type sarifLoc struct {
		PhysicalLocation physLoc `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string                 `json:"ruleId"`
		Level      string                 `json:"level"`
		Message    sarifMsg               `json:"message"`
		Locations  []sarifLoc             `json:"locations"`
		Properties map[string]interface{} `json:"properties,omitempty"`
	}
	type sarifRule struct {
		ID               string                 `json:"id"`
		Name             string                 `json:"name"`
		ShortDescription sarifMsg               `json:"shortDescription"`
		FullDescription  sarifMsg               `json:"fullDescription"`
		HelpURI          string                 `json:"helpUri,omitempty"`
		Properties       map[string]interface{} `json:"properties,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	levelMap := map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
	rules := []sarifRule{}
	results := []sarifResult{}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		rid := f.Category
		if rid == "" {
			rid = "generic"
		}
		if !seen[rid] {
			seen[rid] = true
			rules = append(rules, sarifRule{
				ID: rid, Name: rid,
				ShortDescription: sarifMsg{Text: rid},
				FullDescription:  sarifMsg{Text: f.Description},
				HelpURI:          "https://owlsec.org",
				Properties:       map[string]interface{}{"tags": f.Mitre},
			})
		}
		uri := f.Location
		if uri == "" {
			uri = r.Subject
		}
		lvl := levelMap[strings.ToLower(f.Severity)]
		if lvl == "" {
			lvl = "warning"
		}
		results = append(results, sarifResult{
			RuleID: rid, Level: lvl,
			Message:   sarifMsg{Text: fmt.Sprintf("%s: %s", f.Title, f.Evidence)},
			Locations: []sarifLoc{{PhysicalLocation: physLoc{ArtifactLocation: artLoc{URI: uri}}}},
			Properties: map[string]interface{}{
				"mitre": f.Mitre, "grade_score": f.Score, "tags": f.Tags,
			},
		})
	}
	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: APPNAME, Version: VERSION, InformationURI: "https://owlsec.org", Rules: rules,
			}},
			Results: results,
		}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(data)
}

func exportReport(r *Report, format, outPath string) error {
	r.finalize()
	var body string
	switch strings.ToLower(format) {
	case "txt", "text":
		body = exportTXT(r)
	case "md", "markdown":
		body = exportMD(r)
	case "json":
		body = exportJSON(r)
	case "csv":
		body = exportCSV(r)
	case "sarif":
		body = exportSARIF(r)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	if outPath == "" || outPath == "-" {
		fmt.Print(body)
		return nil
	}
	return os.WriteFile(outPath, []byte(body), 0644)
}

func printReportSummary(r *Report) {
	r.finalize()
	okMsg(fmt.Sprintf("Grade %s (%.1f/100) — %d findings", r.Grade, r.Score, len(r.Findings)))
	rows := [][]string{}
	for _, f := range r.Findings {
		mitre := ""
		if len(f.Mitre) > 0 {
			mitre = f.Mitre[0]
		}
		rows = append(rows, []string{f.ID, f.Severity, truncate(f.Title, 40), mitre})
		if len(rows) >= 25 {
			break
		}
	}
	if len(rows) > 0 {
		table([]string{"ID", "Sev", "Title", "MITRE"}, rows)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func sha1hex(b []byte) string {
	h := sha1.Sum(b)
	return hex.EncodeToString(h[:])
}
func md5hex(b []byte) string {
	h := md5.Sum(b)
	return hex.EncodeToString(h[:])
}

func entropyOf(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]float64
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	ent := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func readFileLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if max <= 0 {
		max = 64 << 20
	}
	return io.ReadAll(io.LimitReader(f, max))
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func mustAtoi(s string, def int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100.0 * float64(n) / float64(d)
}

func nowStamp() string { return time.Now().Format("20060102-150405") }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func u16le(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off:])
}
func u32le(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}
func u64le(b []byte, off int) uint64 {
	if off+8 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[off:])
}
func i64le(b []byte, off int) int64 {
	return int64(u64le(b, off))
}

func utf16leToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(u); i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// decode until null
	n := 0
	for n < len(u) && u[n] != 0 {
		n++
	}
	runes := make([]rune, 0, n)
	for i := 0; i < n; {
		r := rune(u[i])
		if r >= 0xD800 && r <= 0xDBFF && i+1 < n {
			r2 := rune(u[i+1])
			if r2 >= 0xDC00 && r2 <= 0xDFFF {
				r = 0x10000 + ((r - 0xD800) << 10) + (r2 - 0xDC00)
				i += 2
				runes = append(runes, r)
				continue
			}
		}
		runes = append(runes, r)
		i++
	}
	return string(runes)
}

func filetimeToTime(ft uint64) time.Time {
	// Windows FILETIME: 100-ns intervals since 1601-01-01
	if ft == 0 {
		return time.Time{}
	}
	unix := int64(ft/10) - 11644473600000000
	return time.Unix(0, unix*1000).UTC()
}

func writeUsageHeader(w io.Writer, extra string) {
	fmt.Fprintf(w, "%s — %s\n", APPNAME, TAGLINE)
	fmt.Fprintf(w, "Author: khaled.s.haddad  |  https://owlsec.org  |  v%s\n\n", VERSION)
	fmt.Fprintf(w, "USAGE:\n  %s [options]\n  %s --demo\n  %s  (no args → interactive TUI)\n\n", APPNAME, APPNAME, APPNAME)
	fmt.Fprintf(w, "COMMON OPTIONS:\n")
	fmt.Fprintf(w, "  -h, --help            Show this help\n")
	fmt.Fprintf(w, "  --version             Print version\n")
	fmt.Fprintf(w, "  --demo                Run self-contained demo with synthetic data\n")
	fmt.Fprintf(w, "  --format FMT          Output format: txt|md|json|csv|sarif (default txt)\n")
	fmt.Fprintf(w, "  --output FILE         Write report to FILE (default stdout)\n")
	fmt.Fprintf(w, "  --no-color            Disable ANSI colors\n")
	if extra != "" {
		fmt.Fprintf(w, "\nTOOL OPTIONS:\n%s\n", extra)
	}
	fmt.Fprintf(w, "\nEXAMPLES:\n")
	fmt.Fprintf(w, "  %s --input SYSTEM\n", APPNAME)
	fmt.Fprintf(w, "  %s --input NTUSER.DAT --tree\n", APPNAME)
	fmt.Fprintf(w, "  %s --input SOFTWARE --format json --output hive.json\n", APPNAME)
	fmt.Fprintf(w, "  %s --input SYSTEM --format sarif --output hive.sarif\n", APPNAME)
	fmt.Fprintf(w, "  %s --demo\n\n", APPNAME)
	fmt.Fprintf(w, "EXPORTS: TXT, Markdown, JSON, CSV, SARIF 2.1.0\n")
	fmt.Fprintf(w, "MITRE ATT&CK tags included on findings where applicable.\n")
	fmt.Fprintf(w, "Grading scale: A+ … F based on finding severity weights.\n")
}

// ---- Shared depth: MITRE ATT&CK technique database (subset) ----
type AttckTech struct {
	ID, Tactic, Name, Description string
}

var attckDB = []AttckTech{
	{"T1001", "Command and Control", "Data Obfuscation", "Obfuscate C2 traffic"},
	{"T1003", "Credential Access", "OS Credential Dumping", "Dump credentials from OS"},
	{"T1005", "Collection", "Data from Local System", "Collect local data"},
	{"T1027", "Defense Evasion", "Obfuscated Files or Information", "Obfuscate files/info"},
	{"T1036", "Defense Evasion", "Masquerading", "Masquerade as legitimate"},
	{"T1041", "Exfiltration", "Exfiltration Over C2 Channel", "Exfil over C2"},
	{"T1046", "Discovery", "Network Service Discovery", "Scan network services"},
	{"T1048", "Exfiltration", "Exfiltration Over Alternative Protocol", "Alt protocol exfil"},
	{"T1055", "Defense Evasion", "Process Injection", "Inject into processes"},
	{"T1059", "Execution", "Command and Scripting Interpreter", "Script interpreters"},
	{"T1059.001", "Execution", "PowerShell", "PowerShell execution"},
	{"T1059.003", "Execution", "Windows Command Shell", "cmd.exe"},
	{"T1059.005", "Execution", "Visual Basic", "VBScript/VBA"},
	{"T1059.007", "Execution", "JavaScript", "JS execution"},
	{"T1068", "Privilege Escalation", "Exploitation for Privilege Escalation", "PrivEsc exploit"},
	{"T1070", "Defense Evasion", "Indicator Removal", "Remove indicators"},
	{"T1070.004", "Defense Evasion", "File Deletion", "Delete files"},
	{"T1071", "Command and Control", "Application Layer Protocol", "App-layer C2"},
	{"T1082", "Discovery", "System Information Discovery", "System info discovery"},
	{"T1083", "Discovery", "File and Directory Discovery", "File discovery"},
	{"T1105", "Command and Control", "Ingress Tool Transfer", "Transfer tools in"},
	{"T1112", "Defense Evasion", "Modify Registry", "Registry modification"},
	{"T1129", "Execution", "Shared Modules", "Load shared modules"},
	{"T1140", "Defense Evasion", "Deobfuscate/Decode Files or Information", "Decode files"},
	{"T1204", "Execution", "User Execution", "User opens malicious file"},
	{"T1204.002", "Execution", "Malicious File", "User opens malicious file"},
	{"T1218", "Defense Evasion", "System Binary Proxy Execution", "Lolbins"},
	{"T1486", "Impact", "Data Encrypted for Impact", "Ransomware encryption"},
	{"T1543", "Persistence", "Create or Modify System Process", "Service/daemon persist"},
	{"T1547", "Persistence", "Boot or Logon Autostart Execution", "Autostart"},
	{"T1547.001", "Persistence", "Registry Run Keys / Startup Folder", "Run keys"},
	{"T1552", "Credential Access", "Unsecured Credentials", "Find credentials"},
	{"T1553", "Defense Evasion", "Subvert Trust Controls", "Trust subversion"},
	{"T1564", "Defense Evasion", "Hide Artifacts", "Hide artifacts"},
	{"T1566", "Initial Access", "Phishing", "Phishing"},
	{"T1566.001", "Initial Access", "Spearphishing Attachment", "Malicious attachment"},
	{"T1574", "Persistence", "Hijack Execution Flow", "Hijack flow"},
}

func attckLookup(id string) *AttckTech {
	for i := range attckDB {
		if attckDB[i].ID == id {
			return &attckDB[i]
		}
	}
	return nil
}

func attckRows() [][]string {
	rows := [][]string{}
	for _, t := range attckDB {
		rows = append(rows, []string{t.ID, t.Tactic, t.Name})
	}
	return rows
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func absInt64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

func readGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		u32le(b, 0), u16le(b, 4), u16le(b, 6), b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func filetimeString(ft uint64) string {
	t := filetimeToTime(ft)
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

type HiveHeader struct {
	Signature    string
	Seq1, Seq2   uint32
	Timestamp    time.Time
	Major, Minor uint32
	FileName     string
	RootOffset   uint32
	HbinsSize    uint32
}

type HiveKey struct {
	Name      string
	Timestamp time.Time
	Values    []HiveValue
}

type HiveValue struct {
	Name        string
	Type        uint32
	TypeName    string
	Data        []byte
	DataPreview string
}

var regValueTypes = map[uint32]string{
	0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
	5: "REG_DWORD_BE", 6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST",
	9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}

func parseHiveHeader(data []byte) (*HiveHeader, []Finding) {
	findings := []Finding{}
	h := &HiveHeader{}
	if len(data) < 0x200 {
		findings = append(findings, Finding{Severity: "critical", Title: "Hive too small", Category: "format", Mitre: []string{"T1112"}, Location: "hive"})
		return h, findings
	}
	h.Signature = string(data[0:4])
	if h.Signature != "regf" {
		findings = append(findings, Finding{Severity: "high", Title: "Bad hive signature", Evidence: h.Signature, Category: "format", Mitre: []string{"T1112"}, Location: "hive"})
	}
	h.Seq1 = u32le(data, 0x4)
	h.Seq2 = u32le(data, 0x8)
	h.Timestamp = filetimeToTime(u64le(data, 0x0C))
	h.Major = u32le(data, 0x14)
	h.Minor = u32le(data, 0x18)
	h.RootOffset = u32le(data, 0x24)
	h.HbinsSize = u32le(data, 0x28)
	h.FileName = utf16leToString(data[0x30 : 0x30+64])
	if h.Seq1 != h.Seq2 {
		findings = append(findings, Finding{Severity: "medium", Title: "Hive sequence numbers mismatch (dirty hive?)", Evidence: fmt.Sprintf("%d!=%d", h.Seq1, h.Seq2), Category: "integrity", Mitre: []string{"T1112"}, Location: "hive"})
	}
	return h, findings
}

func scanHiveCells(data []byte) []Finding {
	findings := []Finding{}
	// scan for ASCII key/value interesting strings
	needles := []struct{ N, Sev, Mitre, Title string }{
		{"\\Run", "medium", "T1547.001", "Autorun Run key string"},
		{"RunOnce", "medium", "T1547.001", "RunOnce string"},
		{"AppInit_DLLs", "high", "T1546.010", "AppInit_DLLs"},
		{"Image File Execution Options", "high", "T1546.012", "IFEO"},
		{"Userinit", "medium", "T1547.001", "Userinit"},
		{"powershell", "medium", "T1059.001", "PowerShell reference"},
		{"cmd.exe", "low", "T1059.003", "cmd.exe reference"},
		{"Services\\", "info", "T1543.003", "Services path"},
	}
	s := string(data)
	for _, n := range needles {
		if strings.Contains(s, n.N) {
			findings = append(findings, Finding{Severity: n.Sev, Title: n.Title, Evidence: n.N, Category: "hive-scan", Mitre: []string{n.Mitre}, Location: "hive", Tags: []string{n.N}})
		}
	}
	// hbin count
	count := strings.Count(s, "hbin")
	findings = append(findings, Finding{Severity: "info", Title: "hbin markers", Evidence: fmt.Sprintf("%d", count), Category: "structure", Mitre: []string{"T1112"}, Location: "hive"})
	return findings
}

// buildSyntheticHive produces a *structurally valid* regf hive with a small
// key tree (root → "Run" with a REG_SZ autorun value and a REG_DWORD), so the
// real cell parser and the detections can be exercised offline end-to-end.
func buildSyntheticHive() []byte {
	const binsBase = 0x1000
	bins := make([]byte, 0, 0x1000)
	// hbin header (32 bytes): "hbin", file offset (0), size.
	hb := make([]byte, 32)
	copy(hb[0:], []byte("hbin"))
	binary.LittleEndian.PutUint32(hb[0x8:], 0x1000)
	bins = append(bins, hb...)

	alloc := func(payload []byte) uint32 {
		sz := 4 + len(payload)
		if sz%8 != 0 {
			sz += 8 - sz%8
		}
		rel := uint32(len(bins)) // offset relative to bins base (0x1000)
		cell := make([]byte, sz)
		binary.LittleEndian.PutUint32(cell[0:], uint32(int32(-sz))) // allocated
		copy(cell[4:], payload)
		bins = append(bins, cell...)
		return rel
	}
	ft := timeToFiletime(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC))

	// Leaf data first so parents can reference their offsets.
	sz := []byte("powershell.exe")
	u16 := make([]byte, 0, len(sz)*2+2)
	for _, c := range sz {
		u16 = append(u16, byte(c), 0)
	}
	u16 = append(u16, 0, 0)
	dataOff := alloc(u16)

	vk1 := vkPayload("Backdoor", 1 /*REG_SZ*/, uint32(len(u16)), dataOff, false)
	vk1Off := alloc(vk1)
	// REG_DWORD stored inline (value 5).
	var inlineDword [4]byte
	binary.LittleEndian.PutUint32(inlineDword[:], 5)
	vk2 := vkPayloadInline("Count", 4 /*REG_DWORD*/, inlineDword[:])
	vk2Off := alloc(vk2)

	vlist := make([]byte, 8)
	binary.LittleEndian.PutUint32(vlist[0:], vk1Off)
	binary.LittleEndian.PutUint32(vlist[4:], vk2Off)
	vlistOff := alloc(vlist)

	child := nkPayload("Run", 0x20, ft, 0, 0xffffffff, 2, vlistOff)
	childOff := alloc(child)

	lf := make([]byte, 4+8)
	copy(lf[0:], []byte("lf"))
	binary.LittleEndian.PutUint16(lf[2:], 1) // one entry
	binary.LittleEndian.PutUint32(lf[4:], childOff)
	copy(lf[8:], []byte("Run_")) // hash field (ignored by parser)
	lfOff := alloc(lf)

	root := nkPayload("ROOT", 0x2c, ft, 1, lfOff, 0, 0xffffffff)
	rootOff := alloc(root)

	// Base block.
	buf := make([]byte, binsBase+len(bins))
	copy(buf[0:], []byte("regf"))
	binary.LittleEndian.PutUint32(buf[0x4:], 1)
	binary.LittleEndian.PutUint32(buf[0x8:], 1)
	binary.LittleEndian.PutUint64(buf[0x0C:], ft)
	binary.LittleEndian.PutUint32(buf[0x14:], 1) // major
	binary.LittleEndian.PutUint32(buf[0x18:], 3) // minor
	binary.LittleEndian.PutUint32(buf[0x1C:], 1) // file type (primary)
	binary.LittleEndian.PutUint32(buf[0x20:], 1) // file format (direct memory load)
	binary.LittleEndian.PutUint32(buf[0x24:], rootOff)
	binary.LittleEndian.PutUint32(buf[0x28:], uint32(len(bins)))
	binary.LittleEndian.PutUint32(buf[0x2C:], 1) // clustering
	copy(buf[0x30:], utf16leBytes("SYNTH"))
	// base-block checksum: XOR of the first 0x1FC bytes as little-endian u32s.
	var xs uint32
	for i := 0; i < 0x1FC; i += 4 {
		xs ^= binary.LittleEndian.Uint32(buf[i:])
	}
	if xs == 0xffffffff {
		xs = 0xfffffffe
	}
	if xs == 0 {
		xs = 1
	}
	binary.LittleEndian.PutUint32(buf[0x1FC:], xs)
	copy(buf[binsBase:], bins)
	return buf
}

func utf16leBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	out = append(out, 0, 0)
	return out
}

func timeToFiletime(t time.Time) uint64 {
	// 100-ns intervals since 1601-01-01.
	const epochDiff = 11644473600 // seconds 1601→1970
	return uint64((t.Unix() + epochDiff)) * 10000000
}

func nkPayload(name string, flags uint16, ft uint64, numSub, subListOff, numVal, valListOff uint32) []byte {
	p := make([]byte, 0x4C+len(name))
	copy(p[0:], []byte("nk"))
	binary.LittleEndian.PutUint16(p[2:], flags)
	binary.LittleEndian.PutUint64(p[4:], ft)
	binary.LittleEndian.PutUint32(p[0x10:], 0xffffffff) // parent
	binary.LittleEndian.PutUint32(p[0x14:], numSub)
	binary.LittleEndian.PutUint32(p[0x1C:], subListOff)
	binary.LittleEndian.PutUint32(p[0x24:], numVal)
	binary.LittleEndian.PutUint32(p[0x28:], valListOff)
	binary.LittleEndian.PutUint32(p[0x2C:], 0xffffffff) // security
	binary.LittleEndian.PutUint32(p[0x30:], 0xffffffff) // class
	binary.LittleEndian.PutUint16(p[0x48:], uint16(len(name)))
	copy(p[0x4C:], []byte(name)) // ASCII (flags&0x20)
	return p
}

func vkPayload(name string, typ, dataLen, dataOff uint32, _ bool) []byte {
	p := make([]byte, 0x14+len(name))
	copy(p[0:], []byte("vk"))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(name)))
	binary.LittleEndian.PutUint32(p[4:], dataLen)
	binary.LittleEndian.PutUint32(p[8:], dataOff)
	binary.LittleEndian.PutUint32(p[0x0C:], typ)
	binary.LittleEndian.PutUint16(p[0x10:], 0x0001) // ASCII name
	copy(p[0x14:], []byte(name))
	return p
}

func vkPayloadInline(name string, typ uint32, data []byte) []byte {
	p := make([]byte, 0x14+len(name))
	copy(p[0:], []byte("vk"))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(name)))
	binary.LittleEndian.PutUint32(p[4:], 0x80000000|uint32(len(data))) // inline flag
	copy(p[8:], data)                                                  // data lives in the offset field
	binary.LittleEndian.PutUint32(p[0x0C:], typ)
	binary.LittleEndian.PutUint16(p[0x10:], 0x0001)
	copy(p[0x14:], []byte(name))
	return p
}

func runDemo() *Report {
	r := newReport("demo")
	data := buildSyntheticHive()
	hv, err := parseHive(data)
	if err != nil {
		r.add(Finding{Severity: "high", Title: "Demo hive parse failed", Evidence: err.Error(), Category: "format", Location: "demo"})
		r.finalize()
		return r
	}
	analyzeHive(r, hv)
	r.finalize()
	return r
}

func runAnalyze(path, format, output string) int {
	data, err := readFileLimited(path, 1<<30)
	if err != nil {
		errMsg(err.Error())
		return 1
	}
	r := newReport(path)
	hv, err := parseHive(data)
	if err != nil {
		// Still surface the header + a raw string scan so a damaged hive is useful.
		h, hf := parseHiveHeader(data)
		for _, f := range hf {
			r.add(f)
		}
		r.add(Finding{Severity: "high", Title: "Hive parse failed", Evidence: err.Error(), Category: "format", Mitre: []string{"T1112"}, Location: path})
		for _, f := range scanHiveCells(data) {
			r.add(f)
		}
		_ = h
		r.finalize()
		_ = exportReport(r, format, output)
		if output != "" || format == "txt" {
			printReportSummary(r)
		}
		return 1
	}
	analyzeHive(r, hv)
	r.finalize()
	_ = exportReport(r, format, output)
	if output != "" || format == "txt" {
		printReportSummary(r)
	}
	return 0
}

func printHelp() {
	extra := `  --input PATH          Registry hive to parse (SYSTEM, SOFTWARE, NTUSER.DAT, ...)
  --path PATH           Alias for --input
  --tree                Print the parsed key tree and exit
  --list-attck          Show ATT&CK techniques
  --selftest            Run internal self-tests

`
	writeUsageHeader(os.Stdout, extra)
}

func runCLI(args []string) int {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var showHelp, showVersion, demo, noColorFlag, listAttck, selfTest, treeFlag bool
	var format, output, input, dumpHivePath string
	fs.BoolVar(&showHelp, "help", false, "")
	fs.BoolVar(&showHelp, "h", false, "")
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&demo, "demo", false, "")
	fs.BoolVar(&noColorFlag, "no-color", false, "")
	fs.StringVar(&format, "format", "txt", "")
	fs.StringVar(&output, "output", "", "")
	fs.StringVar(&input, "input", "", "")
	fs.StringVar(&input, "path", "", "")
	fs.BoolVar(&listAttck, "list-attck", false, "")
	fs.BoolVar(&selfTest, "selftest", false, "")
	fs.BoolVar(&treeFlag, "tree", false, "")
	fs.StringVar(&dumpHivePath, "dump-hive", "", "")
	if err := fs.Parse(args); err != nil {
		errMsg(err.Error())
		printHelp()
		return 2
	}
	if noColorFlag {
		noColor = true
	}
	if showHelp {
		printHelp()
		return 0
	}
	if showVersion {
		fmt.Printf("%s %s\n", APPNAME, VERSION)
		return 0
	}
	if listAttck {
		table([]string{"ID", "Tactic", "Name"}, attckRows())
		return 0
	}
	if selfTest {
		return runSelfTest()
	}
	if dumpHivePath != "" {
		if err := os.WriteFile(dumpHivePath, buildSyntheticHive(), 0o644); err != nil {
			errMsg(err.Error())
			return 1
		}
		okMsg("wrote synthetic hive to " + dumpHivePath)
		return 0
	}
	if treeFlag {
		if input == "" {
			errMsg("--tree needs --input")
			return 2
		}
		data, err := readFileLimited(input, 1<<30)
		if err != nil {
			errMsg(err.Error())
			return 1
		}
		hv, err := parseHive(data)
		if err != nil {
			errMsg(err.Error())
			return 1
		}
		table([]string{"Key path", "Subkeys", "Values", "Modified (UTC)"}, keyTreeRows(hv, 200))
		okMsg(fmt.Sprintf("%d keys, %d values", len(hv.Keys), hv.valueCount))
		return 0
	}
	if demo {
		r := runDemo()
		_ = exportReport(r, format, output)
		if output != "" || format == "txt" {
			printReportSummary(r)
		}
		return 0
	}
	if input == "" {
		printHelp()
		return 2
	}
	return runAnalyze(input, format, output)
}

func runTUI() {
	for {
		choice := menu("Main Menu", [][2]string{
			{"Analyze hive", "parse a hive: persistence & artefacts"},
			{"Key tree", "print the key tree of a hive"},
			{"ATT&CK techniques", "techniques this tool detects"},
			{"Run demo", "synthetic hive, no file needed"},
		})
		switch choice {
		case "0", "00", "q", "Q", "":
			okMsg("Goodbye.")
			return
		case "h", "H", "help", "?":
			tuiHelp()
		case "1":
			p := prompt("hive path")
			runAnalyze(p, "txt", "")
			pause()
		case "2":
			p := prompt("hive path")
			data, err := readFileLimited(p, 1<<30)
			if err != nil {
				errMsg(err.Error())
				pause()
				continue
			}
			hv, err := parseHive(data)
			if err != nil {
				errMsg(err.Error())
				pause()
				continue
			}
			table([]string{"Key path", "Subkeys", "Values", "Modified (UTC)"}, keyTreeRows(hv, 100))
			okMsg(fmt.Sprintf("%d keys, %d values", len(hv.Keys), hv.valueCount))
			pause()
		case "3":
			table([]string{"ID", "Tactic", "Name"}, attckRows())
			pause()
		case "4":
			printReportSummary(runDemo())
			pause()
		default:
			warnMsg("Invalid selection")
			pause()
		}
	}
}

func main() {
	if len(os.Args) <= 1 {
		runTUI()
		return
	}
	for _, a := range os.Args[1:] {
		if a == "--no-color" {
			noColor = true
		}
	}
	os.Exit(runCLI(os.Args[1:]))
}

// ============================================================
//  Real regf cell parser — hbin / nk / vk / lf / lh / li / ri
//  Cell offsets are relative to the hive-bins base (0x1000).
// ============================================================

const binsBase = 0x1000

type RegValue struct {
	Name     string
	Type     uint32
	TypeName string
	Data     []byte
}

type RegKey struct {
	Path     string
	Name     string
	Modified time.Time
	Values   []RegValue
	NumSub   uint32
	NumVal   uint32
}

type Hive struct {
	data       []byte
	header     *HiveHeader
	Keys       []*RegKey
	valueCount int
	truncated  bool
}

// cell returns the payload of the cell at bins-relative offset `rel`
// (the bytes after the 4-byte size field), or nil if out of range.
func (hv *Hive) cell(rel uint32) []byte {
	if rel == 0xffffffff {
		return nil
	}
	abs := binsBase + int(rel)
	if abs < binsBase || abs+4 > len(hv.data) {
		return nil
	}
	sz := int32(binary.LittleEndian.Uint32(hv.data[abs:]))
	if sz < 0 {
		sz = -sz
	}
	if sz < 4 {
		return nil
	}
	end := abs + int(sz)
	if end > len(hv.data) {
		end = len(hv.data)
	}
	return hv.data[abs+4 : end]
}

func decodeKeyName(p []byte, flags uint16, nlen int) string {
	if 0x4C+nlen > len(p) || nlen < 0 {
		return ""
	}
	raw := p[0x4C : 0x4C+nlen]
	if flags&0x20 != 0 { // KEY_COMP_NAME → Latin-1/ASCII
		return string(raw)
	}
	return utf16leToString(raw)
}

func parseHive(data []byte) (*Hive, error) {
	h, _ := parseHiveHeader(data)
	if h.Signature != "regf" {
		return nil, fmt.Errorf("not a regf hive (signature %q)", h.Signature)
	}
	if len(data) < binsBase+32 {
		return nil, fmt.Errorf("hive too small (%d bytes)", len(data))
	}
	hv := &Hive{data: data, header: h}
	visited := map[uint32]bool{}
	const maxKeys = 500000
	var walk func(rel uint32, path string, depth int)
	walk = func(rel uint32, path string, depth int) {
		if rel == 0xffffffff || visited[rel] || depth > 512 || len(hv.Keys) >= maxKeys {
			if len(hv.Keys) >= maxKeys {
				hv.truncated = true
			}
			return
		}
		visited[rel] = true
		p := hv.cell(rel)
		if len(p) < 0x4C || string(p[0:2]) != "nk" {
			return
		}
		flags := binary.LittleEndian.Uint16(p[2:])
		ft := binary.LittleEndian.Uint64(p[4:])
		numSub := binary.LittleEndian.Uint32(p[0x14:])
		subListOff := binary.LittleEndian.Uint32(p[0x1C:])
		numVal := binary.LittleEndian.Uint32(p[0x24:])
		valListOff := binary.LittleEndian.Uint32(p[0x28:])
		nlen := int(binary.LittleEndian.Uint16(p[0x48:]))
		name := decodeKeyName(p, flags, nlen)
		full := path
		if path == "" {
			full = name
		} else {
			full = path + "\\" + name
		}
		k := &RegKey{Path: full, Name: name, Modified: filetimeToTime(ft), NumSub: numSub, NumVal: numVal}
		k.Values = hv.readValues(valListOff, numVal)
		hv.valueCount += len(k.Values)
		hv.Keys = append(hv.Keys, k)

		for _, childOff := range hv.subkeyOffsets(subListOff, 0) {
			walk(childOff, full, depth+1)
		}
	}
	walk(h.RootOffset, "", 0)
	if len(hv.Keys) == 0 {
		return nil, errors.New("no keys parsed (unsupported or corrupt hive)")
	}
	return hv, nil
}

// subkeyOffsets resolves lf/lh/li/ri subkey lists into child nk offsets.
func (hv *Hive) subkeyOffsets(rel uint32, depth int) []uint32 {
	if rel == 0xffffffff || depth > 32 {
		return nil
	}
	p := hv.cell(rel)
	if len(p) < 4 {
		return nil
	}
	sig := string(p[0:2])
	count := int(binary.LittleEndian.Uint16(p[2:]))
	var out []uint32
	switch sig {
	case "lf", "lh": // hash leaf: {u32 offset, u32 hash} per entry
		for i := 0; i < count; i++ {
			off := 4 + i*8
			if off+4 > len(p) {
				break
			}
			out = append(out, binary.LittleEndian.Uint32(p[off:]))
		}
	case "li": // index leaf: u32 offsets
		for i := 0; i < count; i++ {
			off := 4 + i*4
			if off+4 > len(p) {
				break
			}
			out = append(out, binary.LittleEndian.Uint32(p[off:]))
		}
	case "ri": // index root: u32 offsets to sublists
		for i := 0; i < count; i++ {
			off := 4 + i*4
			if off+4 > len(p) {
				break
			}
			out = append(out, hv.subkeyOffsets(binary.LittleEndian.Uint32(p[off:]), depth+1)...)
		}
	}
	return out
}

func (hv *Hive) readValues(listRel, numVal uint32) []RegValue {
	if listRel == 0xffffffff || numVal == 0 || numVal > 100000 {
		return nil
	}
	list := hv.cell(listRel)
	if len(list) < int(numVal)*4 {
		if len(list) < 4 {
			return nil
		}
		numVal = uint32(len(list) / 4)
	}
	var vals []RegValue
	for i := uint32(0); i < numVal; i++ {
		voff := binary.LittleEndian.Uint32(list[i*4:])
		if v, ok := hv.readValue(voff); ok {
			vals = append(vals, v)
		}
	}
	return vals
}

func (hv *Hive) readValue(rel uint32) (RegValue, bool) {
	p := hv.cell(rel)
	if len(p) < 0x14 || string(p[0:2]) != "vk" {
		return RegValue{}, false
	}
	nlen := int(binary.LittleEndian.Uint16(p[2:]))
	dataLen := binary.LittleEndian.Uint32(p[4:])
	dataOff := binary.LittleEndian.Uint32(p[8:])
	typ := binary.LittleEndian.Uint32(p[0x0C:])
	flags := binary.LittleEndian.Uint16(p[0x10:])
	name := "(Default)"
	if nlen > 0 && 0x14+nlen <= len(p) {
		raw := p[0x14 : 0x14+nlen]
		if flags&0x0001 != 0 {
			name = string(raw)
		} else {
			name = utf16leToString(raw)
		}
	}
	var data []byte
	inline := dataLen&0x80000000 != 0
	realLen := int(dataLen & 0x7fffffff)
	if inline {
		n := realLen
		if n > 4 {
			n = 4
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, dataOff)
		data = buf[:n]
	} else if realLen > 0 {
		dc := hv.cell(dataOff)
		if len(dc) >= 2 && string(dc[0:2]) == "db" {
			data = hv.readBigData(dc, realLen)
		} else if dc != nil {
			if realLen > len(dc) {
				realLen = len(dc)
			}
			data = append([]byte(nil), dc[:realLen]...)
		}
	}
	return RegValue{Name: name, Type: typ, TypeName: regValueTypes[typ], Data: data}, true
}

// readBigData reassembles REG big-data (db) fragment lists.
func (hv *Hive) readBigData(db []byte, total int) []byte {
	if len(db) < 8 {
		return nil
	}
	nseg := int(binary.LittleEndian.Uint16(db[2:]))
	listOff := binary.LittleEndian.Uint32(db[4:])
	list := hv.cell(listOff)
	if list == nil {
		return nil
	}
	var out []byte
	for i := 0; i < nseg && (i*4+4) <= len(list); i++ {
		seg := hv.cell(binary.LittleEndian.Uint32(list[i*4:]))
		chunk := seg
		if len(chunk) > 16344 {
			chunk = chunk[:16344]
		}
		out = append(out, chunk...)
	}
	if len(out) > total {
		out = out[:total]
	}
	return out
}

// renderValueData formats value data per type for display.
func renderValueData(v RegValue) string {
	switch v.Type {
	case 1, 2, 6: // REG_SZ / EXPAND_SZ / LINK
		return utf16leToString(v.Data)
	case 4: // REG_DWORD (LE)
		if len(v.Data) >= 4 {
			return fmt.Sprintf("0x%08x (%d)", binary.LittleEndian.Uint32(v.Data), binary.LittleEndian.Uint32(v.Data))
		}
	case 5: // REG_DWORD_BE
		if len(v.Data) >= 4 {
			return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(v.Data))
		}
	case 11: // REG_QWORD
		if len(v.Data) >= 8 {
			return fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(v.Data))
		}
	case 7: // REG_MULTI_SZ
		return strings.Join(splitMultiSZ(v.Data), " | ")
	}
	// REG_BINARY and fallbacks: hex preview
	if len(v.Data) == 0 {
		return "(empty)"
	}
	max := 32
	if len(v.Data) < max {
		max = len(v.Data)
	}
	return hex.EncodeToString(v.Data[:max]) + cond(len(v.Data) > max, "…", "")
}

func splitMultiSZ(b []byte) []string {
	s := utf16leToStringKeepAll(b)
	parts := strings.Split(s, "\x00")
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func utf16leToStringKeepAll(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16Runes(u))
}

func utf16Runes(u []uint16) []rune {
	var rs []rune
	for i := 0; i < len(u); i++ {
		rs = append(rs, rune(u[i]))
	}
	return rs
}

func cond(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// ============================================================
//  Analysis — persistence / ATT&CK detections over real keys
// ============================================================

type hiveDetector struct {
	keyMatch string // case-insensitive substring of the full key path
	valMatch string // optional value-name match
	sev      string
	mitre    string
	title    string
}

var hiveDetectors = []hiveDetector{
	{"\\Run", "", "medium", "T1547.001", "Run key autostart entry"},
	{"\\RunOnce", "", "medium", "T1547.001", "RunOnce autostart entry"},
	{"\\RunServices", "", "high", "T1547.001", "RunServices autostart entry"},
	{"Image File Execution Options", "Debugger", "high", "T1546.012", "IFEO Debugger hijack"},
	{"Windows\\CurrentVersion\\Winlogon", "Userinit", "high", "T1547.004", "Winlogon Userinit persistence"},
	{"Windows\\CurrentVersion\\Winlogon", "Shell", "high", "T1547.004", "Winlogon Shell persistence"},
	{"Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs", "high", "T1546.010", "AppInit_DLLs injection"},
	{"\\Services\\", "ImagePath", "info", "T1543.003", "Service ImagePath"},
}

func analyzeHive(r *Report, hv *Hive) {
	h := hv.header
	r.add(Finding{Severity: "info", Title: "Hive header",
		Evidence: fmt.Sprintf("sig=%s file=%q ver=%d.%d root=0x%x bins=%d bytes",
			h.Signature, h.FileName, h.Major, h.Minor, h.RootOffset, h.HbinsSize),
		Category: "header", Mitre: []string{"T1112"}, Location: "hive"})
	r.Meta["keys"] = strconv.Itoa(len(hv.Keys))
	r.Meta["values"] = strconv.Itoa(hv.valueCount)
	r.Meta["hive_name"] = h.FileName
	r.Stats["keys"] = len(hv.Keys)
	r.Stats["values"] = hv.valueCount

	r.add(Finding{Severity: "info", Title: "Hive parsed",
		Evidence: fmt.Sprintf("%d keys, %d values", len(hv.Keys), hv.valueCount),
		Category: "structure", Mitre: []string{"T1112"}, Location: "hive"})
	if hv.truncated {
		r.add(Finding{Severity: "low", Title: "Key tree truncated", Evidence: "hit the 500k-key safety cap", Category: "structure", Location: "hive"})
	}
	if hv.header.Seq1 != hv.header.Seq2 {
		r.add(Finding{Severity: "medium", Title: "Dirty hive (sequence mismatch)",
			Evidence: fmt.Sprintf("%d != %d — pending transaction log replay", hv.header.Seq1, hv.header.Seq2),
			Category: "integrity", Mitre: []string{"T1112"}, Location: "hive"})
	}

	for _, k := range hv.Keys {
		for _, det := range hiveDetectors {
			if !containsFold(k.Path, det.keyMatch) {
				continue
			}
			if det.valMatch == "" {
				ev := k.Path
				if len(k.Values) > 0 {
					ev += fmt.Sprintf("  (%d values)", len(k.Values))
				}
				r.add(Finding{Severity: det.sev, Title: det.title, Evidence: ev,
					Category: "persistence", Mitre: []string{det.mitre}, Location: k.Path})
				for _, v := range k.Values {
					if looksExecutable(renderValueData(v)) {
						r.add(Finding{Severity: raise(det.sev), Title: det.title + " → executable",
							Evidence: fmt.Sprintf("%s = %s", valName(v.Name), renderValueData(v)),
							Category: "persistence", Mitre: []string{det.mitre}, Location: k.Path})
					}
				}
			} else {
				for _, v := range k.Values {
					if strings.EqualFold(v.Name, det.valMatch) {
						r.add(Finding{Severity: det.sev, Title: det.title,
							Evidence: fmt.Sprintf("%s\\%s = %s", k.Path, v.Name, renderValueData(v)),
							Category: "persistence", Mitre: []string{det.mitre}, Location: k.Path})
					}
				}
			}
		}
	}
}

func valName(n string) string {
	if n == "" {
		return "(Default)"
	}
	return n
}
func looksExecutable(s string) bool {
	l := strings.ToLower(s)
	for _, e := range []string{".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr", "powershell", "rundll32", "mshta", "cmd.exe", "wscript", "cscript"} {
		if strings.Contains(l, e) {
			return true
		}
	}
	return false
}
func raise(sev string) string {
	switch sev {
	case "info":
		return "medium"
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high":
		return "critical"
	}
	return sev
}

// keyTreeRows returns up to `limit` rows of (path, subkeys, values, modified).
func keyTreeRows(hv *Hive, limit int) [][]string {
	rows := [][]string{}
	for i, k := range hv.Keys {
		if limit > 0 && i >= limit {
			break
		}
		mod := ""
		if !k.Modified.IsZero() {
			mod = k.Modified.UTC().Format("2006-01-02 15:04:05")
		}
		rows = append(rows, []string{truncPath(k.Path, 48), strconv.Itoa(int(k.NumSub)), strconv.Itoa(len(k.Values)), mod})
	}
	return rows
}

func truncPath(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}

// ============================================================
//  Self-test — builds a valid synthetic hive and asserts the
//  real cell parser reconstructs the key tree and value data.
// ============================================================

func runSelfTest() int {
	pass, fail := 0, 0
	check := func(name string, cond bool, detail string) {
		if cond {
			pass++
			okMsg(name)
		} else {
			fail++
			errMsg(name + " — " + detail)
		}
	}
	fmt.Println()
	line(66)
	fmt.Println("  " + col("⬡  OHive self-test", B+CY))
	line(66)
	fmt.Println()

	data := buildSyntheticHive()
	h, _ := parseHiveHeader(data)
	check("synthetic hive signature regf", h.Signature == "regf", h.Signature)
	check("header file name SYNTH", h.FileName == "SYNTH", h.FileName)
	check("root offset populated", h.RootOffset != 0 && h.RootOffset != 0xffffffff, fmt.Sprintf("0x%x", h.RootOffset))

	hv, err := parseHive(data)
	check("hive parses", err == nil && hv != nil, errStr(err))
	if hv != nil {
		check("two keys parsed (ROOT, Run)", len(hv.Keys) == 2, strconv.Itoa(len(hv.Keys)))
		var runKey *RegKey
		for _, k := range hv.Keys {
			if k.Name == "Run" {
				runKey = k
			}
		}
		check("Run subkey found", runKey != nil, "")
		if runKey != nil {
			check("Run path is ROOT\\Run", runKey.Path == "ROOT\\Run", runKey.Path)
			check("Run has 2 values", len(runKey.Values) == 2, strconv.Itoa(len(runKey.Values)))
			var sz, dw *RegValue
			for i := range runKey.Values {
				switch runKey.Values[i].Name {
				case "Backdoor":
					sz = &runKey.Values[i]
				case "Count":
					dw = &runKey.Values[i]
				}
			}
			check("REG_SZ value decodes", sz != nil && renderValueData(*sz) == "powershell.exe", condPtr(sz))
			check("REG_SZ type name", sz != nil && sz.TypeName == "REG_SZ", "")
			check("REG_DWORD inline = 5", dw != nil && len(dw.Data) >= 4 && binary.LittleEndian.Uint32(dw.Data) == 5, "")
			check("key modified time parsed", !runKey.Modified.IsZero(), runKey.Modified.String())
		}
	}

	// Detection pipeline fires on the Run key + executable value.
	r := runDemo()
	titles := map[string]bool{}
	for _, f := range r.Findings {
		titles[f.Title] = true
	}
	check("Run-key persistence finding", titles["Run key autostart entry"], "")
	check("executable-in-Run finding", titles["Run key autostart entry → executable"], "")

	// Big-data / value type map sanity.
	check("REG_MULTI_SZ type name", regValueTypes[7] == "REG_MULTI_SZ", regValueTypes[7])
	check("DWORD render", renderValueData(RegValue{Type: 4, Data: []byte{0x2a, 0, 0, 0}}) == "0x0000002a (42)", renderValueData(RegValue{Type: 4, Data: []byte{0x2a, 0, 0, 0}}))

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("All %d checks passed.", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d failed.", pass, fail))
	return 1
}

func errStr(e error) string {
	if e == nil {
		return "nil"
	}
	return e.Error()
}
func condPtr(v *RegValue) string {
	if v == nil {
		return "nil"
	}
	return renderValueData(*v)
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OHive parses Windows registry hive files offline with its own regf reader (no Windows and no external library). It reads SYSTEM, SOFTWARE, SECURITY, SAM and NTUSER.DAT files copied from a disk image or a live triage, walks the key tree and extracts forensic artefacts.",
	"It flags persistence (Run / RunOnce keys, services set to autostart, Winlogon and AppInit hooks), recently used files, USB device history and other common investigation points, maps findings to MITRE ATT&CK and grades the hive.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Use [1] to analyze a hive you copied, or [4] to see a full example with no file. [H] opens this help, [0] or q quits.",
	"Hives live under C:\\Windows\\System32\\config (SYSTEM, SOFTWARE, SECURITY, SAM) and in each user profile (NTUSER.DAT). Copy them out of a mounted image or triage package; this tool never touches a live registry.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Analyze hive: enter the path of a hive file. Shows the findings (persistence, artefacts ...), ATT&CK tags and a grade."},
	{"2", "Key tree: enter a hive path to print its key tree with subkey / value counts and last-modified times."},
	{"3", "ATT&CK techniques: the MITRE techniques this tool can detect."},
	{"4", "Run demo: parses a built-in synthetic hive so you can see every finding type."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "Different hives hold different evidence: SYSTEM has services and USB history, SOFTWARE has Run keys, NTUSER.DAT has per-user activity. Analyze the one that fits your question."},
	{"*", "On the command line, --tree prints the key tree and --format json / sarif feeds the findings into other tools."},
	{"*", "Copy hives from an image or triage set; never analyze a running system's live hive files directly."},
}

func owlHelpCLI() { printHelp() }
