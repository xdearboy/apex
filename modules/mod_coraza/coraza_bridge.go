package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    int blocked;
    int status_code;
    int rule_id;
    char rule_msg[256];
} coraza_verdict_t;
*/
import "C"
import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

var globalWAF atomic.Pointer[coraza.WAF]

const DefaultSecLangRules = `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

SecRule ARGS|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_URI "@rx (?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|--\s*$)" \
    "id:1001,phase:2,deny,status:403,log,msg:'SQL Injection Attempt Detected'"

SecRule ARGS|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_URI "@rx (?i)(<script[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\(|prompt\(|document\.cookie)" \
    "id:1002,phase:2,deny,status:403,log,msg:'Cross-Site Scripting (XSS) Detected'"

SecRule REQUEST_URI|ARGS "@rx (?i)(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini)" \
    "id:1003,phase:1,deny,status:403,log,msg:'Path Traversal / LFI Attempt Detected'"

SecRule ARGS|REQUEST_HEADERS|REQUEST_BODY|REQUEST_URI "@rx (?i)(\${jndi:|/bin/(sh|bash|zsh)|cmd\.exe|powershell)" \
    "id:1004,phase:2,deny,status:403,log,msg:'Remote Code Execution (RCE) Attempt Detected'"

SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nikto|acunetix|gobuster|wpscan|dirbuster|masscan)" \
    "id:1005,phase:1,deny,status:403,log,msg:'Malicious Scanner Detected'"
`

//export coraza_bridge_init
func coraza_bridge_init(cDirectives *C.char) C.int {
	ruleText := DefaultSecLangRules
	if cDirectives != nil {
		directives := C.GoString(cDirectives)
		if directives != "" {
			if strings.HasPrefix(directives, "/") || strings.HasPrefix(directives, "./") || strings.Contains(directives, ".conf") {
				data, err := os.ReadFile(directives)
				if err == nil && len(data) > 0 {
					ruleText = string(data)
				}
			} else {
				ruleText = directives
			}
		}
	}

	cfg := coraza.NewWAFConfig().WithDirectives(ruleText)
	w, err := coraza.NewWAF(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coraza: failed to initialize WAF: %v\n", err)
		return -1
	}

	globalWAF.Store(&w)
	return 0
}

//export coraza_bridge_destroy
func coraza_bridge_destroy() {
	globalWAF.Store(nil)
}

func fastString(ptr *C.char) string {
	if ptr == nil {
		return ""
	}
	switch {
	case *ptr == 'G' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1)) == 'E' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) == 'T' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 3)) == 0:
		return "GET"
	case *ptr == 'P' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1)) == 'O' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) == 'S' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 3)) == 'T' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 4)) == 0:
		return "POST"
	case *ptr == 'H' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1)) == 'E' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) == 'A' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 3)) == 'D' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 4)) == 0:
		return "HEAD"
	case *ptr == '/' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1)) == 0:
		return "/"
	case *ptr == '1' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1)) == '2' && *(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) == '7':
		if C.GoString(ptr) == "127.0.0.1" {
			return "127.0.0.1"
		}
	}
	return C.GoString(ptr)
}

//export coraza_bridge_eval
func coraza_bridge_eval(
	cClientIP *C.char,
	cMethod *C.char,
	cURI *C.char,
	cProto *C.char,
	cRawHeaders *C.char,
	cHeadersLen C.size_t,
	cBody *C.char,
	cBodyLen C.size_t,
	outVerdict *C.coraza_verdict_t,
) C.int {
	pWaf := globalWAF.Load()
	if pWaf == nil || outVerdict == nil {
		return 0
	}
	waf := *pWaf

	outVerdict.blocked = 0
	outVerdict.status_code = 200
	outVerdict.rule_id = 0
	outVerdict.rule_msg[0] = 0

	clientIP := "127.0.0.1"
	if cClientIP != nil {
		clientIP = fastString(cClientIP)
	}
	method := "GET"
	if cMethod != nil {
		method = fastString(cMethod)
	}
	uri := "/"
	if cURI != nil {
		uri = fastString(cURI)
	}
	proto := "HTTP/1.1"
	if cProto != nil {
		proto = fastString(cProto)
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	// 1. Connection
	tx.ProcessConnection(clientIP, 0, "127.0.0.1", 80)

	// 2. URI
	tx.ProcessURI(uri, method, proto)

	// 3. Headers (zero-copy parsing via unsafe.Slice)
	if cRawHeaders != nil && cHeadersLen > 0 {
		raw := unsafe.Slice((*byte)(unsafe.Pointer(cRawHeaders)), int(cHeadersLen))
		firstLine := true
		for len(raw) > 0 {
			lineEnd := bytes.IndexByte(raw, '\n')
			var line []byte
			if lineEnd >= 0 {
				line = raw[:lineEnd]
				raw = raw[lineEnd+1:]
			} else {
				line = raw
				raw = nil
			}
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if firstLine {
				firstLine = false
				continue
			}
			if len(line) == 0 {
				break
			}
			colon := bytes.IndexByte(line, ':')
			if colon > 0 {
				key := strings.TrimSpace(string(line[:colon]))
				val := strings.TrimSpace(string(line[colon+1:]))
				tx.AddRequestHeader(key, val)
			}
		}
	}

	applyInterruption := func(it *types.Interruption) {
		outVerdict.blocked = 1
		outVerdict.status_code = C.int(it.Status)
		if outVerdict.status_code <= 0 {
			outVerdict.status_code = 403
		}
		outVerdict.rule_id = C.int(it.RuleID)
		msg := fmt.Sprintf("Rule %d triggered (%s)", it.RuleID, it.Action)
		cMsg := C.CString(msg)
		C.strncpy(&outVerdict.rule_msg[0], cMsg, 255)
		C.free(unsafe.Pointer(cMsg))
	}

	it := tx.ProcessRequestHeaders()
	if it != nil {
		applyInterruption(it)
		return 1
	}

	// 4. Body & Phase 2 Evaluation (zero-copy slice)
	if cBody != nil && cBodyLen > 0 {
		bodyBytes := unsafe.Slice((*byte)(unsafe.Pointer(cBody)), int(cBodyLen))
		it, _, err := tx.WriteRequestBody(bodyBytes)
		if err == nil && it != nil {
			applyInterruption(it)
			return 1
		}
	}
	it, err := tx.ProcessRequestBody()
	if err == nil && it != nil {
		applyInterruption(it)
		return 1
	}

	return 0
}

func main() {}
