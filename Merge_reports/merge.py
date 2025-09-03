from Merge_reports.wapiti_to_sarif import wapiti_to_sarif_converter
import json
import uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote_plus
from typing import Dict, List, Set, Tuple, Optional
import re

def start_merge():
    """
    Hợp nhất các phần 'runs.results', 'runs.taxonomies' và 'runs.tool.driver'
    từ một báo cáo SARIF của ZAP (từ tệp) và dữ liệu SARIF của Wapiti (trong bộ nhớ)
    vào một báo cáo SARIF mới.

    """
    # Đọc cấu hình từ file config.json
    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config.json"
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    zap_sarif_filepath = project_root / config['zap']['report_file']
    output_sarif_filepath = project_root / config['merge']['output_file']
    wapiti_json_filepath = project_root / config['wapiti']['report_file']

    try:
        # 1. Đọc dữ liệu từ tệp SARIF của ZAP và json của Wapiti
        with open(zap_sarif_filepath, 'r', encoding='utf-8') as f:
            zap_data = json.load(f)
        with open(wapiti_json_filepath, 'r', encoding='utf-8') as f:
            wapiti_data = json.load(f)

        # Dữ liệu Wapiti đã được truyền vào hàm dưới dạng dictionary
        wapiti_data = wapiti_to_sarif_converter(wapiti_data)
        print("✅ Chuyển đổi Wapiti sang định dạng SARIF thành công.")

        # Kiểm tra xem cả hai báo cáo có ít nhất một "run" không
        if not zap_data.get("runs") or not zap_data["runs"]:
            print(f"❌ Lỗi: Tệp ZAP SARIF '{zap_sarif_filepath}' không chứa dữ liệu 'runs' hợp lệ.")
            return
        if not wapiti_data.get("runs") or not wapiti_data["runs"]:
            print(f"❌ Lỗi: Dữ liệu Wapiti SARIF trong bộ nhớ không chứa dữ liệu 'runs' hợp lệ.")
            return

        # Lấy "run" đầu tiên từ mỗi báo cáo
        zap_run = zap_data["runs"][0]
        wapiti_run = wapiti_data["runs"][0]

        # 2. Chuẩn bị cấu trúc SARIF đầu ra
        merged_sarif_data = {
            "$schema": zap_data.get("$schema", "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"),
            "version": zap_data.get("version", "2.1.0"),
            "runs": []
        }

        merged_run = {
            "results": [],
            "taxonomies": [],
            "tool": {
                "driver": {
                    "name": "Merged Report Driver",
                    "rules": []
                }
            }
        }


        # 3. Hợp nhất runs.taxonomies: ZAP trước, Wapiti sau (và xử lý trùng lặp)
        unique_taxonomies = {}

        if zap_run.get("taxonomies"):
            for tax in zap_run["taxonomies"]:
                if tax.get("name"):
                    unique_taxonomies[tax["name"]] = tax
        
        if wapiti_run.get("taxonomies"):
            for tax in wapiti_run["taxonomies"]:
                if tax.get("name") and tax["name"] not in unique_taxonomies:
                    unique_taxonomies[tax["name"]] = tax
                elif tax.get("name") and tax["name"] in unique_taxonomies:
                    existing_taxa_ids = {t.get('id') for t in unique_taxonomies[tax["name"]].get('taxa', [])}
                    for wapiti_taxa in tax.get('taxa', []):
                        if wapiti_taxa.get('id') not in existing_taxa_ids:
                            unique_taxonomies[tax["name"]].get('taxa', []).append(wapiti_taxa)
                            
        merged_run["taxonomies"] = list(unique_taxonomies.values())
        for tax in merged_run["taxonomies"]:
            if tax.get('taxa'):
                tax['taxa'].sort(key=lambda x: x.get('id', ''))

        # 4. Hợp nhất runs.tool.driver (rules): ZAP trước, Wapiti sau
        if zap_run.get("tool", {}).get("driver", {}).get("rules"):
            merged_run["tool"]["driver"]["rules"].extend(zap_run["tool"]["driver"]["rules"])
        
        zap_rule_ids = {r.get('id') for r in zap_run.get("tool", {}).get("driver", {}).get("rules", [])}
        
        if wapiti_run.get("tool", {}).get("driver", {}).get("rules"):
            for wapiti_rule in wapiti_run["tool"]["driver"]["rules"]:
                original_wapiti_rule_id = wapiti_rule.get('id')
                if original_wapiti_rule_id in zap_rule_ids:
                    wapiti_rule['id'] = f"wapiti-merged-{original_wapiti_rule_id}-{uuid.uuid4().hex[:4]}"
                    print(f"⚠️ Cảnh báo: Rule ID '{original_wapiti_rule_id}' trùng lặp. Đã đổi tên thành '{wapiti_rule['id']}'. "
                          f"Các results của Wapiti cần được cập nhật để trỏ đến ID mới này.")

                merged_run["tool"]["driver"]["rules"].append(wapiti_rule)

        merged_sarif_data["runs"].append(merged_run)


        # 5. Hợp nhất runs.results: ZAP trước, Wapiti sau
        seen = {}
        CWE_mapping = build_mapping_id_to_CWE(merged_run["tool"]["driver"]["rules"])

        if zap_run.get("results") or wapiti_run.get("results"):
            add_merge_result(zap_run["results"], wapiti_run["results"], CWE_mapping, merged_run)

        # 6. Ghi báo cáo SARIF đã hợp nhất vào tệp đầu ra
        with open(output_sarif_filepath, 'w', encoding='utf-8') as f:
            json.dump(merged_sarif_data, f, indent=2, ensure_ascii=False)

        print(f"✅ Đã hợp nhất thành công từ '{zap_sarif_filepath}' và dữ liệu Wapiti trong bộ nhớ")
        print(f"   và lưu vào '{output_sarif_filepath}'")

    except FileNotFoundError as e:
        print(f"❌ Lỗi: Không tìm thấy tệp đầu vào ZAP: {e}")
    except json.JSONDecodeError as e:
        print(f"❌ Lỗi: Không thể phân tích cú pháp tệp JSON của ZAP. Đảm bảo tệp hợp lệ: {e}")
    except KeyError as e:
        print(f"❌ Lỗi: Cấu trúc tệp SARIF của ZAP không như mong đợi (thiếu khóa: {e}).")
    except Exception as e:
        print(f"❌ Đã xảy ra lỗi không mong muốn khi hợp nhất: {e}")




def normalize_url(url: str) -> str:
    url = url.replace("\\","")
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

VULN_PATTERNS: Dict[str, List[str]] = {
    # XSS (reflected/DOM): thẻ script, handler, URL JS, event
    "XSS": [
        r"<\s*script\b", r"%3c\s*script", r"javascript\s*:", r"data\s*:\s*text/html",
        r"onerror\s*=", r"onload\s*=", r"onmouseover\s*=", r"onfocus\s*=", r"onclick\s*=",
        r"<\s*img\b.*onerror\s*=", r"<\s*svg\b.*onload\s*=", r"</\s*script\s*>",
        r"document\s*\.", r"window\s*\.", r"eval\s*\(", r"setTimeout\s*\(", r"Function\s*\(",
    ],

    # SQL injection: các chuỗi hay gặp; có cả URL-encoded
    "SQLi": [
        r"(?<!\w)union\s+select(?!\w)", r"(?<!\w)or\s+1\s*=\s*1(?!\w)", r"(?<!\w)and\s+1\s*=\s*1(?!\w)",
        r"(?<!\w)or\b.+\b=\b", r"(?<!\w)and\b.+\b=\b", r"\'\s*or\s*\'", r"\"\s*or\s*\"",
        r"\bwaitfor\s+delay\b", r"\bsleep\s*\(", r"\bdatabase\(\)", r"\bversion\(\)", r"\bextractvalue\s*\(",
        r"%27", r"%22", r"%2d%2d", r"--\s", r";\s*shutdown", r";\s*drop\b", r"\bxp_cmdshell\b",
    ],

    # Path traversal / LFI/RFI
    "PathTraversal": [
        r"\.\./", r"\.\.\\", r"\.\.\/", r"\.\.\\\\", r"%2e%2e%2f", r"%2e%2e%5c",
        r"%252e%252e%252f", r"%c0%ae%c0%ae%c0%af", r"%u002e%u002e%u002f",
        r"/etc/passwd", r"/etc/shadow", r"/windows/win.ini", r"/boot.ini",
        r"proc/self/environ", r"usr/bin/passwd",
        r"(?:file|ftp|php|jar|gopher|dict|tftp|ldap|ldaps):\/\/",
        r"\x00", r"%00"
    ],

    # Command Injection (OS)
    "CommandInjection": [
        r";\s*\w+", r"\|\s*\w+", r"&&\s*\w+", r"\$\(", r"`.*?`",
        r"%26%26", r"%7c", r"\bcat\s+/etc/passwd\b", r"\bwget\s+http",
    ],

    # SSRF (URL-scheme + nội bộ)
    "SSRF": [
        r"(?:http|https|ftp|file|gopher|dict|ldap|ldaps|tftp):\/\/",
        r"\b(127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d+\.\d+|localhost|::1)\b",
        r"\b169\.254\.169\.254\b",  # AWS metadata
    ],

    # LDAP Injection
    "LDAPi": [
        r"\(\|\)", r"\(\&\)", r"\(\!\)", r"\(\w+=\*\)", r"\(\w+=\*.+\*\)",
        r"\*\)\s*\(",  # close-and-open condition
    ],

    # NoSQL Injection (Mongo-like)
    "NoSQLi": [
        r"\$ne\b", r"\$gt\b", r"\$lt\b", r"\$in\b", r"\$regex\b", r"\{\s*\$",
    ],

    # XXE (tải external entity trong XML)
    "XXE": [
        r"<!DOCTYPE\s", r"<!ENTITY\s", r"system\s+['\"]file:", r"system\s+['\"]http",
    ],

    # Open Redirect
    "OpenRedirect": [
        r"(?:^|[?&])(url|next|target|redir|redirect|dest|destination)=https?%3a%2f%2f",
        r"(?:^|[?&])(url|next|target|redir|redirect|dest|destination)=https?://",
        r"(?:^|[?&])(url|next|target|redir|redirect|dest|destination)=//",  # schemaless
    ],

    # Header Injection / CRLF
    "CRLF": [
        r"%0d%0a", r"\r\n", r"%0a", r"%0d"
    ],
}

# Pre-compile
VULN_REGEX: Dict[str, List[re.Pattern]] = {
    k: [re.compile(p, re.IGNORECASE) for p in pats]
    for k, pats in VULN_PATTERNS.items()
}

def detect_payload_types(value: str) -> Set[str]:
    """Trả về tập các loại lỗ hổng mà value 'ngửi thấy'."""
    print(f"   [Payload tìm thấy] {value}")
    if value is None:
        return set()
    s = value if isinstance(value, str) else str(value)
    types = set()
    for vtype, regs in VULN_REGEX.items():
        for rg in regs:
            if rg.search(s):
                print(f"   [Payload] {s} | {vtype}")
                types.add(vtype)
                break
    return types

def get_param_from_url(url: str) -> Tuple[str, Set[str], str]:
    """
    Trả về: (param_name | 'None', {types}, raw_value | '')
    - Nếu nhiều param trúng: trả cái đầu tiên
    """
    if not url:
        return "None", set(), ""
    url = url.replace("\\", "")
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    for key, vals in qs.items():
        for raw in vals:
            types = detect_payload_types(raw)
            if types:
                return key, types, raw
    return "None", set(), ""


def build_mapping_id_to_CWE(rules) -> dict:
    """
    Xây dựng bản đồ từ ID quy tắc đến CWE từ rules.
    """
    mapping = {}
    for rule in rules:
        rule_id = rule.get('id')
        cwe_id = None

        for rel in rule.get("relationships", []):
            target = rel.get("target",{})
            if target.get("toolComponent",{}).get("name", "") == "CWE":
                cwe_id = target.get("id")
                break
        if cwe_id:
            mapping[rule_id] = cwe_id
    return mapping


def build_corr_key(url: str, cwe: str) -> str:
    """
    Xây dựng khóa tương ứng cho một URL và ID CWE.
    """
    url_norm = normalize_url(url)
    param = get_param_from_url(url)
    cwe = f"CWE-{cwe}"
    if param[0] == "None":
        param = url_norm.split("/")[-1]
        return f"{url_norm}::{cwe}::{param}"
    
    return f"{url_norm}::{cwe}::{param[0]}"





# --- helpers gọn để lấy trường từ result ---
def _first_location(result: dict) -> dict:
    locs = result.get("locations") or []
    return locs[0] if locs else {}

def _get_uri_from_result(result: dict) -> str:
    return (
        _first_location(result)
        .get("physicalLocation", {})
        .get("artifactLocation", {})
        .get("uri", "")
    )

def _get_startline_from_result(result: dict):
    region = (
        _first_location(result)
        .get("physicalLocation", {})
        .get("region", {})
    )
    return region.get("startLine")

def _get_snippet_from_result(result: dict) -> str:
    region = (
        _first_location(result)
        .get("physicalLocation", {})
        .get("region", {})
    )
    snip = region.get("snippet", {}) if isinstance(region, dict) else {}
    return snip.get("text", "")

def _get_attack_from_result(result: dict):
    loc = _first_location(result)
    phys = loc.get("physicalLocation", {}) if isinstance(loc, dict) else {}
    if isinstance(phys.get("properties"), dict):
        if "attack" in phys["properties"]:
            return phys["properties"]["attack"]
        if "attack_parameter" in phys["properties"]:
            return phys["properties"]["attack_parameter"]
    if isinstance(loc.get("properties"), dict):
        if "attack" in loc["properties"]:
            return loc["properties"]["attack"]
        if "attack_parameter" in loc["properties"]:
            return loc["properties"]["attack_parameter"]
    return None

def _ensure_props_maps(tgt_result: dict):
    """Tạo sẵn các map trong properties nếu chưa có."""
    props = tgt_result.setdefault("properties", {})
    props.setdefault("sources", [])
    props.setdefault("levels", {})
    props.setdefault("messages", {})
    props.setdefault("uris", {})
    props.setdefault("startLines", {})
    props.setdefault("snippets", {})
    props.setdefault("attacks", {})
    props.setdefault("altRuleIds", [])
    return props

def _use_as_canonical_location(tgt_result: dict, src_result: dict):
    """Dùng location của src_result làm location duy nhất của tgt_result."""
    loc = _first_location(src_result)
    # làm sạch 'source' trong location.properties nếu có
    if isinstance(loc.get("properties"), dict) and "source" in loc["properties"]:
        loc = dict(loc)
        loc["properties"] = dict(loc["properties"])
        loc["properties"].pop("source", None)
    tgt_result["locations"] = [loc]



#--- helper để merge phần result ---
def add_merge_result(zap_results, wapiti_results, CWE_mapping: dict, merged_run):
    corr_key_map = {}
    for tool_name, results in [("ZAP", zap_results), ("Wapiti", wapiti_results)]:
        for r in results:
            uri = _get_uri_from_result(r)
            rule_id = r.get("ruleId", "Unknown")
            cwe = CWE_mapping.get(rule_id, rule_id)
            corr_key = build_corr_key(uri, cwe)
            corr_key_map.setdefault(corr_key, []).append((tool_name, r))

    for corr_key, items in corr_key_map.items():
        if len(items) == 1:
            tool_name, r = items[0]
            props = _ensure_props_maps(r)
            props["sources"].append(tool_name)
            merged_run["results"].append(r)
        else:
            # Có nhiều hơn 1 item, kiểm tra xem có phải là trùng giữa 2 tool không
            tools_involved = set(tool_name for tool_name, r in items)
            
            if len(tools_involved) == 2 and "ZAP" in tools_involved and "Wapiti" in tools_involved:
                # Đúng là trùng giữa ZAP và Wapiti
                # Lấy 1 item từ mỗi tool (item đầu tiên của mỗi tool)
                zap_item = next((tool, r) for tool, r in items if tool == "ZAP")
                wapiti_item = next((tool, r) for tool, r in items if tool == "Wapiti")
                
                tool1, r1 = zap_item
                tool2, r2 = wapiti_item
                
                # print(f"Debug: Cross-tool duplicate found: {corr_key}")
                # print(f"  {tool1} - {r1.get('ruleId', 'Unknown')}")
                # print(f"  {tool2} - {r2.get('ruleId', 'Unknown')}")
                
                loc1 = _first_location(r1)
                loc2 = _first_location(r2)
                
                result_entry = {
                    "level": [f"{tool1} - {r1.get('level', 'note')}",
                             f"{tool2} - {r2.get('level', 'note')}"],
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": [f"{tool1} - {loc1.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')}",
                                           f"{tool2} - {loc2.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')}"],
                                },
                                "region": {
                                    "startLine": [f"{tool1} - {loc1.get('physicalLocation', {}).get('region', {}).get('startLine', '')}",
                                                 f"{tool2} - {loc2.get('physicalLocation', {}).get('region', {}).get('startLine', '')}"],
                                    "snippet": {
                                        "text": [f"{tool1} - {loc1.get('physicalLocation', {}).get('region', {}).get('snippet', {}).get('text', '')}",
                                                f"{tool2} - {loc2.get('physicalLocation', {}).get('region', {}).get('snippet', {}).get('text', '')}"],
                                    }
                                }
                            },
                            "properties": {
                                "attack": [f"{tool1} - {loc1.get('properties', {}).get('attack', '')}",
                                          f"{tool2} - {loc2.get('properties', {}).get('attack', '')}"],
                                "curl_command": f"{tool2} - {loc2.get('properties', {}).get('curl_command', '')}",
                            }
                        }
                    ],
                    "message": {
                        "text": [f"{tool1} - {r1.get('message', {}).get('text', '')}",
                                f"{tool2} - {r2.get('message', {}).get('text', '')}"],
                    },
                    "ruleId": [f"{tool1} - {r1.get('ruleId', '')}",
                              f"{tool2} - {r2.get('ruleId', '')}"],
                    "webRequest": [f"{tool1} - {r1.get('webRequest', '')}",
                                   f"{tool2} - {r2.get('webRequest', '')}"],
                    "webResponse": [f"{tool1} - {r1.get('webResponse', '')}",
                                    f"{tool2} - {r2.get('webResponse', '')}"]
                }
                merged_run["results"].append(result_entry)
            else:
                # Trùng lặp trong cùng 1 tool hoặc có >2 tools, thêm từng cái riêng biệt
                # print(f"Debug: Same-tool duplicates or unexpected case: {corr_key}")
                for tool_name, r in items:
                    # print(f"  {tool_name} - {r.get('ruleId', 'Unknown')}")
                    props = _ensure_props_maps(r)
                    props["sources"].append(tool_name)
                    merged_run["results"].append(r)

            
            
