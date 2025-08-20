import uuid
import re
from urllib.parse import unquote_plus

def _build_wstg_taxonomy_entry(wstg_ids: set) -> dict:
    wstg_taxonomy = {
        "downloadUri": "https://owasp.org/www-project-web-security-testing-guide/stable/",
        "guid": str(uuid.uuid4()),
        "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
        "isComprehensive": False,
        "language": "en",
        "name": "OWASP WSTG",
        "organization": "OWASP",
        "shortDescription": {"text": "The OWASP Web Security Testing Guide (WSTG)."},
        "taxa": []
    }

    wstg_uri_map = {
        "WSTG-CONF-04": "02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html",
        "WSTG-ATHN-07": "04-Authentication_Testing/07-Testing_for_Weak_Password_Policy.html",
        "WSTG-INPV-15": "07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling.html",
        "WSTG-CONF-12": "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy.html",
        "OSHP-Content-Security-Policy": "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy.html", 
        "WSTG-SESS-05": "06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery.html",
        "WSTG-CONF-01": "02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration.html",
        "WSTG-INPV-12": "07-Input_Validation_Testing/12-Testing_for_Command_Injection.html",
        "WSTG-ATHZ-01": "05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.html", 
        "WSTG-INFO-08": "01-Information_Gathering/08-Fingerprint_Web_Application_Framework.html",
        "WSTG-INFO-02": "01-Information_Gathering/02-Fingerprint_Web_Server.html",
        "WSTG-CONF-06": "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.html",
        "WSTG-CLNT-03": "11-Client_Side_Testing/03-Testing_for_HTML_Injection.html",
        "OSHP-X-Frame-Options": "11-Client-side_Testing/09-Testing_for_Clickjacking.html",
        "WSTG-CONF-07": "02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security.html",
        "OSHP-HTTP-Strict-Transport-Security": "02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security.html",
        "OSHP-X-Content-Type-Options": "02-Configuration_and_Deployment_Management_Testing/13-Test_for_MIME_Type_Sniffing.html", 
        "WSTG-SESS-02": "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html",
        "WSTG-CRYP-03": "09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels.html",
        "WSTG-INPV-06": "07-Input_Validation_Testing/06-Testing_for_LDAP_Injection.html", 
        "WSTG-INPV-11": "07-Input_Validation_Testing/11-Testing_for_Code_Injection.html", 
        "WSTG-CLNT-04": "11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect.html",
        "WSTG-INPV-01": "07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html",
        "WSTG-INPV-05": "07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html", 
        "WSTG-CRYP-01": "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection.html",
        "WSTG-INPV-19": "07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery.html",
        "WSTG-INPV-02": "07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.html",
        "WSTG-CONF-10": "02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover.html",
        "WSTG-BUSL-08": "10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types.html",
        "WSTG-ERRH-01": "08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.html", 
        "WSTG-INFO-03": "01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage.html",
    }
    
    for wstg_id in sorted(list(wstg_ids)):
        help_uri = "https://owasp.org/www-project-web-security-testing-guide/stable/UNMAPPED.html" 
        mapped_path = wstg_uri_map.get(wstg_id, None)

        if mapped_path:
            if wstg_id in ["OSHP-X-Content-Type-Options"]:
                help_uri = "https://owasp.org/www-community/attacks/MIME_sniffing.html" 
            elif wstg_id in ["OSHP-X-Frame-Options"]:
                help_uri = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking.html"
            else:
                help_uri = f"https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/{mapped_path}"
        else:
            match = re.match(r"(WSTG|OSHP)-(\w+)-(\d+)", wstg_id)
            if match:
                prefix = match.group(1)
                category_code = match.group(2)
                number = match.group(3).zfill(2)
                
                general_category_map = {
                    "INFO": "Information_Gathering", "CONF": "Configuration_and_Deployment_Management_Testing",
                    "ATHN": "Authentication_Testing", "SESS": "Session_Management_Testing",
                    "ATHZ": "Authorization_Testing", "INPV": "Input_Validation_Testing",
                    "ERRH": "Error_Handling", "CRYP": "Cryptography",
                    "BUSL": "Business_Logic_Testing", "CLNT": "Client-side_Testing",
                }
                path_segment = general_category_map.get(category_code, "General_Testing")
                help_uri = f"https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/{path_segment}/{number}-{wstg_id.lower().replace(prefix.lower() + '-', '').replace('-', '_')}.html"
                #help_uri = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/Input_Validation_Testing/05-inpv_05.html"

            
            if help_uri == "https://owasp.org/www-project-web-security-testing-guide/stable/UNMAPPED.html":
                print(f"⚠️ Cảnh báo: Không tìm thấy URI WSTG chính xác cho ID: {wstg_id}. Sử dụng URI mặc định.")


        wstg_taxonomy["taxa"].append({
            "guid": str(uuid.uuid4()),
            "helpUri": help_uri,
            "id": wstg_id
        })
    
    return wstg_taxonomy

def _build_cwe_taxonomy_entry(cwe_ids: set) -> dict:
    cwe_taxonomy = {
        "downloadUri": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "guid": str(uuid.uuid4()),
        "informationUri": "https://cwe.mitre.org/data/published/cwe_latest.pdf",
        "isComprehensive": False,
        "language": "en",
        "name": "CWE",
        "organization": "MITRE",
        "shortDescription": {"text": "The MITRE Common Weakness Enumeration."},
        "taxa": []
    }

    for cwe_id in sorted(list(cwe_ids)):
        cwe_number = cwe_id.replace("CWE-", "")
        help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        cwe_taxonomy["taxa"].append({
            "guid": str(uuid.uuid4()),
            "helpUri": help_uri,
            "id": cwe_number
        })
    return cwe_taxonomy

def wapiti_to_sarif_converter(wapiti_json_data: dict) -> dict:
    sarif_data = {
        "runs": [],
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
    }

    run_entry = {
        "results": [],
        "taxonomies": [],
        "tool": {
            "driver": {
                "name": "Wapiti",
                "informationUri": "https://wapiti.sourceforge.io/",
                "rules": []
            }
        }
    }

    wapiti_infos = wapiti_json_data.get("infos", {})
    target_base_uri = wapiti_infos.get("target", "https://example.com")
    run_entry["tool"]["driver"]["version"] = wapiti_infos.get("version", "Unknown Wapiti Version")

    rule_map = {} 
    all_unique_wstg_ids = set() 
    all_unique_cwe_ids = set()

    default_rule_id = "wapiti-general-finding" 
    
    classifications = wapiti_json_data.get("classifications", {})
    for classification_name, details in classifications.items():
        final_rule_id = f"wapiti-{classification_name.lower().replace(' ', '-')}"

        original_final_rule_id = final_rule_id
        while final_rule_id in rule_map:
            final_rule_id = f"{original_final_rule_id}-{uuid.uuid4().hex[:4]}" 
        
        rule_entry = {
            "id": final_rule_id,
            "name": classification_name,
            "fullDescription": {
                "text": details.get("desc", f"No description for {classification_name}.")
            },
            "properties": {
                "solution": details.get("sol", "No solution provided."),
                "references": []
            },
            "relationships": []
        }
        
        if "ref" in details and isinstance(details["ref"], dict):
            for ref_name, ref_uri in details["ref"].items():
                rule_entry["properties"]["references"].append({
                    "uri": ref_uri,
                    "text": ref_name 
                })
                cwe_match = re.search(r"cwe\.mitre\.org\/data\/definitions\/(\d+)\.html", ref_uri)
                if cwe_match:
                    cwe_id = f"CWE-{cwe_match.group(1)}"
                    # đã sửa
                    cwe_id = cwe_id.replace("CWE-", "")
                    all_unique_cwe_ids.add(cwe_id)
                    rule_entry["relationships"].append({
                        "target": { "toolComponent": {"name": "CWE"}, "id": cwe_id },
                        "kind": "relevant" 
                    })

        if "wstg" in details and details["wstg"]:
            wstg_list_for_rule = []
            if isinstance(details["wstg"], list):
                wstg_list_for_rule = details["wstg"]
            elif isinstance(details["wstg"], str):
                wstg_list_for_rule = [details["wstg"]]
            
            all_unique_wstg_ids.update(wstg_list_for_rule)
            
            for wstg_id_item in wstg_list_for_rule:
                rule_entry["relationships"].append({
                    "target": { "toolComponent": {"name": "OWASP WSTG"}, "id": wstg_id_item },
                    "kind": "relevant"
                })

        run_entry["tool"]["driver"]["rules"].append(rule_entry)
        rule_map[final_rule_id] = rule_entry 
    
    if default_rule_id not in [r["id"] for r in run_entry["tool"]["driver"]["rules"]]:
        run_entry["tool"]["driver"]["rules"].append({
            "id": default_rule_id,
            "name": "Wapiti General Finding",
            "fullDescription": {"text": "A general vulnerability or anomaly reported by Wapiti, or one without a specific classification in the report."}
        })


    all_findings = []
    vulnerabilities_section = wapiti_json_data.get("vulnerabilities", {})
    if isinstance(vulnerabilities_section, dict):
        for vuln_type_name, vuln_instances_list in vulnerabilities_section.items():
            if isinstance(vuln_instances_list, list):
                for instance in vuln_instances_list:
                    if isinstance(instance, dict):
                        instance["_wapiti_type_name"] = vuln_type_name
                        all_findings.append(instance)
                        if "wstg" in instance and instance["wstg"]:
                            if isinstance(instance["wstg"], list):
                                all_unique_wstg_ids.update(instance["wstg"])
                            elif isinstance(instance["wstg"], str):
                                all_unique_wstg_ids.add(instance["wstg"])

    anomalies_list = wapiti_json_data.get("anomalies", [])
    if isinstance(anomalies_list, list):
        for anomaly in anomalies_list:
            if isinstance(anomaly, dict):
                if "info" in anomaly and "error" in anomaly["info"].lower():
                    anomaly["_wapiti_type_name"] = "Internal Server Error"
                else:
                    anomaly["_wapiti_type_name"] = "Anomaly"
                all_findings.append(anomaly)
                if "wstg" in anomaly and anomaly["wstg"]:
                    if isinstance(anomaly["wstg"], list):
                        all_unique_wstg_ids.update(anomaly["wstg"])
                    elif isinstance(anomaly["wstg"], str):
                        all_unique_wstg_ids.add(anomaly["wstg"])

    if all_unique_wstg_ids:
        run_entry["taxonomies"].append(_build_wstg_taxonomy_entry(all_unique_wstg_ids))
    
    if all_unique_cwe_ids:
        run_entry["taxonomies"].append(_build_cwe_taxonomy_entry(all_unique_cwe_ids))

    for finding in all_findings:
        sarif_level = finding.get("level", 0) 

        found_rule_id = default_rule_id 
        type_name = finding.get("_wapiti_type_name", "")
        if type_name:
            potential_id_prefix = f"wapiti-{type_name.lower().replace(' ', '-')}"
            
            for r_obj in run_entry["tool"]["driver"]["rules"]:
                if r_obj["id"].startswith(potential_id_prefix):
                    found_rule_id = r_obj["id"]
                    break

        web_request = {}
        raw_request_text = finding.get("http_request", "")
        if raw_request_text:
            request_lines = raw_request_text.split('\n')
            
            req_protocol = "HTTP"
            req_version = "1.1"
            req_method = finding.get("method", "GET")
            req_target = finding.get("path", target_base_uri)
            req_headers = {}
            req_body_text = ""

            if request_lines:
                first_line_match = re.match(r"(\w+)\s+(\S+)\s+(HTTP\/(\d\.\d))", request_lines[0])
                if first_line_match:
                    req_method = first_line_match.group(1)
                    request_path_query = first_line_match.group(2)
                    req_protocol = first_line_match.group(3).split('/')[0]
                    req_version = first_line_match.group(4)

                    if not request_path_query.startswith(('http://', 'https://')):
                            parsed_base_uri = re.match(r"(https?:\/\/[^\/]+)", target_base_uri)
                            if parsed_base_uri:
                                req_target = parsed_base_uri.group(0) + request_path_query
                            else:
                                req_target = request_path_query
                    else:
                        req_target = request_path_query
                
                header_body_separator_found = False
                for line in request_lines[1:]:
                    if not line.strip():
                        header_body_separator_found = True
                        continue
                    
                    if not header_body_separator_found:
                        if ': ' in line:
                            header_name, header_value = line.split(': ', 1)
                            req_headers[header_name.strip()] = header_value.strip()
                    else:
                        req_body_text += line + '\n'
            
            web_request["protocol"] = req_protocol
            web_request["version"] = req_version
            web_request["target"] = req_target
            web_request["method"] = req_method
            web_request["headers"] = req_headers
            
            if req_body_text.strip():
                web_request["body"] = {"text": req_body_text.strip()}
            else:
                web_request["body"] = {}


        web_response = {
            "statusCode": finding.get("detail", {}).get("response", {}).get("status_code", 0),
            "reasonPhrase": "",
            "protocol": "HTTP",
            "version": "1.1",
            "headers": {}
        }

        raw_response_body = finding.get("detail", {}).get("response", {}).get("body", "")
        if raw_response_body:
            decoded_body = raw_response_body.replace("&#x2f;", "/").replace("&#x3a;", ":").replace("&#xa;", "\n").replace("&#x3b;", ";").replace("&#x3d;", "=")
            web_response["body"] = {"text": decoded_body}
        else:
            web_response["body"] = {}
        
        response_headers_list = finding.get("detail", {}).get("response", {}).get("headers", [])
        resp_headers_dict = {}
        for header_pair in response_headers_list:
            if isinstance(header_pair, list) and len(header_pair) == 2:
                resp_headers_dict[header_pair[0].strip()] = header_pair[1].strip()
        web_response["headers"] = resp_headers_dict

        # add
        url_artifact = find_artifact_location_uri(finding)
        payload = find_payload(url_artifact)

        result_entry = {
            "level": sarif_level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            # "uri": finding.get("path", target_base_uri)
                            "uri": url_artifact
                        },
                        "region": {
                            "startLine": find_start_line(payload, finding),

                            "snippet": {
                                "text": payload
                            }
                        }
                    },
                    "properties": {
                        "attack": payload
                    }
                    
                }
            ],
            "message": {
                "text": finding.get("info", "No information provided.")
            },
            "ruleId": found_rule_id
        }
        
        # result_entry_relationships = []
        
        # wstg_list_for_result = []
        # if "wstg" in finding and finding["wstg"]:
        #     if isinstance(finding["wstg"], list):
        #         wstg_list_for_result = finding["wstg"]
        #     elif isinstance(finding["wstg"], str):
        #         wstg_list_for_result = [finding["wstg"]]
            
        #     for wstg_id_item in wstg_list_for_result:
        #         result_entry_relationships.append({
        #             "target": {
        #                 "toolComponent": {"name": "OWASP WSTG"},
        #                 "id": wstg_id_item
        #             },
        #             "kind": "relevant"
        #         })
        
        # if result_entry_relationships:
        #     result_entry["relationships"] = result_entry_relationships


        if web_request:
            result_entry["webRequest"] = web_request
        if web_response["statusCode"] or web_response["headers"] or web_response["body"]:
            result_entry["webResponse"] = web_response

        run_entry["results"].append(result_entry)

    sarif_data["runs"].append(run_entry)
    return sarif_data


def find_artifact_location_uri(finding):
    curl = finding.get("curl_command","") or ""
    m1 = re.search(r'curl\s+(?:-[^\s]+\s+)*["\'](https?://[^"\']+)["\']', curl)
    url_dest = m1.group(1) if m1 else ""
    body_parts = re.findall(r'-(?:d|data(?:-raw|-binary)?)\s+(?:"([^"]*)"|\'([^\']*)\')', curl, flags=re.I)
    if url_dest and body_parts:
        req_body = "&".join((a or b) for a,b in body_parts if (a or b))
        return f"{url_dest}?{req_body}"
    return url_dest


# def find_payload(finding):
#     curl = finding.get("curl_command", "")
#     # m = re.search(r'-d\s+"([^"]+)"', curl)
#     # body = m.group(1) if m else ""
#     # pairs = body.split('&')
#     pairs = curl.split('&')
#     pattern = re.compile(r'(?i)(%3c|%3e|<|>|script|onerror|onload)')
#     payload_raw = None
#     for pair in pairs:
#         if "=" in pair:
#             key, val = pair.split("=", 1)
#         else:
#             key, val = pair, ""
#         if pattern.search(val):
#             payload_raw = val
#             break
#     return unquote_plus(payload_raw)
#     # return payload_raw

def find_payload(url_artifact):
    pairs = url_artifact.split("&")
    pattern = re.compile(r'(?i)(%3c|%3e|<|>|script|onerror|onload)')
    payload_raw = None
    for pair in pairs:
        if "=" in pair:
            key, val = pair.split("=", 1)
        else:
            key, val = pair, ""
        if pattern.search(val):
            payload_raw = val
            break
    return unquote_plus(payload_raw)

def find_start_line(payload, finding):
    body = finding.get("detail", {}).get("response", {}).get("body", "")
    lines = body.split('\n')
    for i, line in enumerate(lines):
        if payload in line:
            return i + 1
    return None
