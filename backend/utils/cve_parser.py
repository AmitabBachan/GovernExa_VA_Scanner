import json
import os

def get_cve_details(cve_id: str) -> dict:
    """
    Parses a CVE-YYYY-NNNN string, finds the corresponding JSON in /cves/,
    and extracts Title, CVSS Score, Description, and Reference along with advanced fields.
    """
    default_data = {
        "title": "Title not available",
        "cvss_score": "N/A",
        "description": "No description available in local CVE repository.",
        "reference": None,
        "cwe": "N/A",
        "cvss_vector": "N/A",
        "cvss_version": "N/A",
        "cna_name": "Unknown",
        "published": "Unknown",
        "updated": "Unknown",
        "versions": [],
        "all_references": [],
        "solution": None,
        "workaround": None,
        "cvss_severity": "Unknown"
    }
    
    try:
        parts = cve_id.split("-")
        if len(parts) < 3:
            return default_data
            
        year = parts[1]
        sequence = parts[2]
        
        # Calculate folder name: '4437' -> '4xxx', '40001' -> '40xxx'
        if len(sequence) >= 4:
            folder_prefix = sequence[:-3]
            folder_name = f"{folder_prefix}xxx"
        else:
            folder_name = "0xxx"
            
        file_path = f"/cves/{year}/{folder_name}/{cve_id}.json"
        
        if not os.path.exists(file_path):
            return default_data
            
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        meta = data.get("cveMetadata", {})
        default_data["published"] = meta.get("datePublished", "Unknown")[:10] if meta.get("datePublished") else "Unknown"
        default_data["updated"] = meta.get("dateUpdated", "Unknown")[:10] if meta.get("dateUpdated") else "Unknown"
        
        # We try to format assigner properly or fallback
        cna_raw = meta.get("assignerShortName", "Unknown").replace("_", " ").title()
        if cna_raw.lower() == "redhat": cna_raw = "Red Hat, Inc."
        default_data["cna_name"] = cna_raw
        
        cna = data.get("containers", {}).get("cna", {})
        
        default_data["title"] = cna.get("title", default_data["title"])
        
        # Extract CVSS
        metrics = cna.get("metrics", [])
        for metric in metrics:
            for cvss_key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if cvss_key in metric:
                    default_data["cvss_score"] = metric[cvss_key].get("baseScore", default_data["cvss_score"])
                    default_data["cvss_vector"] = metric[cvss_key].get("vectorString", default_data["cvss_vector"])
                    default_data["cvss_version"] = metric[cvss_key].get("version", cvss_key.replace("cvssV", "").replace("_", "."))
                    default_data["cvss_severity"] = metric[cvss_key].get("baseSeverity", default_data.get("cvss_severity", "Unknown"))
                    break
                    
        # Extract description
        descriptions = cna.get("descriptions", [])
        if descriptions:
            default_data["description"] = descriptions[0].get("value", default_data["description"])
            
        # Extract CWE
        problem_types = cna.get("problemTypes", [])
        if problem_types:
            cwe_descs = problem_types[0].get("descriptions", [])
            if cwe_descs:
                cwe_id = cwe_descs[0].get("cweId", "")
                cwe_desc = cwe_descs[0].get("description", "")
                if cwe_id and cwe_desc:
                    default_data["cwe"] = f"{cwe_id}: {cwe_desc}"
                else:
                    default_data["cwe"] = cwe_id or cwe_desc
                    
        # Extract structured affected products
        affected = cna.get("affected", [])
        affected_products = []
        for a in affected:
            vendor = a.get("vendor", "Unknown")
            product = a.get("product", a.get("packageName", "Unknown"))
            
            versions_list = a.get("versions", [])
            if not versions_list:
                affected_products.append({
                    "vendor": vendor,
                    "product": product,
                    "version": "N/A",
                    "status": a.get("defaultStatus", "unknown")
                })
            else:
                for v in versions_list:
                    if "version" in v:
                        status = v.get("status", "unknown")
                        val = v["version"]
                        affected_products.append({
                            "vendor": vendor,
                            "product": product,
                            "version": val,
                            "status": status
                        })
        default_data["affected_products"] = affected_products
            
        # Extract references
        refs = cna.get("references", [])
        default_data["all_references"] = refs
        if refs:
            default_data["reference"] = refs[0].get("url")
            
        # Extract solutions and workarounds
        solutions = cna.get("solutions", [])
        if solutions:
            default_data["solution"] = solutions[0].get("value", "")
            
        workarounds = cna.get("workarounds", [])
        if workarounds:
            default_data["workaround"] = workarounds[0].get("value", "")
            
        return default_data
        
    except Exception as e:
        print(f"Error parsing CVE details for {cve_id}: {e}")
        return default_data
