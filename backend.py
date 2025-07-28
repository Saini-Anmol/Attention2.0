# --- In backend.py, find and replace these two functions ---

def find_exploit_for_cve(cve_id):
    """
    Searches for exploits using the security-db.io public API.
    """
    if not cve_id: return None
    try:
        # The API endpoint for searching by CVE
        api_url = f"https://security-db.io/api/v1/search?q=cve:{cve_id}"
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        
        # The API returns a list of results
        if data and isinstance(data, list) and len(data) > 0:
            formatted_results = []
            for exploit in data[:3]: # Limit to top 3
                # We extract the title and a link to the exploit
                formatted_results.append({
                    "title": exploit.get("title"),
                    "url": exploit.get("url")
                })
            return formatted_results
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error querying Exploit-DB API: {e}")
        return None

def handle_exploit_query(query, api_key):
    """
    Handles exploit queries by using the Exploit-DB API and formatting the results.
    """
    cve_id = find_cve_id(query)
    if not cve_id:
        return "Please provide a valid CVE ID (e.g., CVE-2016-5195) to search for exploits."

    exploit_data = find_exploit_for_cve(cve_id)
    
    if not exploit_data:
        return f"No public exploits found for **{cve_id}** in the public Exploit-DB API."

    # Build the response string using the API data
    response_lines = [f"**Public exploits found for {cve_id}:**\n"]
    for i, exploit in enumerate(exploit_data):
        response_lines.append(f"---\n**Exploit {i+1}: {exploit['title']}**\n")
        response_lines.append(f"You can view the details and code for this exploit here:\n{exploit['url']}")

    response_lines.append("\n---\n")
    response_lines.append("**Disclaimer:** This information is for educational and authorized security testing purposes only. Executing exploits against systems without explicit permission is illegal and unethical.")
    
    return "\n".join(response_lines)
