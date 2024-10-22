import json
import logging
import requests
from flask import Flask, render_template, request, jsonify

# Import your tool modules
from tools import abuseipdb, virustotal

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# System prompt for Ollama
system_prompt = "You are a highly knowledgeable cybersecurity analyst with expertise in threat intelligence, incident response, and risk assessment. Your role is to provide accurate, actionable insights based on provided cybersecurity data, reports, or logs.\n\n" 

f"**Instructions:**\n"
f"1. Analyze the given cybersecurity data, identifying potential threats, vulnerabilities, and any signs of malicious activity. Correlate findings from different sources such as VirusTotal, AbuseIPDB, and WHOIS to deliver a comprehensive overview.\n"
  
f"2. Summarize the findings clearly, categorizing any identified threats as 'malicious', 'suspicious', or 'clean'. Include relevant metrics and insights to inform decision-making.\n"

f"3. Offer brief recommendations for remediation or further investigation based on your analysis, but do not provide implementation steps or procedural instructions.\n"

f"4. Ensure your responses are concise, factual, and straightforward. Do not include any code snippets or instructions on how to interpret the data yourself. Focus solely on providing a detailed analysis and insights.\n"


# Function to interact with the local Ollama model API
def generate_ollama_response(ip_address, virustotal_results, abuseipdb_results, temperature=0):
    url = "http://localhost:11434/api/generate"
    headers = {"Content-Type": "application/json"}
    
    # Create the full prompt including the system prompt
    prompt = (
        f"{system_prompt}\n\n"
        f"Analyze the following cybersecurity data for potential threats:\n\n"

        f"**VirusTotal Results:**\n{json.dumps(virustotal_results, indent=2)}\n\n"
        f"**AbuseIPDB Results:**\n{json.dumps(abuseipdb_results, indent=2)}\n\n"
           
    )

    
    payload = {
        "model": "mistral",
        "prompt": prompt,
        "temperature": temperature
    }

    try:
        logging.debug(f"Sending prompt to model: {prompt}")
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
        # Collecting all fragments of the response
        response_lines = response.text.strip().split('\n')
        response_text = ''.join(
            [json.loads(line)["response"] for line in response_lines if line]
        )
        return response_text

    except (requests.RequestException, json.decoder.JSONDecodeError, KeyError) as e:
        logging.error(f"Error in generating response: {e}")
        return "Error generating response."

# Home route
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lookup', methods=['POST'])
def lookup_ip():
    ip_address = request.form.get('ip_address')
    if not ip_address:
        return jsonify({'error': 'No IP address provided'}), 400

    # Query the AbuseIPDB API
    abuseipdb_results = abuseipdb.query_ip(ip_address)
    # Query the VirusTotal API
    virustotal_results = virustotal.query_virustotal(ip_address)

    # Log the results for debugging
    logging.debug(f"AbuseIPDB Results: {abuseipdb_results}")
    logging.debug(f"VirusTotal Results: {virustotal_results}")

    # Return raw results for display
    return render_template('results.html', 
                           virustotal_results=virustotal_results, 
                           abuseipdb_results=abuseipdb_results,  
                           ip_address=ip_address)

@app.route('/perform_analysis', methods=['POST'])
def perform_analysis():
    ip_address = request.json.get('ip_address')  # Use request.json for JSON input

    if not ip_address:
        return jsonify({'error': 'No IP address provided'}), 400

    # Query the AbuseIPDB API again or reuse the previous results if necessary
    abuseipdb_results = abuseipdb.query_ip(ip_address)
    virustotal_results = virustotal.query_virustotal(ip_address)

    # Log the analysis initiation
    logging.debug(f"Performing analysis for IP: {ip_address}")

    # Generate analysis using Ollama
    analysis_response = generate_ollama_response(ip_address, virustotal_results, abuseipdb_results)

    return jsonify({'analysis': analysis_response})

if __name__ == '__main__':
    app.run(debug=True)
