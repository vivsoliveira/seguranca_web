from flask import Flask, render_template, request, jsonify
import sys
from pathlib import Path
import json
from datetime import datetime
import threading

sys.path.insert(0, str(Path(__file__).parent))
from scanner import WebScanner, get_incremental_filename
from report_generator import ReportGenerator

app = Flask(__name__)

scan_results = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL é obrigatória'}), 400
    
    scan_id = datetime.now().strftime('%Y%m%d%H%M%S')
    
    scan_results[scan_id] = {
        'status': 'scanning',
        'url': url,
        'start_time': datetime.now().isoformat()
    }
    
    def run_scan():
        try:
            scanner = WebScanner(url)
            scanner.scan()
            
            generator = ReportGenerator(
                scanner.vulnerabilities,
                url,
                scanner.get_scan_duration()
            )
            
            report_json = generator.generate_json_report()
            report_dict = json.loads(report_json)
            
            filepath = get_incremental_filename(url, 'json')
            generator.save_report(filepath)
            
            scan_results[scan_id] = {
                'status': 'completed',
                'url': url,
                'report': report_dict,
                'filepath': filepath,
                'end_time': datetime.now().isoformat()
            }
        except Exception as e:
            scan_results[scan_id] = {
                'status': 'error',
                'url': url,
                'error': str(e),
                'end_time': datetime.now().isoformat()
            }
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/status/<scan_id>')
def status(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan não encontrado'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/reports')
def list_reports():
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)
    
    reports = []
    for file in reports_dir.glob('*.json'):
        if file.name.startswith('batch_'):
            continue
        
        reports.append({
            'filename': file.name,
            'size': file.stat().st_size,
            'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat()
        })
    
    reports.sort(key=lambda x: x['modified'], reverse=True)
    return jsonify(reports)

if __name__ == '__main__':
    print("Iniciando scanner...")
    print("Acesse: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)