#EXTERNAL IMPORTS
import warnings
import json
import argparse
from sys import exit
import pandas as pd

#INTERNAL IMPORTS
import api

warnings.simplefilter(action='ignore', category=UserWarning)
warnings.simplefilter(action='ignore', category=ResourceWarning)

ig1_color = '#74AA50'
ig2_color = '#DB8906'
ig3_color = '#00A3AD'

navigator_json = {
	"name": "CIS Controls Mapped to Attack",
	"versions": {
		"attack": "13",
		"navigator": "4.8.2",
		"layer": "4.4"
	},
	"domain": "enterprise-attack",
	"description": "",
	"filters": {
		"platforms": [
			"Linux",
			"macOS",
			"Windows",
			"Network",
			"PRE",
			"Containers",
			"Office 365",
			"SaaS",
			"Google Workspace",
			"IaaS",
			"Azure AD"
		]
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": False,
		"showName": True,
		"showAggregateScores": False,
		"countUnscored": False
	},
	"hideDisabled": False,
	"techniques": [],
	"gradient": {
		"colors": [
			"#ff6666ff",
			"#ffe766ff",
			"#8ec843ff"
		],
		"minValue": 0,
		"maxValue": 100
	},
		"legendItems": [
		{
			"label": "Implementation Group 1",
			"color": "#74AA50"
		},
		{
			"label": "Implementation Group 2",
			"color": "#DB8906"
		},
        {
			"label": "Implementation Group 3",
			"color": "#00A3AD"
		}
	],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": False,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": True,
	"selectSubtechniquesWithParent": False
}

technique_json_template = {
			"techniqueID": None,
			"color": None,
			"comment": None,
			"enabled": True,
			"metadata": [],
			"links": [
                {
					"label": "Fortra",
					"url": "https://www.fortra.com"
				},
                {
					"label": "Tripwire",
					"url": "https://www.tripwire.com"
				}
            ],
			"showSubtechniques": False
		}

welcome = 'Map CIS and ATT&CK Content!'

parser = argparse.ArgumentParser(description = welcome)
parser.add_argument('-f', '--file', dest='filename', help='Input Filename')
parser.add_argument('-o', '--out', dest='outfile', help='Output filename (default: attack_layer.json).')
parser.add_argument('-l', '--license', dest='license_file', help='CIS SecureSuite License File')
parser.add_argument('-b', '--benchmark', dest='benchmark_id', help='CIS Benchmark ID')
parser.add_argument('-1', '--can', dest='generate_can', action='store_true', help='Generate a json file that maps CIS Critical Security Controls to MITRE ATT&CK for ATT&CK Navigator')
parser.add_argument('-2', '--ban', dest='generate_ban', action='store_true', help='Generate a json file that maps a CIS Benchmark to MITRE ATT&CK for ATT&CK Navigator')

def error(msg):
    print(msg)
    exit(-1)

def get_min_ig(ig1, ig2):
    if ig1:
        return 1
    elif ig2:
        return 2
    else:
        return 3

def get_ig_color(ig):
    match ig:
        case 1:
            return ig1_color
        case 2:
            return ig2_color
        case 3:
            return ig3_color

def map_safeguard_to_attack(filename):
    mapped_data = {}
    xlsx = pd.ExcelFile(filename)
    dfs = pd.read_excel(xlsx, sheet_name='V8-ATT&CK Low (Sub-)Techniques')
    for index in range(dfs.index.stop):
        data_dict = {
            'ID'                :   dfs.at[index, 'ATT&CK Technique ID'],
            'Sub ID'            :   dfs.at[index, 'Combined ATT&CK (Sub-)Technique ID'],
            'IG1'               :   True if isinstance(dfs.at[index, 'IG1'], str) else False,
            'IG2'               :   True if isinstance(dfs.at[index, 'IG2'], str) else False,
            'IG3'               :   True if isinstance(dfs.at[index, 'IG3'], str) else False,
            'Title'             :   dfs.at[index, 'Title'],
            'Security Function' :   dfs.at[index, 'Security Function']
        }
        if not isinstance(data_dict['ID'], str):
            continue
        try:
            mapped_data[dfs.at[index, 'CIS Safeguard']].append(data_dict)
        except KeyError:
            mapped_data[dfs.at[index, 'CIS Safeguard']] = [data_dict]
    return mapped_data

def process_group(data):
    processed_data = []
    if 'Rules' in data:
        for rule in data['Rules']:
            if 'Rule' in rule and 'metadata' in rule['Rule'] and 'framework' in rule['Rule']['metadata'] and 'safeguard' in rule['Rule']['metadata']['framework']:
                title = rule['Rule']['title']
                for control in (rule['Rule']['metadata']['framework']['safeguard']):
                    if ':8.0:' in control['urn']:
                        control_list = control['urn'].split(':')
                        control_value = control_list[-2] + '.' + control_list[-1]
                        processed_data.append((title, control_value))
    elif 'Groups' in data:
        for group in data['Groups']:
            if 'Group' in group:
                processed_data.extend(process_group(group['Group']))
            elif 'Rules' in group:
                processed_data.extend(process_group(group))
    return processed_data

def map_benchmark_to_safeguard(benchmark_id, license_file):
    processed_data = []
    benchmark = json.loads(api.get_benchmark(benchmark_id, license_file = license_file))
    if 'Benchmark' not in benchmark:
        error('Benchmark Document does not contain Benchmark Section.')
    if 'Guidelines' not in benchmark['Benchmark']:
        error('Benchmark Document does not contain Guidelines Section.')
    title = benchmark['Benchmark']['title']
    for section in benchmark['Benchmark']['Guidelines']:
        if 'Group' in section: 
            processed_data.extend(process_group(section['Group']))
    return title, processed_data

def parse_safeguard_to_attack_mapping(safeguard_to_attack, benchmark_data = None):
    techniques = {}
    for safeguard, safeguard_data in safeguard_to_attack.items():
        if not benchmark_data or str(safeguard) in benchmark_data.keys():
            for items in safeguard_data:
                if (items['Sub ID']) not in techniques:
                    techniques[items['Sub ID']] = {}
                    techniques[items['Sub ID']]['IG'] = get_min_ig(items['IG1'], items['IG2'])
                    techniques[items['Sub ID']]['metadata'] = [
                        {
                            'name'  :   f'{safeguard} (IG{techniques[items["Sub ID"]]["IG"]})',
                            'value' :   f'{items["Title"]} ({items["Security Function"]})'
                        }
                    ]
                else:
                    new_min_ig = get_min_ig(items['IG1'], items['IG2'])
                    if techniques[items['Sub ID']]['IG'] > new_min_ig:
                        techniques[items['Sub ID']]['IG'] = new_min_ig
                    techniques[items['Sub ID']]['metadata'].extend([
                        {
                            'name'  :   f'{safeguard} (IG{techniques[items["Sub ID"]]["IG"]})',
                            'value' :   f'{items["Title"]} ({items["Security Function"]}'
                        }
                    ])
                if benchmark_data:
                    for title in benchmark_data[str(safeguard)]:
                        techniques[items['Sub ID']]['metadata'].extend([
                            {
                                'name'  :   'Benchmark Rule',
                                'value' :   f'{title}'
                            }
                        ])

    return techniques

def parse_benchark_to_safeguard_mapping(benchmark_to_safeguard):
    results = {}
    for title, control in benchmark_to_safeguard:
        if control not in results:
            results[control] = [title]
        else:
            results[control].append(title)
    return results

def generate_controls_to_attack_json(filename, outfile = 'attack_layer.json', benchmark_data = None, title = None):
    safeguard_to_attack = map_safeguard_to_attack(filename)
    techniques = parse_safeguard_to_attack_mapping(safeguard_to_attack, benchmark_data = benchmark_data)
    for key in techniques.keys():
        temp_json_techniques = technique_json_template.copy()
        temp_json_techniques['techniqueID'] = key
        temp_json_techniques['color'] = get_ig_color(techniques[key]['IG'])
        temp_json_techniques['metadata'] = techniques[key]['metadata']
        navigator_json['techniques'].append(temp_json_techniques)
    if title:
        navigator_json['name'] = title
    with open(outfile, 'w') as fh:
        json.dump(navigator_json, fh)


if __name__ == '__main__':
    args = parser.parse_args()
    if args.generate_can:
        if not args.filename:
            error('File with CIS Critical Security Controls to ATT&CK Mapping required.')
        if args.outfile:    
            generate_controls_to_attack_json(args.filename, outfile = args.outfile)
        else:
            generate_controls_to_attack_json(args.filename)
    if args.generate_ban:
        if not args.filename:
            error('File with CIS Critical Security Controls to ATT&CK Mapping required.')
        elif not args.license_file:
            error('CIS SecureSuite License required to obtain Benchmark document.')
        elif not args.benchmark_id:
            error('CIS Benchmark ID required.')
        title, controls_list = map_benchmark_to_safeguard(args.benchmark_id, args.license_file)
        parsed_controls = parse_benchark_to_safeguard_mapping(controls_list)
        if args.outfile:
            generate_controls_to_attack_json(args.filename, outfile = args.outfile, benchmark_data = parsed_controls, title = title)
        else:
            generate_controls_to_attack_json(args.filename, benchmark_data = parsed_controls, title = title)
