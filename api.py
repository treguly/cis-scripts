import requests
import zipfile
import io
import json
from tabulate import tabulate


CISURL = 'https://workbench.cisecurity.org/api/vendor/v1'
LICENSE_EP = '/license'
BENCHMARK_EP = '/benchmarks'
PDF_EP = '/pdf'
CIS_HEADER = 'X-SecureSuite-Token'

class LicenseError(Exception):
    '''Raised when no license informaiton is provided'''
    pass

def get_token(license_file):
    with open(license_file) as license:
        token = requests.post(f'{CISURL}{LICENSE_EP}', data = license).json()['token']

    return token

def get_benchmarks():
    benchmark_list = []
    benchmark_list_raw = requests.get(f'{CISURL}{BENCHMARK_EP}').json()
    for benchmark in benchmark_list_raw['Benchmarks']:
        benchmark_list.append((benchmark['workbenchId'], benchmark['benchmarkTitle'], benchmark['platformId'], benchmark['benchmarksUrl']))        
    return benchmark_list

def get_benchmark(id, format = 'JSON', token = None, license_file = None):
    if not token and not license_file:
        raise LicenseError
    elif license_file and not token:
        token = get_token(license_file)
    benchmark_data = requests.get(f'{CISURL}{BENCHMARK_EP}/{id}/{format}', headers = { CIS_HEADER : token })
    zipped_file = zipfile.ZipFile(io.BytesIO(benchmark_data.content))
    file_name = zipped_file.namelist()[0]
    contents = zipped_file.read(file_name)
    return contents

def write_benchmark(id, format = 'JSON', token = None, license_file = None):
    if not token and not license_file:
        raise LicenseError
    elif license_file and not token:
        token = get_token(license_file)
    benchmark_data = requests.get(f'{CISURL}{BENCHMARK_EP}/{id}/{format}', headers = { CIS_HEADER : token })
    zipfile.ZipFile(io.BytesIO(benchmark_data.content)).extractall()
    return

def get_pdfs():
    pdf_list = []
    pdf_list_raw = requests.get(f'{CISURL}{PDF_EP}').json()
    for pdf in pdf_list_raw['PDFs']:
        pdf_list.append((pdf['workbenchId'], pdf['benchmarkTitle'], pdf['pdfFileName']))
    return pdf_list

def write_pdf(id, name = None, token = None, license_file = None):
    if not token and not license_file:
        raise LicenseError
    elif license_file and not token:
        token = get_token(license_file)
    print(f'{CISURL}{PDF_EP}/{id}')
    pdf = requests.get(f'{CISURL}{PDF_EP}/{id}', headers = { CIS_HEADER : token }).content
    if not name: name = f'{id}-PDF.pdf'
    with open(name, 'wb') as pdf_file:
        pdf_file.write(pdf)
    return



if __name__ == '__main__':
    #Sample Code
    #token = get_token('license.xml')
    print(tabulate(get_benchmarks(), headers=['ID', 'Title', 'Platform', 'URL']))
    #write_benchmark(12741, license_file = 'license.xml')
    #print(tabulate(get_pdfs(), headers=['ID', 'Title', 'File Name']))
    #write_pdf(13165, name='CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v2.0.0.pdf', license_file = 'license.xml')

    # results = get_benchmarks()
    # for item in results:
    #     benchmark = json.loads(get_benchmark(item[0], license_file = 'license.xml'))
    #     print(benchmark['Benchmark'].keys())
    #     exit()
    
    # results = get_benchmarks()
    # benchmark_names = []
    # for benchmark_id, benchmark_name, benchmark_cpe, benchmark_url in results:
    #     benchmark_names.append(benchmark_name.strip(' [imported]'))
    
    # print(benchmark_names)
    # print(len(benchmark_names))
    # print(len(set(benchmark_names)))

    pass