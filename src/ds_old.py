from argparse import ArgumentParser
from pathlib import Path
from re import match
from time import sleep
import requests
import pprint
import json



class DependencyScanner():


    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0" # This product uses data from the NVD API but is not endorsed or certified by the NVD.
        self.dependencies = []
        self.results = []
        self.dependency_type = ''


    def read_local_dependency_file(self, dependency_file):
        if dependency_file == 'requirements.txt':
            if Path('requirements.txt').exists():
                self.dependency_type = 'python'
                print('started parsing requirements.txt')
                with open('requirements.txt') as f:
                    unfiltered_dependencies = f.read().splitlines()
                self.filter_python_dependencies(unfiltered_dependencies)
                print('finished parsing requirements.txt')
            else:
                format_error_message('requirements.txt NOT FOUND; File must be in current directory')
                return 1
        else:
            format_error_message('DEPENDENCY FILE NOT FOUND')
        # elif package.json etc


    def filter_python_dependencies(self, unfiltered_dependencies):
        for x in unfiltered_dependencies:
            if x[:1] != '#': # skip commented packages
                x = x.split('#')[0].strip() # remove comments post package definition
                if match(r'^[A-Za-z0-9\-_.=]+$', x):  # ensure only valid characters are used
                    package, version = x.split('==')
                    self.dependencies.append({
                        'name': package,
                        'version': version,
                    })
                else:
                    format_error_message('INVALID PACKAGE: ' + x)


    def get_affected_versions(self, cve):
        affected_versions = {}
        # always one configuration
        config = cve['configurations'][0]
        # cant garuntee first node containing version info
        for node in config.get('nodes', []):
            # nodes only contains one cpeMatch
            if self.dependency_type in node['cpeMatch'][0].get('criteria'):
                affected_versions = {
                    'startIncluding': node['cpeMatch'][0].get('versionStartIncluding'),
                    'startExcluding': node['cpeMatch'][0].get('versionStartExcluding'),
                    'endIncluding': node['cpeMatch'][0].get('versionEndIncluding'),
                    'endExcluding': node['cpeMatch'][0].get('versionEndExcluding')
                }
                if affected_versions['startExcluding'] == None and affected_versions['startIncluding'] == None:
                    affected_versions['startIncluding'] = '0.0.0'
                if affected_versions['endExcluding'] == None and affected_versions['endIncluding'] == None:
                    affected_versions['endIncluding'] == '9999.9999.9999'
                break
        
        return affected_versions
        
    def is_version_affected(self, active_version, affected_versions):
        padded_active_version = self.pad_version(active_version)
        """ | start I | start E | end I | end E | 
            |    1    |    0    |   1   |   0   | <= <=
            |    1    |    0    |   0   |   1   | <= <
            |    0    |    1    |   1   |   0   | <  <=
            |    0    |    1    |   0   |   1   | <  <
        """
        print(f'checking {active_version} with {affected_versions}')
        if affected_versions['startIncluding'] != None and affected_versions['endIncluding'] != None:
            padded_start = self.pad_version(affected_versions['startIncluding'])
            padded_end = self.pad_version(affected_versions['endIncluding'])
            if padded_start[0] <= padded_active_version[0] and padded_active_version[0] <= padded_end[0]:
                print('end case 1')
                return True
        elif affected_versions['startIncluding'] != None and affected_versions['endExcluding'] != None:
            padded_start = self.pad_version(affected_versions['startIncluding'])
            padded_end = self.pad_version(affected_versions['endExcluding'])
            if padded_start[0] <= padded_active_version[0] and padded_active_version[0] < padded_end[0]:
                print('end case 2')
                return True
            elif padded_active_version[0] == padded_end[0]:
                if padded_active_version[1] < padded_end[1]:
                    print('end case 2.1')
                    return True
                elif padded_active_version[1] == padded_end[1]:
                    if padded_active_version[2] < padded_end[2]:
                        print('end case 2.2')
                        return True
        elif affected_versions['startExcluding'] != None and affected_versions['endIncluding'] != None:
            padded_start = self.pad_version(affected_versions['startExcluding'])
            padded_end = self.pad_version(affected_versions['endIncluding'])
            if padded_start[0] < padded_active_version[0] and padded_active_version[0] <= padded_end[0]:
                print('end case 3')
                return True
            elif padded_start[0] == padded_active_version[0]:
                if padded_start[1] < padded_active_version[1]:
                    print('end case 3.1')
                    return True
                elif padded_start[1] == padded_active_version[1]:
                    if padded_start[2] < padded_active_version[2]:
                        print('end case 3.2')
                        return True
        elif affected_versions['startExcluding'] != None and affected_versions['endExcluding'] != None:
            padded_start = self.pad_version(affected_versions['startExcluding'])
            padded_end = self.pad_version(affected_versions['endExcluding'])
            if padded_start[0] < padded_active_version[0] and padded_active_version[0] < padded_end[0]:
                print('end case 4')
                return True
            elif padded_start[0] < padded_active_version[0] and padded_active_version[0] == padded_end[0]:
                if padded_active_version[1] < padded_end[1]:
                    print('end case 4.1')
                    return True
                elif padded_active_version[1] == padded_end[1]:
                    if padded_active_version[2] < padded_end[2]:
                        print('end case 4.2')
                        return True
            elif padded_start[0] == padded_active_version[0] and padded_active_version[0] < padded_end[0]:
                if padded_start[1] < padded_active_version[1]:
                    print('end case 4.3')
                    return True
                elif padded_start[1] == padded_active_version[1]:
                    if padded_start[2] < padded_active_version[2]:
                        print('end case 4.4')
                        return True
            elif padded_start[0] == padded_active_version[0] and padded_active_version[0] == padded_end[0]:
                if padded_start[1] < padded_active_version[1] and padded_active_version[1] < padded_end[1]:
                    print('end case 4.5')
                    return True
                elif padded_start[1] < padded_active_version[1] and padded_active_version[1] == padded_end[1]:
                    if padded_active_version[2] < padded_end[2]:
                        print('end case 4.6')
                        return True
                elif padded_start[1] == padded_active_version[1] and padded_active_version[1] < padded_end[1]:
                    if padded_start[2] < padded_active_version[2]:
                        print('end case 4.7')
                        return True
                elif padded_start[1] == padded_active_version[1] and padded_active_version[1] == padded_end[1]:
                    if padded_start[2] < padded_active_version[2] and padded_active_version[2] < padded_end[2]:
                        print('end case 4.8')
                        return True
        return False 
    

    def pad_version(self, version): # default into major.minor.micro
        version_parts = version.split('.')
        while len(version_parts) <= 2: #change from if incase only major version passed
            version_parts.append('0')
        return [int(x) for x in version_parts]


   # This product uses data from the NVD API but is not endorsed or certified by the NVD.
   # https://nvd.nist.gov/developers/vulnerabilities
    def check_nvd_database(self):
        print('IMPORTANT: This product uses data from the NVD API but is NOT endorsed or certified by the NVD.')
        print('connecting to NVD Database') 
        for x in self.dependencies: 
            # search_url = self.nvd_api_url + f'?keywordSearch={x['name']}&keywordExactMatch' | TO BE removed after testing of cpename parameter
            params = {
                'cpeName' : f"cpe:2.3:a:{self.dependency_type}:{x['name']}:0" 
            }
            response = requests.get(self.nvd_api_url, params=params) 
            if response.status_code == 200:
                vulnerabilties = response.json().get('vulnerabilities', [])
                for y in vulnerabilties:
                    pprint.pprint(y)
                    cve = y['cve']
                    affected_versions = self.get_affected_versions(cve) #pass in params dict
                    if self.is_version_affected(x['version'], affected_versions):
                        self.results.append({
                            'package': x['name'],
                            'version': x['version'],
                            'vulnerability': {
                                'cve_id': cve['id'],
                                'description': cve['descriptions'][0]['value'], #first description typically english
                                'severity': cve.get('baseSeverity', 'UNKNOWN'), # check validity of baseSeverity variable
                                # 'references': [ref['url'] for ref in cve.get('references', [])] TODO: Make optional
                            }
                        })
            else:
                format_error_message('FAILED TO CONNECT TO NVD DATABASE: ' + str(response.status_code))
            sleep(6) #Cannot exceed 5 api calls within 30 seconds; https://nvd.nist.gov/developers/start-here
                
    def print_to_cmdline(self):
        if len(self.results) == 0:
            print('No Vulnerabilties Found')
        else:
            for x in self.results:
                pprint.pprint(x)


# move to helper class if more cases arise
# sets error text color to red then resets coloring to default
def format_error_message(error_message): 
    return print('\u001b[31m' + error_message + '\u001b[0m')          


def main():
    parser = ArgumentParser(description='Dependency Scanner')
    #TODO: add segement describing versions accepted ie major.minor.micro or major.minor or year.month as 2020.12 | 2020.12.30 will also works but not widely accepted
    parser.add_argument('-n', '--name', help='Name of dependency file; e.g, requirements.txt, package.json', required=True)
    arg = parser.parse_args()

    scanner = DependencyScanner()
    scanner.read_local_dependency_file(arg.name)

    if len(scanner.dependencies) < 1:
        format_error_message('NO DEPENDENCIES STORED; SEE ABOVE')
        return 1
    
    scanner.check_nvd_database()

    scanner.print_to_cmdline()
    


if __name__ == "__main__":
    main()