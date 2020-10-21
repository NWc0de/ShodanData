#!/usr/bin/env python
# @file retrieve_data.py
# @brief Retrieves data from defaced websites via Shodan
# @details Queries Shodan for web servers that contain keywords
# indicitave of defacement. Saves results to a .csv file.
# @author Spencer Little (mrlittle@uw.edu)
# Last edit: 10/20/2020

from os import environ

from shodan.query_utils import execute_queries, write_results_to_csv

DEFACEMENT_FULL_URL = 'defaced_web_servers_full.csv'
DEFACEMENT_REDUCED_URL = 'defaced_web_servers_reduced.csv'

DEFACEMENT_QUERIES = [
    'http.title:\"Hacked by\"',
    'http.html:\"Hacked by\" !http.title:\"Hacked by\"',  # negation avoids duplicate queries
    'http.title:\"Pwned by\"',
    'http.html:\"Pwned by\" !http.title:\"Pwned by\"',
]

EXTRACT_ATTRIBUTES = [
    'ip_str',     # str
    'hostnames',  # list : str
    'location',   # dict
    'domains',    # list : str
    'http',       # dict
    'os',         # str
    'info',       # str
    'isp',        # str
    'data',       # str
]

if __name__=='__main__':
    results = execute_queries(DEFACEMENT_QUERIES, environ['SHODAN_API_KEY'])
    results_reduced = []

    for result in results:
        reduced_dict = {}
        for key in [attr for attr in result if attr.split('.')[0] in EXTRACT_ATTRIBUTES]:
            reduced_dict[key] = result[key]
        results_reduced.append(reduced_dict)

    write_results_to_csv(results, DEFACEMENT_FULL_URL)
    write_results_to_csv(results_reduced, DEFACEMENT_REDUCED_URL)
