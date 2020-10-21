#!/usr/bin/env python
# @file shodan/queryutils.py
# @brief Provides a set of functions for interacting with the Shodan API
# @details Wraps the official Shodan python API and enables clients to
# define queries, retrieve specific sets of attributes from the results,
# and write query results to a csv.
# @author Spencer Little (mrlittle@uw.edu)
# Last update: 10/20/2020 -- Initial commit

from enum import Enum
from math import ceil
from os import environ, path
from time import sleep, time

import shodan

RATE_LIMIT = 1  # Shodan limits queries to 1 per second

LIST_DELIMITER = ','
TMP_DELIMITER = '||+||'
QUOTE_REPL = '|'
NULL = 'None'

class Query(Enum):
    """Constants describing the status of a query. """
    QUERY_SUCCESS = 0x01
    QUERY_LIMIT_REACHED = 0x02
    QUERY_FAILED = 0xff


def execute_queries(
        queries,
        api_key,
        attributes=[],
        query_limit=25,
        unique_ips=True,
):
    """Executes the provided list of queries, extracts the attributes of interest for each
    entity in the response and returns a list of dictionaries where each dictionary represents
    an entity in the response and contains a mapping from the attribute's of interest to Shodan's response for that value, or 'None' if no value was returned from Shodan. Nested attributes are
    flattened, see extracted_attributes() for more details.

    Args:
        queries (list : str): a list of queries to execute
        api_key (str): the Shodan API key to use for the queries
        attributes (list : str): a list of attribute to include in the results. If none
            are specified all attributes are retrieved
        query_limit (int): the maximum number of query tokens that will be used for a single
            invocation
        unique_ips (bool): a boolean flag indicating that no two entities in the results should
            contain the same ip_str

    Returns:
        all_results (list): a list of dictionaries where each dictionary represents an
            entity in the response and contains a mapping from the attribute's of interest
            to Shodan's response for that value, or 'None' if no value was returned from Shodan

    """
    all_results = []
    total_queries = 0
    api = shodan.Shodan(api_key)

    for query in queries:
        start = time()
        print(f'Executing query {query}...')
        query_res, status, query_count = query_shodan(query, api, attributes=attributes)
        print(f'Retrieved and processed {len(query_res)} results in {round(time() - start, 2)}s\n')
        all_results.extend(query_res)
        total_queries += query_count
        if status == Query.QUERY_LIMIT_REACHED:
            print(f'Query count exceeded, {query_count} query tokens have have been utilized...')
            break
        elif status == Query.QUERY_FAILED:
            print(f'Query failed after {query_count} intermediate queries...')
            continue

    print(f'Retrieved {len(all_results) - 1} results from all queries.\n')
    print(f'Utilized {total_queries} query tokens.')

    return all_results


def write_results_to_csv(all_results, filename):
    """Writes a list of query results (dictionaries) to csv file. Attributes in the
    dictionaries must be flattened.

    Args:
        all_results (list): a list of dictionaries where each dictionary represents an
            entity in a response. Attribute names (keys) must be flattened and values may
            only be string or list. See the value returned by execute_queries() for details.
        filename (str): the fully qualified URL to write the results to
    """
    print(f'Writing {len(all_results)} results to {filename}...')

    with open(filename, 'w+') as data_file:
        all_keys = set()  # results may have different number of attributes
        for dict in all_results:
            for key in dict:
                all_keys.add(key)
        all_keys = list(all_keys)

        if 'ip_str' in all_keys:  # if ip_str is availabe, use it as PK
            ip_ind = all_keys.index('ip_str')
            tmp = all_keys[0]
            all_keys[0] = all_keys[ip_ind]
            all_keys[ip_ind] = tmp

        if len(all_results) > 0:
            data_file.write(', '.join([x for x in all_keys]) + '\n')

        for dict in all_results:
            data_file.write(result_dict_to_str(dict, all_keys))

    print(f'Successfuly wrote {len(all_results) - 1} results to {filename}.')


def result_dict_to_str(res_dict, all_attr):
    """Converts a dictionary of extracted attributes to a csv line.

    Args:
        res_dict (dict): a dictionary of extracted values, specifically one of
            the entities of the query_res list returned from query_shodan()
        all_attr (list : str): a list of all attribute ids for the table that is being
            written. If res_dict doesn't contain one of the attributes, NULL is substituted.

    Return:
        as_str (str): a string representing the attributes of res_dict in the
            format of a .csv line
    """
    as_str = ''
    for attr in all_attr:
        if attr in res_dict:
            val = res_dict[attr]
        else:
            val = NULL

        if (isinstance(val, list)):
            as_str += '\"'
            for entity in val:
                as_str += str(entity).replace('\"', QUOTE_REPL) + LIST_DELIMITER
            as_str += '\",'
        else:
            as_str += '\"' + str(val).replace('\"', QUOTE_REPL) + '\",'

    return as_str.strip(',') + '\n'


def query_shodan(
        query,
        shodan_api,
        query_limit=25,
        attributes=[],
        page_num=1,
        result_count=None,
        query_count=0,
        unique_ips=True,
        observed_ips=set(),
):
    """Queries the Shodan endpoint with the specified query and returns all results as a list of
    dictionaries where each dictionary an entity in the response and contains a mapping from the attribute's of interest to Shodan's response for that value, or 'None' if no value was returned from Shodan. Nested attributes are flattened, see extracted_attributes() for more details.

    Shodan returns 100 results per request (or 'page'), so this method recursively queries the
    endpoint until all results have been retreived or the query_limit has been reached.

    Args:
        query (str): the search query
        shodan_api (Shodan): an instance of the Shodan API class. For details see
            https://shodan.readthedocs.io/en/latest/.
        query_limit (int): the maximum number of query tokens that will be used for a single
            invocation
        attributes (list : str): a list of attribute to include in the results. If none
            are specified all attributes are retrieved
        page_num (int): the current page number, Shodan returns 100 results per
            request (or 'page')
        result_count (int): the total number of results to be retrieved for this query.
            If no argument is passed all results will retrieved. ELABORATE
        query_count (int): the number of queries performed for this invocation, used
            to manage proliferation of queries accross recursive calls. May be called
            with some int > 0 to track the cumulative queries accross invocations
        unique_ips (bool): a boolean flag indicating that no two entities in the results should
            contain the same ip_str
        observed_ips (set): the set of ip_str's for all results that have been observed for
            this query. Used to filter duplicated results if unique_ips is set.

    Return:
        query_res (list: dict): a list of dictionaries where each dictionary
            represents an entity in the response from Shodan. Only the attributes
            defined in EXTRACT_ATTRIBUTES are returned

    """
    if page_num != 1 and (page_num * 100) - result_count >= 100:
        return [], Query.QUERY_SUCCESS, query_count
    try:
            results = shodan_api.search(query, page=page_num)
            results_extracted = []
            result_total = results['total'] if result_count == None else result_count

            if page_num == 1:
                print(f'{result_total} total responses for query: {query}.')
                print(f'Will consume {ceil(result_total/100)} query tokens.')
            else:
                print(f'Retrieved page {page_num} of {ceil(result_total/100)}...')


            matches = results['matches']
            if unique_ips:
                matches = [res for res in results['matches'] if not res['ip_str'] in observed_ips]

            for result in matches:
                observed_ips.add(result['ip_str'])
                results_extracted.append(extract_attributes(result, attributes))

            sleep(RATE_LIMIT)
            if query_count + 1 > query_limit:
                status = Query.QUERY_LIMIT_REACHED
            else:
                next_page, status, query_total = query_shodan(
                    query,
                    shodan_api,
                    query_limit,
                    attributes,
                    page_num + 1,
                    result_total,
                    query_count + 1,
                    observed_ips,
                )
                results_extracted.extend(next_page)

            return results_extracted, status, query_total
    except shodan.APIError as query_err:
            print(f'Error occured while querying Shodan: {query_err}')
            return [], Query.QUERY_FAILED, query_count


def extract_attributes(shodan_response, attributes=[]):
    """Extracts the attributes of interest for the provided response, flattens nested
    attributes, and returns the results in a dictionary. If no attributes are specified
    all attributes are returned.

    Args:
        shodan_reponse (dict): the result of querying the Shodan API. Specifically,
            a dictionary mirroring their JSON format defined on
            https://developer.shodan.io/api provided by the Shodan python API.
        attributes (list : str): a list of attribute to include in the results. If none
            were provided all attributes are extracted

    Returns:
        extracted_res (dict): a dictionary derived from the response containing only
            the attributes defined in EXTRACT_ATTRIBUTES

    """
    extracted_res = {}
    for attribute in shodan_response:
        if attributes == [] or attribute in attributes:
            retrieve_attributes(attribute, shodan_response, extracted_res)
    return extracted_res


def retrieve_attributes(attribute, response, extracted_res):
    """Retrieves all attributes nested under the given attribute from Shodan's
    repsonse dictionary and flattens the attribute name using dot notation. If
    the attribute is None the NULL value is substituted for None.

    Note:
        Some attributes may contains '.' in their name (filenames under http.component
        for instance) so TMP_DELIMITER is used while flattening to prevent issues with
        extracting local_attr.

    Args:
        attribute (str): the attribute name
        response (dict): the dictionary response from Shodan's API
        extract_res (dict): the dictionary that will hold the extracted attributes

    """
    local_attr = attribute.split(TMP_DELIMITER)[-1]
    if isinstance(response[local_attr], dict):
        for n_attribute in response[local_attr]:
            retrieve_attributes(
                attribute + TMP_DELIMITER + n_attribute,
                response[local_attr],
                extracted_res
            )
    elif response[attribute.split(TMP_DELIMITER)[-1]] == None:
        extracted_res[attribute.replace(TMP_DELIMITER, '.')] = NULL
    else:
        extracted_res[attribute.replace(TMP_DELIMITER, '.')] = response[local_attr]
