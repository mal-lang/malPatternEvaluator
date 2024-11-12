#!/usr/bin/env python
# Author: Jens Ekenblad
# Date: 2024-10-16
# Part of master thesis "Enhancing Cybersecurity Defenses through Structural Patterns in Threat Modeling" at KTH.

import sys
import logging
import datetime
import time
import argparse
import pyfiglet
import json
from tqdm import tqdm
from maltoolbox.ingestors import neo4j
from py2neo import Graph, Node, Relationship, Subgraph

import logging

import maltoolbox
from maltoolbox.language import LanguageGraph, LanguageClassesFactory
from maltoolbox.model import Model, AttackerAttachment
from maltoolbox.attackgraph import AttackGraph, query
from maltoolbox.attackgraph.analyzers import apriori
from maltoolbox.ingestors import neo4j


# Initialize the program by loading the model and patterns file
def init(modelFile: str, patternFile: str) -> dict:
    """
    Initialize the program by loading the model and patterns file
    
    Arguments:
    modelFile        - the model file to load
    patternFile      - the pattern file to load
    """

    ingest_model(modelFile)
    for _ in tqdm (range (100), desc="Connecting to Neo4j..."):
        time.sleep(0.004)
    print("Successfully connected!\n")
    patterns = load_patterns(patternFile)
    return patterns

# Load MAL model into Neo4j instance
def ingest_model(modelFile):
    lang_file = 'org.mal-lang.coreLang-1.0.0.mar'
    lang_graph = LanguageGraph.from_mar_archive(lang_file)
    lang_classes_factory = LanguageClassesFactory(lang_graph)
    #model = Model('M1', lang_classes_factory)
    try:
        model = Model.load_from_file(modelFile, lang_classes_factory)
        neo4j.ingest_model(model,
                "bolt://localhost:7687", 
                "neo4j",
                "dynp12345!",
                "neo4j",
            delete=True)
    except:
        print("Error loading model file and connecting to Neo4j")
        sys.exit(1)

# Load patterns file from a json file
def load_patterns(filename: str) -> dict:
    """
    Load patterns file from a json file

    Arguments:
    filename        - the path of the input file to parse
    """

    try:
        raw_patterns = {}
        with open(filename, 'r', encoding='utf-8') as file:
            raw_patterns = json.load(file)

        patterns = raw_patterns.copy()
        for pattern,attribs in raw_patterns.items():
            patterns[pattern] = {}
            patterns[pattern]['badDescription'] = attribs['badDescription']
            patterns[pattern]['impact'] = attribs['impact']
            patterns[pattern]['mitigationDescription'] = attribs['mitigationDescription']
            patterns[pattern]['badPattern'] = ' '.join(attribs['badPattern'])
            patterns[pattern]['mitigationPattern'] = ' '.join(attribs['mitigationPattern'])
            patterns[pattern]['attackIDs'] = attribs['attackIDs']
    except:
        print("Error loading patterns file")
        sys.exit(1)
    return patterns


# Analyze all patterns on a model and log the corresponding ATT&CK techniques of detected patterns
def analyze_patterns(patterns) -> dict:
    """
    Analyze patterns on a model and log the corresponding ATT&CK techniques of detected patterns
    
    Arguments:
    patterns        - JSON file containing the patterns to analyze 
    """

    # Load the attack data
    dataMapping = {}
    with open('attackData.json', 'r', encoding='utf-8') as file:
        dataMapping = json.load(file)
   
    # Create a logger for detected patterns
    logger = logging.getLogger('patternReport')
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler('tmp/patternReport.log')
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    logger.info(f"\n***\n----------Attack Patterns Report----------\n\n\nTime: {datetime.datetime.now()}\n")

    log_id = 1
    detPatterns = {}

    # Extract and apply each available pattern query
    for name,attribs in patterns.items():
        for i in tqdm (range (100), desc=f"Analyzing pattern [{name}] on model..."):
            time.sleep(0.002)
        queries = attribs['badPattern'].split(';')
        for query in queries:
            query = query.strip()
            if query == '': continue
            results = apply_query(query)
            
            if (results != None) and (len(results) > 0):
                tactics = attribs['attackIDs']['Tactic']
                mitigations = attribs['attackIDs']['Mitigations']
                detPatterns[log_id] = {"name":name, "assets":[]}
                for r in results:
                    assets = [v for v in r.values()]
                    detPatterns[log_id]['assets'].append(assets)
                
                
                # Log the detected pattern with ATT&CK data
                logger.info(f"""Id: {log_id}\nPattern: {name}\nBadDescription: {attribs['badDescription']}\nImpact: {attribs['impact']}\nMitigationDescription: {attribs['mitigationDescription']}\nNeo4j_Assets:{assets}\n\n----------ATT&CK----------\nTactic:""")
                for tactic in tactics:
                    logger.info(f"\n      {tactic}:")
                    for technique in tactics[tactic]:
                        logger.info(f"""
                    Technique: {dataMapping['ATT&CK']['Tactic'][tactic][technique]['name']}
                    ID: {dataMapping['ATT&CK']['Tactic'][tactic][technique]['id']}
                    Description: {dataMapping['ATT&CK']['Tactic'][tactic][technique]['description']}
                    URL: {dataMapping['ATT&CK']['Tactic'][tactic][technique]['url']}
                    CAPEC: {dataMapping['ATT&CK']['Tactic'][tactic][technique]['CAPEC_id']}""")
                
                logger.info(f"""\nMitigations:""")
                for mitigation in mitigations:
                    logger.info(f"""
                    Mitigation: {dataMapping['ATT&CK']['Mitigation'][mitigation]['name']}
                    ID: {dataMapping['ATT&CK']['Mitigation'][mitigation]['id']}
                    Description: {dataMapping['ATT&CK']['Mitigation'][mitigation]['description']}
                    URL: {dataMapping['ATT&CK']['Mitigation'][mitigation]['url']}""")

                logger.info("\n\n\n")    
                log_id += 1
        
    logger.info(f"""----------Summary----------\n\nTotal patterns detected: {len(detPatterns.keys())}""")
    for id, val in detPatterns.items():
        logger.info(f"""{id}. {val['name']}""")
    logger.removeHandler(handler)
    print("**Analysis completed**")
    return detPatterns
        
# Apply a query on the Neo4J graph database
def apply_query(query, 
        uri="bolt://localhost:7687",
        username="neo4j",
        password="dynp12345!",
        dbname="neo4j",
) -> None:
    """
    Apply a query on the Neo4J platform

    Arguments:
    query                - the query to issue to Neo4J
    uri                  - the URI to a running neo4j instance
    username             - the username to login on Neo4J
    password             - the password to login on Neo4J
    dbname               - the selected database

    Return:
    Return value is what would a  Neo4J query would return.
    For example:
    - in case of SELECT/MATCH queries the matching records are returned
    - in case of CREATION/UPDATE queries no record is returned
    """
    try:
        g = Graph(uri=uri, user=username, password=password, name=dbname)  
        return g.run(query).data()
    except:
        print("Error applying query to Neo4j instance!")


# Revise a query with the given arguments in detPat
def apply_mitigation(patterns, detPat,) -> None:
    """
    Apply mitigations for a detected pattern, by revising the mitigation query with the given arguments in detPat
    
    Arguments:
    patterns        - the original pattern file that is analyzed
    detPat          - the detected pattern with assets to mitigate"""

    print("Applying mitigations for: " + detPat['name'] + "\n")
    for assets in detPat['assets']:
        inp = input(f"Apply to assets: {assets} (y/n)\n")
        if inp != 'y':
            continue
        newQuery = patterns[detPat['name']]['mitigationPattern']
        argId = 1
        for asset in assets:
            if asset == None:
                continue
            arg = '$' + str(argId)
            newQuery = newQuery.replace(arg, asset)
            argId += 1
        print("Following query is applied:\n" + newQuery)
        apply_query(newQuery)
    



def review_pattern_report():
    with open('tmp/patternReport.log', 'r') as file:
        print(file.read().split("\n***\n")[-1])


def main():
    
    parser = argparse.ArgumentParser(description='Specify model and patterns to analyze')
    parser.add_argument('-m', type=str, help='MAL model that will be analyzed')
    parser.add_argument('-p', type=str, help='Patterns file to analyze')
    args = parser.parse_args()

    if not args.m or not args.p:
        print("""
        Usage: python3 mpd.py -m <modelFile> -p <patternFile>

        -m: MAL model built and stored as JSON file)
        -p: Patterns to analyze as JSON file
        """)
        sys.exit(1)
    else:
        print(pyfiglet.figlet_format("MALPattern\nEvaluator"))
        modelFile = args.m
        patternFile = args.p

        patterns = init(modelFile, patternFile)

        while True:
            print("""
        
    
        [1] Analyze patterns
        [2] Review Pattern Report
        [3] Apply mitigation
        [4] Restore model
        [5] Exit
                        
            """)
        
            choice = input("Enter your choice (1-5):\n")

            if choice == '1':
                detectedPatterns = analyze_patterns(patterns)
            elif choice == '2':
                review_pattern_report()
            elif choice == '3':
                inp = input("Enter pattern ID to mitigate:\n")
                if int(inp) in detectedPatterns.keys():
                    apply_mitigation(patterns, detectedPatterns[int(inp)])    
                else:  
                    print("Invalid pattern ID")
            elif choice == '4':
                ingest_model(modelFile)
                print("**Model restored**")
            elif choice == '5':
                print("Exiting program.")
                break
            else:
                print("Invalid choice")



if __name__ == "__main__":
    main()