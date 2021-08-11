import json, os, csv
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.patches as mpatches
import matplotlib.ticker as plticker
from pprint import pprint
from numpy.core.numeric import NaN
import pandas as pd
from enum import Enum
from ref import StatsRef
import seaborn as sns

try:
    os.remove('tactic_results.json')
    os.remove('vendor_results.json')
except:
    pass

if not os.path.exists(os.getcwd() + '/results'):
    os.makedirs(os.getcwd() + '/results')
if not os.path.exists(os.getcwd() + 'results/graphs'):
    os.makedirs(os.getcwd() + 'results/graphs')

pd.set_option("display.max_rows", None)
filenames = [f for f in os.listdir('json')]

r = StatsRef()
attacks, colors, evaluations, participants, countries, scoring, grading, detection_types, modifiers, participants_by_eval = r.get_references()
for e in evaluations:
    if not os.path.exists(os.getcwd() + f'/graphs/{e}'):
        os.makedirs(os.getcwd() + f'/graphs/{e}')

technique_coverage = pd.DataFrame(columns=('Tactic', 'TechniqueName', 'Detection', 'Modifiers'))
vendor_coverage = pd.DataFrame(columns=('Tactic', 'TechniqueName', 'Detection', 'Modifiers'))
vendor_protections = {}
datasources = {}
tactic_protections = {}

def crawl_results(filename, rnd):
    vendor = filename.split('_Results')[0]
    vendor_protections[vendor] = {}
    if rnd not in datasources.keys():
        datasources[rnd] = {}
    pdf = pd.DataFrame(columns=('Vendor', 'Adversary', 'Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'Detection', 'Modifiers'))
    with open('json/' + filename, 'r') as fp:
        data = json.load(fp)
        for elem in data['Adversaries']:
            if elem['Adversary_Name'] != rnd:
                continue
            tally = 0
            for ii in range(1, 3):
                for item in elem['Detections_By_Step'][f'Scenario_{ii}']['Steps']:
                    for substep in item['Substeps']:
                        tally += 1
                        obj = {'Vendor': vendor, 'Adversary': rnd, 'Substep':None, 'Criteria':None, 'Tactic':None, 'TechniqueId':None, 'TechniqueName':None, 'SubtechniqueId':None, 'Detection':None, 'Modifiers':None}
                        technique = substep['Technique']['Technique_Name']
                        detections = substep['Detections']
                        obj['Substep'] = substep['Substep']
                        obj['Criteria'] = substep['Criteria']
                        obj['Tactic'] = substep['Tactic']['Tactic_Name']
                        obj['TechniqueId'] = substep['Technique']['Technique_Id']
                        obj['TechniqueName'] = substep['Technique']['Technique_Name']
                        obj['SubtechniqueId'] = substep['Subtechnique']['Subtechnique_Id']
                        ret = {'Detection_Type':'None', 'Modifiers':'', 'Indicator':'', 'Indicator_Name':''} 
                        dt = Enum('DetectionTypes', detection_types[rnd])
                        for detection in detections:
                            detection_type = detection['Detection_Type'].replace(' ', '')
                            if dt[ret['Detection_Type'].replace(' ', '')].value < dt[detection_type].value:
                                ret = detection
                            if vendor not in datasources[rnd].keys():
                                datasources[rnd][vendor] = {}
                            try:
                                for source in detection['Data_Sources']:
                                    try:
                                        datasources[rnd][vendor][source] += 1
                                    except KeyError:
                                        datasources[rnd][vendor][source] = 1
                            except KeyError:
                                pass
                        try:
                            i = ret['Indicator']
                        except:
                            i = 'N/A'
                        try:
                            n = ret['Indicator_Name']
                        except:
                            n = 'N/A'
                        obj['Detection'], obj['Modifiers'], obj['Indicator'], obj['IndicatorName'] = \
                            ret['Detection_Type'], ' '.join(ret['Modifiers']), i, n
                        pdf = pdf.append(obj, ignore_index=True)
            prot_score = None
            try:
                blocks = 0
                tests = 0
                for test in elem['Protections']['Protection_Tests']:
                    for step in test['Substeps']:
                        if rnd == 'carbanak_fin7':
                            if step['Technique']['Technique_Name'] not in tactic_protections.keys():
                                tactic_protections[step['Technique']['Technique_Name']] = {'Total': 0, 'Blocked': 0}
                        if step['Protection_Type'] != 'N/A':
                            tests += 1
                            tactic_protections[step['Technique']['Technique_Name']]['Total'] += 1
                        if step['Protection_Type'] == 'Blocked':
                            tactic_protections[step['Technique']['Technique_Name']]['Blocked'] += 1
                            blocks += 1
                prot_score = blocks/tests
            except KeyError:
                prot_score = 0
            datasources[rnd][vendor]['Tally'] = tally
            vendor_protections[vendor][rnd] = prot_score
    return pdf

def score_df(df, rnd):
    tdf = df[df['Modifiers'].str.contains('Correlated|Tainted', na=False)]
    try:
        tainted_telemetry = tdf.Detection.value_counts()['Telemetry']
    except:
        tainted_telemetry = 0
    counts = df.Detection.value_counts()
    try:
        misses = counts['None']
    except KeyError:
        misses = 0
    try:
        tactic = counts['Tactic']
    except KeyError:
        tactic = 0
    try:
        general = counts['General']
    except KeyError:
        try:
            general = counts['General Behavior']
        except KeyError:
            general = 0
    try:
        enrich = counts['Enrichment']
    except:
        enrich = 0
    try:
        na = counts['N/A']
    except KeyError:
        na = 0
    substeps = len(df.index) - na
    visibility = (substeps - misses)
    quality = 0
    for index, content in df.iterrows():
        if content['Detection'] != 'N/A' or content['Detection'] != 'None' or content['Detection'] != 'MSSP':
            if content['Modifiers'].find('Delayed') == -1 and content['Modifiers'].find('Configuration Change') == -1:
                quality += 1
    cdf = df[df['Modifiers'].str.contains('Delayed|Configuration Change', na=False)]
    badcounts = cdf.Detection.value_counts()
    try:
        bna = badcounts['N/A']
    except:
        bna = 0
    try:
        bnone = badcounts['None']
    except:
        bnone = 0
    badsteps = len(cdf.index) - bna - bnone
    quality = 1 - (badsteps/int(visibility))
    if type(quality) != float:
        quality = 0
    assert(quality >= 0 and quality <= 1)
    if rnd == 'apt3':
        try:
            techniques = counts['Specific Behavior'] + general + enrich
        except:
            try:
                techniques = counts['General Behavior'] + enrich
            except:
                try:
                    techniques = counts['Enrichment']
                except:
                    techniques = 0
    else:
        try:
            techniques = counts['Technique'] + tactic + general
        except:
            try:
                techniques = counts['Tactic'] + general
            except:
                techniques = general
    analytics = techniques/visibility if visibility != 0 else 0
    if rnd == 'apt3':
        try:
            techniquelevel = counts['Specific Behavior']
        except:
            techniquelevel = 0
        try:
            telemetry = counts['Telemetry']
        except:
            telemetry = 0
        confidence = ((4 * techniquelevel) + (3 * general) + (2 * enrich) + telemetry)/substeps
    else:
        try:
            techniquelevel = counts['Technique']
        except:
            techniquelevel = 0
        try:
            telemetry = counts['Telemetry']
        except:
            telemetry = 0
        confidence = ((4 * techniquelevel) + (3 * tactic) + (2 * general) + telemetry)/substeps

    visibility /= substeps
        
    return visibility, analytics, quality, confidence

def query_df(pdf, rnd, mode, query):
    df = pdf[(pdf[mode] == query) & (pdf['Adversary'] == rnd)]
    if len(df.index) == 0:
        return None
    visibility, analytics, quality, confidence = score_df(df, rnd)
    return visibility, analytics, quality, confidence

def run_analysis(filenames):
    tdf = pd.DataFrame(columns=('Vendor', 'Adversary', 'Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'Detection', 'Modifiers'))
    if not os.path.exists(os.getcwd() + '/vendor_results.json'):
        vendor_results = {}
        for adversary in evaluations:
            vendor_results[adversary] = {}
            for vendor in participants_by_eval[adversary]:
                try:
                    df = crawl_results(vendor + '_Results.json', adversary)
                    tdf = tdf.append(df, ignore_index=True)
                    visibility, analytics, quality, confidence = query_df(df, adversary, 'Vendor', vendor)
                    g = None
                    g_v = None
                    g_q = None
                    g_c = None
                    pct = analytics * 100
                    pct_v = visibility * 100
                    pct_q = quality * 100
                    pct_c = confidence * 100
                    for grade in grading.keys():
                        low = grading[grade][0]
                        high = grading[grade][1]
                        if pct >= low and pct <= high:
                            g = grade
                        if pct_v >= low and pct_v <= high:
                            g_v = grade
                        if pct_q >= low and pct_q <= high:
                            g_q = grade
                        if pct_c >= low and pct_c <= high:
                            g_c = grade
                    if adversary == 'carbanak_fin7':
                        tally = datasources['carbanak_fin7'][vendor]['Tally']
                        availability = (sum(datasources['carbanak_fin7'][vendor].values()) - tally)/tally
                        vendor_results[adversary][vendor] = {'Visibility': visibility, 'Analytics': analytics, 'Quality': quality, 'Confidence': confidence, 'Protection': vendor_protections[vendor][adversary], 'Availability': availability}
                    else:
                        vendor_results[adversary][vendor] = {'Visibility': visibility, 'Analytics': analytics, 'Quality': quality, 'Confidence': confidence}
                except TypeError:
                    pass
        max_ = 0
        for vendor in vendor_results['carbanak_fin7'].keys():
            if vendor_results['carbanak_fin7'][vendor]['Availability'] > max_:
                max_ = vendor_results['carbanak_fin7'][vendor]['Availability']
        for vendor in vendor_results['carbanak_fin7'].keys():
            vendor_results['carbanak_fin7'][vendor]['Availability'] /= max_
        with open('vendor_results.json', 'w') as fp:
            json.dump(vendor_results, fp, indent=4)
    else:
        with open('vendor_results.json', 'r') as fp:
            vendor_results = json.load(fp)
    if not os.path.exists(os.getcwd() + 'tactic_results.json'):
        tactic_results = {}
        for adversary in evaluations:
            tactic_results[adversary] = {}
            for tactic in attacks.keys():
                tactic_results[adversary][tactic] = {}
                for technique in attacks[tactic].keys():
                    vis = 0
                    ana = 0
                    qua = 0
                    conf = 0
                    tally = 0
                    try:
                        #for vendor in participants_by_eval[adversary]:
                        #df = crawl_results(vendor + '_Results.json', adversary)
                        visibility, analytics, quality, confidence = query_df(tdf, adversary, 'TechniqueName', technique)
                        try:
                            prot = tactic_protections[technique]['Blocked']/tactic_protections[technique]['Total']
                        except:
                            prot = 0
                        tactic_results[adversary][tactic][technique] = {'Visibility': visibility, 'Analytics': analytics, 'Quality': quality, 'Confidence': confidence, 'Protection': prot}
                    except Exception as e:
                        pass
        with open('results/tactic_results.json', 'w') as fp:
            json.dump(tactic_results, fp, indent=4)
    else:
        with open('results/tactic_results.json', 'r') as fp:
            tactic_results = json.load(fp)
    
    return vendor_results, tactic_results, vendor_protections

def graph_results(adversary, vendor_results, tactic_results=None):
    sns.set_theme(color_codes=True)
    colors = {
        'Visibility': 'green',
        'Analytics': 'red',
        'Quality': 'blue'
    }
    vendors = participants_by_eval[adversary]
    visibility = []
    analytics = []
    for vendor in vendors:
        item = vendor_results[adversary][vendor]
        visibility.append(item['Visibility'])
        analytics.append(item['Analytics'])
    fig = plt.figure(figsize=(12, 12))
    vendors, visibility, analytics = [list(t) for t in zip(*sorted(zip(vendors, visibility, analytics), key=lambda x: x[1] + x[2]))]
    points = list(zip(visibility, analytics))
    df = pd.DataFrame(points, columns=['Visibility', 'Analytics'], index=vendors)
    g = sns.scatterplot(x='Visibility', y='Analytics', data=df)
    g.tick_params(labelsize=14)
    g.set_xlabel("Visibility", fontsize = 20)
    g.set_ylabel("Analytics", fontsize = 20)
    for line in range(0,df.shape[0]):
        if adversary == 'carbanak_fin7':
            if df.index[line] == 'Bitdefender':
                g.text(df['Visibility'][line]+0.005, df['Analytics'][line]+ 0.015, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'CheckPoint':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] - 0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Microsoft':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] - 0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Sophos':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] + 0.015, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Cisco':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] - 0.015, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            else:
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line], 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
        elif adversary == 'apt29':
            if df.index[line] == 'VMware':
                g.text(df['Visibility'][line]+0.007 , df['Analytics'][line]+ 0.02, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'TrendMicro':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]-0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Symantec':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]+0.007, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'PaloAltoNetworks':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]-0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'CrowdStrike':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]+0.01, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Microsoft':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]-0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            else:
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line], 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
        elif adversary == 'apt3':
            if df.index[line] == 'F-Secure':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line]-0.01, 
                    df.index[line], horizontalalignment='left', 
                    size=20, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Cybereason':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line]+0.01, 
                    df.index[line], horizontalalignment='left', 
                    size=20, color='black', weight='semibold', rotation=30)
            else:
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line], 
                    df.index[line], horizontalalignment='left', 
                    size=20, color='black', weight='semibold', rotation=30)
    plt.xlim(0, 1)
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{adversary}/Vendor Breakdown.png')
    plt.close()

    quality = []
    for vendor in vendors:
        quality.append(vendor_results[adversary][vendor]['Quality'])
    fig = plt.figure(figsize=(12, 12))
    quality, vendors = [list(t) for t in zip(*sorted(zip(quality, vendors), key=lambda x: x[0]))]
    indices = range(len(vendors))
    points = list(zip(indices, quality))
    df = pd.DataFrame(points, columns=['Vendor', 'Quality'], index=vendors)
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Quality', data=df, palette=("Reds_d"))
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 20)
    g.set_ylabel("Quality", fontsize = 20)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    g.set_yticklabels([x/5 for x in list(range(6))], fontsize = 18)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{adversary}/Quality Breakdown.png')
    plt.close()

    confidence = []
    analytics = []
    for vendor in vendors:
        confidence.append(vendor_results[adversary][vendor]['Confidence'])
    fig = plt.figure(figsize=(12, 12))
    confidence, vendors = [list(t) for t in zip(*sorted(zip(confidence, vendors), key=lambda x: x[0]))]
    indices = range(len(vendors))
    points = list(zip(vendors, confidence))
    df = pd.DataFrame(points, columns=['Vendor', 'Confidence'], index=indices)
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Confidence', data=df, palette=("Blues_d"))
    g.tick_params(labelsize=10)
    plt.autoscale(False)
    g.set_xlabel("Vendor", fontsize = 20)
    g.set_ylabel("Confidence", fontsize = 20)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    g.set_yticks(list(range(5)))
    plt.ylim(0, 4)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{adversary}/Confidence Breakdown.png')
    plt.close()

def graph_protections():
    import matplotlib.ticker as ticker
    protections = []
    vendors = []
    for vendor in vendor_results['carbanak_fin7'].keys():
        vendors.append(vendor)
        if vendor_results['carbanak_fin7'][vendor]['Protection'] != 'N/A':
            protections.append(vendor_results['carbanak_fin7'][vendor]['Protection'])
        else:
            protections.append(float(0))
    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    protections, vendors = [list(t) for t in zip(*sorted(zip(protections, vendors), key=lambda x: x[0]))]
    points = list(zip(indices, protections))
    df = pd.DataFrame(points, columns=['Vendor', 'Protection'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Protection', data=df, palette=("Greens_d"))
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Protection", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 16)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/carbanak_fin7/Protection Breakdown.png')
    plt.close()

def graph_rankings(rnd):
    import matplotlib.ticker as ticker
    scores = []
    vendors = []
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[1]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    points = list(zip(reversed(indices), reversed(scores)))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Unweighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Unweighted Rankings.png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[2]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Weighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Weighted Rankings (Detection).png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[3]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    indices = range(len(vendors))
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Weighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Weighted Rankings (Correlation).png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[4]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Weighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Weighted Rankings (Automation).png')
    plt.close()

def make_ranking(vendor_results, rnd, weighted=True):
    rankings = {}
    if weighted is True:
        for vendor in vendor_results[rnd].keys():
            rankings[vendor] = {}
            if rnd == 'carbanak_fin7':
                prot = 0 if vendor_results[rnd][vendor]['Protection'] == 'N/A' else vendor_results[rnd][vendor]['Protection']
                weighted_score = (.25 * prot) + (.25 * vendor_results[rnd][vendor]['Visibility']) + (.2 * vendor_results[rnd][vendor]['Analytics']) + (.2 * (vendor_results[rnd][vendor]['Confidence']/4)) + (.1 * vendor_results[rnd][vendor]['Quality'])
                unweighted_score = prot + vendor_results[rnd][vendor]['Visibility'] + vendor_results[rnd][vendor]['Analytics'] + (vendor_results[rnd][vendor]['Confidence']/4) + vendor_results[rnd][vendor]['Quality']
                unweighted_score /= 5 
                rankings[vendor]['Weighted'] = weighted_score
                rankings[vendor]['Unweighted'] = unweighted_score
            else:
                weighted_score = (.3 * vendor_results[rnd][vendor]['Visibility']) + (.25 * vendor_results[rnd][vendor]['Analytics']) + (.25 * (vendor_results[rnd][vendor]['Confidence']/4)) + (.2 * vendor_results[rnd][vendor]['Quality'])
                unweighted_score = vendor_results[rnd][vendor]['Visibility'] + vendor_results[rnd][vendor]['Analytics'] + (vendor_results[rnd][vendor]['Confidence']/4) + vendor_results[rnd][vendor]['Quality']
                rankings[vendor]['Weighted'] = weighted_score
                rankings[vendor]['Unweighted'] = unweighted_score
    return rankings

def make_tactic_rankings(tactic_results, rnd):
    technique_ranks = {}
    tactic_ranks = {}
    for category in tactic_results[rnd].keys():
        technique_ranks[category] = {}
        li = []
        for technique in tactic_results[rnd][category].keys():
            score = (.3 * tactic_results[rnd][category][technique]['Visibility']) + (.25 * tactic_results[rnd][category][technique]['Analytics']) + (.25 * (tactic_results[rnd][category][technique]['Confidence']/4)) + (.2 * tactic_results[rnd][category][technique]['Quality'])
            technique_ranks[category][technique] = score
            li.append(score)
        tactic_ranks[category] = sum(li)/len(li)

    return technique_ranks, tactic_ranks

def make_3d_plot(vendor_results):
    from mpl_toolkits.mplot3d import Axes3D
    detection_scores = []
    correlation_scores = []
    automation_scores = []
    vendors = []
    for vendor in vendor_results['carbanak_fin7'].keys():
        vendors.append(vendor)
        detection_scores.append(vendor_results['carbanak_fin7'][vendor]['Visibility'])
        correlation_scores.append((vendor_results['carbanak_fin7'][vendor]['Analytics'] + (vendor_results['carbanak_fin7'][vendor]['Confidence']/4))/2)
        automation_scores.append((vendor_results['carbanak_fin7'][vendor]['Quality'] + vendor_results['carbanak_fin7'][vendor]['Protection'])/2)

    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')

    ax.scatter(detection_scores, correlation_scores, automation_scores, c='r', marker='o')
    ax.set_xlabel('Detection Ability')
    ax.set_ylabel('Correlation Ability')
    ax.set_zlabel('Automation Ability')

    plt.show()

def run_eval():
    vendor_results, tactic_results, vendor_protections = run_analysis(filenames)
    rankings = {}
    for adversary in vendor_results.keys():
        ranking = make_ranking(vendor_results, adversary)
        rankings[adversary] = ranking
        with open(f'results/{adversary} Rankings.csv', 'w') as fp:
            writer = csv.writer(fp)
            if adversary == 'carbanak_fin7':
                writer.writerow(['Vendor', 'Unweighted Score', 'Detection Priority Score', 'Correlation Priority Score', 'Automation Priority Score', 'Visibility', 'Analytics', 'Confidence', 'Quality', 'Protection', 'Availability'])
                rs = []
                vs = []
                us = []
                for vendor in ranking.keys():
                    vs.append(vendor)
                    rs.append(ranking[vendor]['Unweighted'])
                vs, rs = [list(t) for t in zip(*sorted(zip(vs, rs), key=lambda x: x[1]))]
                scores = zip(reversed(vs), reversed(rs))
                for item in scores:
                    if vendor_results[adversary][item[0]]['Protection'] == 'N/A':
                        prot = 0
                    else:
                        prot = vendor_results[adversary][item[0]]['Protection']
                    visibility = vendor_results[adversary][item[0]]['Visibility']
                    analytics = vendor_results[adversary][item[0]]['Analytics']
                    confidence = vendor_results[adversary][item[0]]['Confidence']/4
                    quality = vendor_results[adversary][item[0]]['Quality']
                    det_score = (.3 * visibility)+ (.175 * analytics) + (.175 * confidence) + (.175 * quality) + (.175 * prot)
                    corr_score = (.2 * visibility)+ (.25 * analytics) + (.25 * confidence) + (.20 * quality) + (.10 * prot)
                    auto_score = (.2 * visibility)+ (.15 * analytics) + (.15 * confidence) + (.25 * quality) + (.25 * prot)
                    try:
                        writer.writerow([item[0], "%.3f" % item[1], "%.3f" % det_score, "%.3f" % corr_score, "%.3f" % auto_score, "%.3f" % vendor_results[adversary][item[0]]['Visibility'], "%.3f" % vendor_results[adversary][item[0]]['Analytics'],"%.3f" % (vendor_results[adversary][item[0]]['Confidence']/4), "%.3f" % vendor_results[adversary][item[0]]['Quality'], "%.3f" % prot])
                    except Exception as e:
                        print(e)
            else:
                writer.writerow(['Vendor', 'Unweighted Score', 'Visibility', 'Analytics', 'Confidence', 'Quality'])
                rs = []
                vs = []
                for vendor in ranking.keys():
                    vs.append(vendor)
                    rs.append(ranking[vendor]['Unweighted'])
                vs, rs = [list(t) for t in zip(*sorted(zip(vs, rs), key=lambda x: x[1]))]
                scores = zip(reversed(vs), reversed(rs))
                for item in scores:
                    try:
                        writer.writerow([item[0], "%.3f" % item[1], "%.3f" %  vendor_results[adversary][item[0]]['Visibility'], "%.3f" %  vendor_results[adversary][item[0]]['Analytics'],"%.3f" %  (vendor_results[adversary][item[0]]['Confidence']/4), "%.3f" %  vendor_results[adversary][item[0]]['Quality']])
                    except:
                        pass
    graph_rankings('carbanak_fin7')
    graph_protections()

if __name__ == "__main__":
    run_eval()