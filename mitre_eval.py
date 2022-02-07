import json, os, csv, sys
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
import matplotlib.ticker as ticker

if '-n' in sys.argv:
    try:
        os.remove(os.getcwd() + '/results/tactic_results.json')
        os.remove(os.getcwd() + '/results/vendor_results.json')
    except Exception as e:
        print(e)

if not os.path.exists(os.getcwd() + '/results'):
    os.makedirs(os.getcwd() + '/results')
if not os.path.exists(os.getcwd() + 'results/graphs'):
    os.makedirs(os.getcwd() + 'results/graphs')

if not os.path.exists(os.getcwd() + 'results/graphs/carbanak_fin7'):
    os.makedirs(os.getcwd() + 'results/graphs/carbanak_fin7')

if not os.path.exists(os.getcwd() + 'results/graphs/apt29'):
    os.makedirs(os.getcwd() + 'results/graphs/apt29')

if not os.path.exists(os.getcwd() + 'results/graphs/apt3'):
    os.makedirs(os.getcwd() + 'results/graphs/apt3')

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

def score_df(df, rnd, vendor=None):
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
        confidence = ((4 * techniquelevel) + (3 * general) + (2 * enrich) + telemetry)/visibility
    else:
        try:
            techniquelevel = counts['Technique']
        except:
            techniquelevel = 0
        try:
            telemetry = counts['Telemetry']
        except:
            telemetry = 0
        
        confidence = ((4 * techniquelevel) + (3 * tactic) + (2 * general) + telemetry)/visibility

    visibility /= substeps
        
    return visibility, analytics, quality, confidence

def query_df(pdf, rnd, mode, query):
    df = pdf[(pdf[mode] == query) & (pdf['Adversary'] == rnd)]
    if len(df.index) == 0:
        return None
    if mode == 'Vendor':
        visibility, analytics, quality, confidence = score_df(df, rnd, vendor=query)
    else:
        visibility, analytics, quality, confidence = score_df(df, rnd)
    return visibility, analytics, quality, confidence

def run_analysis(filenames):
    tdf = pd.DataFrame(columns=('Vendor', 'Adversary', 'Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'Detection', 'Modifiers'))
    if not os.path.exists(os.getcwd() + '/results/vendor_results.json'):
        vendor_results = {}
        for adversary in evaluations:
            vendor_results[adversary] = {}
            for vendor in participants_by_eval[adversary]:
                try:
                    df = crawl_results(vendor + '_Results.json', adversary)
                    tdf = tdf.append(df, ignore_index=True)
                    visibility, analytics, quality, confidence = query_df(df, adversary, 'Vendor', vendor)
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
        with open('results/vendor_results.json', 'w') as fp:
            json.dump(vendor_results, fp, indent=4)
    else:
        with open('results/vendor_results.json', 'r') as fp:
            vendor_results = json.load(fp)
    if not os.path.exists(os.getcwd() + '/results/tactic_results.json'):
        tactic_results = {}
        for adversary in evaluations:
            tactic_results[adversary] = {}
            for tactic in attacks.keys():
                tactic_results[adversary][tactic] = {}
                for technique in attacks[tactic].keys():
                    try:
                        visibility, analytics, quality, confidence = query_df(tdf, adversary, 'TechniqueName', technique)
                        try:
                            prot = tactic_protections[technique]['Blocked']/tactic_protections[technique]['Total']
                        except:
                            prot = None
                        tactic_results[adversary][tactic][technique] = {'Visibility': visibility, 'Analytics': analytics, 'Quality': quality, 'Confidence': confidence, 'Protection': prot}
                    except Exception as e:
                        pass
        with open('results/tactic_results.json', 'w') as fp:
            json.dump(tactic_results, fp, indent=4)
    else:
        with open('results/tactic_results.json', 'r') as fp:
            tactic_results = json.load(fp)
    
    return vendor_results, tactic_results, vendor_protections

def grade_score(score):
    score = float(score * 100)
    for grade in grading.keys():
        low = grading[grade][0]
        high = grading[grade][1]
        if score >= low and score <= high:
            return grade

def color_grade(grade):
    if grade == 'Excellent':
        return 'Dark Green'
    elif grade == 'Very Good':
        return 'Light Green'
    elif grade == 'Good':
        return 'Yellow'
    elif grade == 'Fair':
        return 'Light Red'
    elif grade == 'Poor':
        return 'Dark Red'


def graph_protections(vendor_results):
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
    sns.set_style('whitegrid')
    #sns.set(rc={'axes.facecolor':'white', 'figure.facecolor':'white'})
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            if rnd == 'carbanak_fin7':
                scores.append(float(row[1]))
                vendors.append(row[0])
            else:
                scores.append(float(row[1])/4)
                vendors.append(row[0])
    colors = []
    for i in range(len(vendors)):
        g = grade_score(scores[i])
        if g == 'Excellent':
            colors.append('#176121')
        elif g == 'Very Good':
            colors.append('#6ec47a')
        elif g == 'Good':
            colors.append('#c7c358')
        elif g == 'Fair':
            colors.append('#e37b6f')
        elif g == 'Poor':
            colors.append('#a82011')
    #colors = list(reversed(colors))
    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    points = list(zip(reversed(indices), reversed(scores)))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    #sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette=colors)
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Unweighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    plt.autoscale(False)
    plt.tight_layout()
    #plt.gray()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Unweighted Rankings.png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        if rnd == 'carbanak_fin7':
            for row in reader:
                if row[1] == 'Unweighted Score':
                    continue
                scores.append(float(row[5]))
                vendors.append(row[0])
        else:
            for row in reader:
                if row[1] == 'Unweighted Score':
                    continue
                scores.append(float(row[2]))
                vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    colors = []
    for i in range(len(vendors)):
        g = grade_score(scores[i])
        if g == 'Excellent':
            colors.append('#176121')
        elif g == 'Very Good':
            colors.append('#6ec47a')
        elif g == 'Good':
            colors.append('#c7c358')
        elif g == 'Fair':
            colors.append('#e37b6f')
        elif g == 'Poor':
            colors.append('#a82011')
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    #sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette=colors)
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Detection Capability", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    #plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    #plt.gray()
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Rankings (Detection).png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        if rnd == 'carbanak_fin7':
            for row in reader:
                if row[1] == 'Unweighted Score':
                    continue
                scores.append((float(row[6]) + float(row[7]))/2)
                vendors.append(row[0])
        else:
            for row in reader:
                if row[1] == 'Unweighted Score':
                    continue
                scores.append((float(row[3]) + float(row[4]))/2)
                vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    colors = []
    for i in range(len(vendors)):
        g = grade_score(scores[i])
        if g == 'Excellent':
            colors.append('#176121')
        elif g == 'Very Good':
            colors.append('#6ec47a')
        elif g == 'Good':
            colors.append('#c7c358')
        elif g == 'Fair':
            colors.append('#e37b6f')
        elif g == 'Poor':
            colors.append('#a82011')
    indices = range(len(vendors))
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    #sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette=colors)
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Contextual Richness", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    #plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    #plt.gray()
    plt.autoscale(False)
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Rankings (Correlation).png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd} Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        if rnd == 'carbanak_fin7':
            for row in reader:
                if row[1] == 'Unweighted Score':
                    continue
                scores.append((float(row[8]) + float(row[9]))/2)
                vendors.append(row[0])
        else:
            for row in reader:
                if row[1] == 'Unweighted Score':
                    continue
                scores.append(float(row[5]))
                vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    colors = []
    for i in range(len(vendors)):
        g = grade_score(scores[i])
        if g == 'Excellent':
            colors.append('#176121')
        elif g == 'Very Good':
            colors.append('#6ec47a')
        elif g == 'Good':
            colors.append('#c7c358')
        elif g == 'Fair':
            colors.append('#e37b6f')
        elif g == 'Poor':
            colors.append('#a82011')
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
   #sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette=colors)
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Automation Capability", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    #plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    #plt.gray()
    plt.autoscale(False)
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/results/graphs/{rnd}/Rankings (Automation).png')
    plt.close()

def make_ranking(vendor_results, rnd, weighted=False):
    rankings = {}
    if weighted is True:
        for vendor in vendor_results[rnd].keys():
            rankings[vendor] = {}
            if rnd == 'carbanak_fin7':
                prot = 0 if vendor_results[rnd][vendor]['Protection'] == 'N/A' else vendor_results[rnd][vendor]['Protection']
                weighted_score = (.25 * prot) + (.25 * vendor_results[rnd][vendor]['Visibility']) + (.2 * vendor_results[rnd][vendor]['Analytics']) + (.2 * (vendor_results[rnd][vendor]['Confidence']/4)) + (.1 * vendor_results[rnd][vendor]['Quality'])
                rankings[vendor] = weighted_score
            else:
                weighted_score = (.3 * vendor_results[rnd][vendor]['Visibility']) + (.25 * vendor_results[rnd][vendor]['Analytics']) + (.25 * (vendor_results[rnd][vendor]['Confidence']/4)) + (.2 * vendor_results[rnd][vendor]['Quality'])
                rankings[vendor] = weighted_score
    else:
        for vendor in vendor_results[rnd].keys():
            rankings[vendor] = {}
            if rnd == 'carbanak_fin7':
                prot = 0 if vendor_results[rnd][vendor]['Protection'] == 'N/A' else vendor_results[rnd][vendor]['Protection']
                unweighted_score = vendor_results[rnd][vendor]['Visibility'] + ((vendor_results[rnd][vendor]['Analytics'] + (vendor_results[rnd][vendor]['Confidence']/4))/2)
                unweighted_score /= 2
                rankings[vendor] = unweighted_score
            else:
                unweighted_score = (vendor_results[rnd][vendor]['Visibility'] + ((vendor_results[rnd][vendor]['Analytics'] + (vendor_results[rnd][vendor]['Confidence']/4))/2))/2
                rankings[vendor] = unweighted_score
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
    with open('TechniqueHeatmapOverall.csv', 'w') as fp:
        writer = csv.writer(fp)
        writer.writerow(['Tactic', 'Technique', 'Grade', 'Data Collection Capability', 'Detection Capability', 'Response Capability', 'Visibility', 'Analytics', 'Confidence', 'Quality', 'Protection', 'Color', 'Eval'])
        for tactic in tactic_results['carbanak_fin7'].keys():
            li = []
            seen = []
            for technique in tactic_results['carbanak_fin7'][tactic].keys():
                seen.append(technique)
                cell = tactic_results['carbanak_fin7'][tactic][technique]
                eval = 'FIN7'
                visibility = cell['Visibility']
                analytics = cell['Analytics']
                confidence = cell['Confidence']/4
                quality = cell['Quality']
                prot = cell['Protection']
                if technique in tactic_results['apt29'][tactic].keys():
                    cell1 = tactic_results['apt29'][tactic][technique]
                    eval += '/APT29'
                    visibility += cell1['Visibility']
                    analytics += cell1['Analytics']
                    confidence += cell1['Confidence']/4
                    quality += cell1['Quality']
                    visibility /= 2
                    analytics /= 2
                    confidence /= 2
                    quality /= 2
                collection = visibility
                detection = (analytics + confidence)/2
                if prot is not None:
                    response = (quality + prot) / 2
                else:
                    response = quality
                grade = (collection + detection)/2
                li.append([tactic, technique, grade, collection, detection, response, visibility, analytics, confidence, quality, prot, color_grade(grade_score(grade)), eval])
            for technique in tactic_results['apt29'][tactic].keys():
                if technique not in seen:
                    cell = tactic_results['apt29'][tactic][technique]
                    visibility = cell['Visibility']
                    analytics = cell['Analytics']
                    confidence = cell['Confidence']/4
                    quality = cell['Quality']
                    collection = visibility
                    detection = (analytics + confidence)/2
                    response = quality
                    grade = (collection + detection)/2
                    li.append([tactic, technique, grade, collection, detection, response, visibility, analytics, confidence, quality, 'N/A' , color_grade(grade_score(grade)), 'APT29'])
            li = sorted(li, key=lambda x: x[2])
            for item in reversed(li):
                writer.writerow(item)

    for adversary in vendor_results.keys():
        ranking = make_ranking(vendor_results, adversary)
        rankings[adversary] = ranking
        with open(f'results/{adversary} Rankings.csv', 'w') as fp:
            writer = csv.writer(fp)
            if adversary == 'carbanak_fin7':
                writer.writerow(['Vendor', 'Unweighted Score', 'Data Collection Capability', 'Detection Capability', 'Response Capability', 'Visibility', 'Analytics', 'Confidence', 'Quality', 'Protection'])
                rs = []
                vs = []
                us = []
                for vendor in ranking.keys():
                    vs.append(vendor)
                    rs.append(ranking[vendor])
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
                    det_score = visibility
                    corr_score = (analytics + confidence)/2
                    auto_score = (quality + prot)/2
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
                    rs.append(ranking[vendor])
                vs, rs = [list(t) for t in zip(*sorted(zip(vs, rs), key=lambda x: x[1]))]
                scores = zip(reversed(vs), reversed(rs))
                for item in scores:
                    try:
                        writer.writerow([item[0], "%.3f" % item[1], "%.3f" %  vendor_results[adversary][item[0]]['Visibility'], "%.3f" %  vendor_results[adversary][item[0]]['Analytics'],"%.3f" %  (vendor_results[adversary][item[0]]['Confidence']/4), "%.3f" %  vendor_results[adversary][item[0]]['Quality']])
                    except:
                        pass
    graph_rankings('carbanak_fin7')
    graph_rankings('apt29')
    graph_rankings('apt3')

if __name__ == "__main__":
    run_eval()

