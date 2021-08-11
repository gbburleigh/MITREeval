import csv, json, sys
import matplotlib.pyplot as plt
import matplotlib.colors as mplcolors
import matplotlib.pyplot as plt, numpy as np
from mpl_toolkits.mplot3d import proj3d
from mpl_toolkits.mplot3d import Axes3D

class Plotter:
    def __init__(self):
        self.prot_included = True

    def visualize3DData(self, X, vendors, colors, x1=None, c1=None):
        """Referenced from https://stackoverflow.com/questions/10374930/matplotlib-annotating-a-3d-scatter-plot/42915422#42915422"""
        fig = plt.figure(figsize = (8,6))
        ax = fig.add_subplot(111, projection = '3d')
        ax.scatter(X[:, 0], X[:, 1], X[:, 2], c=colors)
        ax.set_xlabel('Detection')
        ax.set_ylabel('Context')
        ax.set_zlabel('Automation')

        def onclick(event):
            if self.prot_included is True and x1 is not None and c1 is not None:
                plt.clf()
                ax = fig.add_subplot(111, projection = '3d')
                ax.scatter(x1[:, 0], x1[:, 1], x1[:, 2], c=c1)
                self.prot_included = False
                ax.set_xlabel('Detection')
                ax.set_ylabel('Context')
                ax.set_zlabel('Automation')
            else:
                plt.clf()
                ax = fig.add_subplot(111, projection = '3d')
                ax.scatter(X[:, 0], X[:, 1], X[:, 2], c=colors)
                self.prot_included = True
                ax.set_xlabel('Detection')
                ax.set_ylabel('Context')
                ax.set_zlabel('Automation')


        def distance(point, event):
            assert point.shape == (3,), "distance: point.shape is wrong: %s, must be (3,)" % point.shape
            x2, y2, _ = proj3d.proj_transform(point[0], point[1], point[2], plt.gca().get_proj())
            x3, y3 = ax.transData.transform((x2, y2))
            return np.sqrt ((x3 - event.x)**2 + (y3 - event.y)**2)

        def calcClosestDatapoint(X, event):
            distances = [distance (X[i, 0:3], event) for i in range(X.shape[0])]
            return np.argmin(distances)

        def annotatePlot(X, index):
            if hasattr(annotatePlot, 'label'):
                annotatePlot.label.remove()
            x2, y2, _ = proj3d.proj_transform(X[index, 0], X[index, 1], X[index, 2], ax.get_proj())
            annotatePlot.label = plt.annotate(vendors[index],
                xy = (x2, y2), xytext = (-20, 20), textcoords = 'offset points', ha = 'right', va = 'bottom',
                bbox = dict(boxstyle = 'round,pad=0.5', fc = 'yellow', alpha = 0.5),
                arrowprops = dict(arrowstyle = '->', connectionstyle = 'arc3,rad=0'))
            fig.canvas.draw()

        def onMouseMotion(event):
            closestIndex = calcClosestDatapoint(X, event)
            annotatePlot (X, closestIndex)

        fig.canvas.mpl_connect('motion_notify_event', onMouseMotion)
        fig.canvas.mpl_connect('key_press_event',onclick)
        plt.show()

    def plot_vendors(self, vendor_results):
        detection_scores = []
        correlation_scores = []
        automation_scores = []
        vendors = []
        colors = []
        for vendor in vendor_results['carbanak_fin7'].keys():
            vendors.append(vendor)
            detection_scores.append(vendor_results['carbanak_fin7'][vendor]['Visibility'])
            correlation_scores.append((vendor_results['carbanak_fin7'][vendor]['Analytics'] + (vendor_results['carbanak_fin7'][vendor]['Confidence']/4))/2)
            automation_scores.append((vendor_results['carbanak_fin7'][vendor]['Quality'] + vendor_results['carbanak_fin7'][vendor]['Protection'])/2)
            score = vendor_results['carbanak_fin7'][vendor]['Visibility'] + ((vendor_results['carbanak_fin7'][vendor]['Analytics'] + (vendor_results['carbanak_fin7'][vendor]['Confidence']/4))/2)\
                + ((vendor_results['carbanak_fin7'][vendor]['Quality'] + vendor_results['carbanak_fin7'][vendor]['Protection'])/2)
            score /= 5
            if score <= 1.0 and score > .85:
                colors.append(4)
            elif score <= .85 and score > .7:
                colors.append(3.5)
            elif score <= .7 and score > .55:
                colors.append(2.7)
            elif score <= .55 and score > .4:
                colors.append(2.0)
            elif score < .4:
                colors.append(1)
        X = np.array(list(zip(detection_scores, correlation_scores, automation_scores)))
        self.visualize3DData(X, vendors, colors)

    def plot_techniques(self, tactic_results):
        detection_scores = []
        correlation_scores = []
        automation_scores = []
        quality_scores = []
        techniques = []
        colors = []
        colors2 = []
        for tactic in tactic_results['carbanak_fin7'].keys():
            for technique in tactic_results['carbanak_fin7'][tactic].keys():
                detection_scores.append(tactic_results['carbanak_fin7'][tactic][technique]['Visibility'])
                correlation_scores.append((tactic_results['carbanak_fin7'][tactic][technique]['Analytics'] + (tactic_results['carbanak_fin7'][tactic][technique]['Confidence']/4))/2)
                automation_scores.append((tactic_results['carbanak_fin7'][tactic][technique]['Quality'] + tactic_results['carbanak_fin7'][tactic][technique]['Protection'])/2)
                quality_scores.append(tactic_results['carbanak_fin7'][tactic][technique]['Quality'])
                techniques.append(technique)

                score = tactic_results['carbanak_fin7'][tactic][technique]['Visibility'] + ((tactic_results['carbanak_fin7'][tactic][technique]['Analytics'] + (tactic_results['carbanak_fin7'][tactic][technique]['Confidence']/4))/2) \
                    + ((tactic_results['carbanak_fin7'][tactic][technique]['Quality'] + tactic_results['carbanak_fin7'][tactic][technique]['Protection'])/2)
                score /= 5
                if score <= 1.0 and score > .85:
                    colors.append("#39a83b")
                elif score <= .85 and score > .7:
                    colors.append("#9afc9c")
                elif score <= .7 and score > .55:
                    colors.append("#f5d153")
                elif score <= .55 and score > .4:
                    colors.append("#ff7d88")
                elif score < .4:
                    colors.append("#f52234")

                q_score = tactic_results['carbanak_fin7'][tactic][technique]['Visibility'] + ((tactic_results['carbanak_fin7'][tactic][technique]['Analytics'] + (tactic_results['carbanak_fin7'][tactic][technique]['Confidence']/4))/2) \
                    + tactic_results['carbanak_fin7'][tactic][technique]['Quality']
                q_score /= 4
                if q_score <= 1.0 and q_score > .85:
                    colors2.append("#39a83b")
                elif q_score <= .85 and q_score > .7:
                    colors2.append("#9afc9c")
                elif q_score <= .7 and q_score > .55:
                    colors2.append("#f5d153")
                elif q_score <= .55 and q_score > .4:
                    colors2.append("#ff7d88")
                elif q_score < .4:
                    colors2.append("#f52234")
        X = np.array(list(zip(detection_scores, correlation_scores, automation_scores)))
        self.visualize3DData(X, techniques, colors, x1=np.array(list(zip(detection_scores, correlation_scores, quality_scores))), c1=colors2)

if __name__ == "__main__":
    d = Plotter()
    if '-vendor' in sys.argv:
        with open('results/vendor_results.json', 'r') as fp:
            vendor_results = json.load(fp)
        d.plot_vendors(vendor_results)
    elif '-technique' in sys.argv:
        with open('results/tactic_results.json', 'r') as fp:
            tactic_results = json.load(fp)
        d.plot_techniques(tactic_results)