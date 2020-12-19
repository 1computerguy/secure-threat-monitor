#!/usr/bin/env python3

import pandas as pd
#from sklearn.preprocessing import MinMaxScaler
from matplotlib import pyplot as plt
import numpy as np
#from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import dendrogram, linkage
import seaborn as sns

#scaler = MinMaxScaler()
csv_file = 'test_train_data-all.csv'
#scaler = MinMaxScaler()
dataset = pd.read_csv(csv_file).sample(n=100)
dataset.insert(loc=0, column='count', value=np.arange(len(dataset)))
# Set count to index, transpose dataset, then rename first column to labels
dataset = dataset.set_index('count').T.rename_axis('labels').reset_index().rename_axis(None, axis=1)
# Set new index to new labels column
dataset = dataset.set_index('labels')
# Remove columns filled with all 0 value (these will be statistically insignifant and will cause
# issues when using correlation methods of analysis)
dataset = dataset[(dataset.T != 0).any()]

dataset_linkage = linkage(dataset_sample, 'ward')
dendrogram(dataset_linkage, orientation='left', labels=dataset_header)
plt.show()

#link = linkage(dataset.sample( n = 100 ), method='ward')

#dendrogram(link, leaf_rotation=90, leaf_font_size=8)
#plt.show()

#cluster = AgglomerativeClustering(n_clusters=6)