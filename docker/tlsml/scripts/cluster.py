#!/usr/bin/env python3

import pandas as pd
#from sklearn.preprocessing import MinMaxScaler
from matplotlib import pyplot as plt
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import dendrogram, linkage

#scaler = MinMaxScaler()
csv_file = "test_train_data-pre.csv"
dataset = pd.read_csv(csv_file)
#normalized_data = scaler.fit_transform(dataset)

X = dataset.iloc[:, :].values
link = linkage(X.sample( n = 100 ), method='ward')

#dendrogram(link, leaf_rotation=90, leaf_font_size=8)

cluster = AgglomerativeClustering(n_clusters=6)