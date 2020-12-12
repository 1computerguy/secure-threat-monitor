#!/usr/bin/env python3

import pandas as pd
#from sklearn.preprocessing import MinMaxScaler
from matplotlib import pyplot as plt
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import dendrogram, linkage

#scaler = MinMaxScaler()
csv_file = "test_train_data.csv.old3"
dataset = pd.read_csv(csv_file)
#normalized_data = scaler.fit_transform(dataset)

X = dataset.iloc[:, :].values
dendro = linkage(X, method='ward')



#cluster = AgglomerativeClustering(n_clusters=)