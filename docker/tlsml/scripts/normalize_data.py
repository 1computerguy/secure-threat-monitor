#!/usr/bin/env python3

from pandas import read_csv
from pandas import DataFrame
from sklearn.preprocessing import MinMaxScaler
from pandas.plotting import scatter_matrix
from matplotlib import pyplot

csv_file = "test_train_data.csv"
dataset = read_csv(csv_file, header=1)

data = dataset.values[:, :-1]
transform_data = MinMaxScaler()
data = transform_data.fit_transform(data)

dataset = DataFrame(data)

print(dataset.describe())

dataset.hist()
pyplot.show()