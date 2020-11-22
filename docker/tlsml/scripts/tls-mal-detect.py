#!/usr/bin/env python3

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import RobustScaler

scaler = RobustScaler()
dataset = pd.read_csv('data.csv')

X = dataset.drop(['diagnosis', 'Unnamed: 32'], axis=1)
X = scaler.fit_transform(X)
y = (dataset['diagnosis'] == 'M').astype(int)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20)
svclassifier = SVC(kernel='linear')
svclassifier.fit(X_train, y_train)
y_pred = svclassifier.predict(X_test)

print(confusion_matrix(y_test,y_pred))
print(classification_report(y_test,y_pred))